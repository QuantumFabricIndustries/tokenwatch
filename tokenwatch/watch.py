"""Real-time watch on credential stores.

Backends (auto-selected):
  WindowsEventBackend — auditpol File-System success + PowerShell SACL on each
      protected path -> Security event 4663 via wevtutil. Full per-process
      attribution (exe path + pid + access mask).
  LinuxAuditBackend   — auditctl -w path -k tokenwatch + ausearch. Needs root.
  SnapshotBackend     — degraded fallback: size/mtime/hash polling. Detects
      writes/deletes ONLY; reads are invisible at this layer. Loudly reported.

Non-allowlisted access -> alerts.jsonl + returned events. Honeytoken paths are
flagged critical (no legitimate reader exists).
"""
import csv
import hashlib
import io
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from . import platforms
from . import procwatch
from . import secrets

AUDIT_SUBCATEGORY_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"  # File System
PROC_CREATION_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"  # Proc Creation
_CMDLINE_REG = (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
                r"\System\Audit")
_CMDLINE_VAL = "ProcessCreationIncludeCmdLine_Enabled"
LOG_MAX_BYTES = 256 * 1024 * 1024   # 4688 volume would roll ~20MB fast
_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# access types emitted by the watcher itself (not allowlist-filtered)
_SELF_EVENTS = ("sacl-reapply", "debug-launch", "debug-launch-info")

# AccessMask bits (4663)
AM_READ = 0x1
AM_WRITE = 0x2
AM_APPEND = 0x4
AM_DELETE = 0x10000
AM_WRITE_DAC = 0x40000      # ACL change on a cred store — takeover signal
AM_WRITE_OWNER = 0x80000

# Every specified field must match (AND). Fields:
#   name             basename of the accessing process
#   process_dir      substring of the process's DIRECTORY (blocks
#                    C:\Temp\claude.exe — name match alone is spoofable)
#   process_contains substring of the full process path
#   path_contains    substring of the accessed OBJECT path
#   signer           Authenticode subject substring, status must be Valid
#                    (Windows only; unverifiable signer => rule fails closed)
DEFAULT_ALLOW = [
    # OS noise, path+signer anchored
    {"name": "msmpeng.exe", "process_dir": "windows defender",
     "signer": "Microsoft"},
    {"name": "searchindexer.exe", "process_dir": "\\windows\\",
     "signer": "Microsoft"},
    {"name": "searchprotocolhost.exe", "process_dir": "\\windows\\",
     "signer": "Microsoft"},
    {"name": "searchfilterhost.exe", "process_dir": "\\windows\\",
     "signer": "Microsoft"},
    # agent binaries — real install dirs only
    {"name": "claude.exe", "process_dir": "claude"},
    {"name": "claude", "process_dir": "claude"},
    {"name": "cursor.exe", "process_dir": "cursor"},
    {"name": "windsurf.exe", "process_dir": "windsurf"},
    {"name": "zed.exe", "process_dir": "zed"},
    {"name": "codex.exe", "process_dir": "codex"},
    {"name": "devin.exe", "process_dir": "devin"},
    {"name": "gemini.exe", "process_dir": "gemini"},
    {"name": "code.exe", "process_dir": "code",
     "path_contains": "globalstorage"},
    # node runtimes — pinned to real install dirs AND object scope
    {"name": "node.exe", "process_dir": "\\nodejs\\",
     "path_contains": ".claude"},
    {"name": "node.exe", "process_dir": "\\nvm\\",
     "path_contains": ".claude"},
    {"name": "node.exe", "process_dir": "\\nodejs\\",
     "path_contains": ".codeium"},
    {"name": "node.exe", "process_dir": "\\nvm\\",
     "path_contains": ".codeium"},

    # browsers — real install dir + valid signature, object scoped to the
    # browser's own profile paths (a legit chrome.exe reading .aws alerts)
    {"name": "chrome.exe", "process_dir": "\\google\\chrome\\",
     "signer": "Google", "path_contains": "google/chrome"},
    {"name": "chrome", "process_dir": "\\google\\chrome\\",
     "path_contains": "google-chrome"},          # linux /opt/google/chrome
    {"name": "msedge.exe", "process_dir": "\\microsoft\\edge\\",
     "signer": "Microsoft", "path_contains": "microsoft/edge"},
    {"name": "brave.exe", "process_dir": "\\brave",
     "signer": "Brave", "path_contains": "brave"},
    {"name": "brave", "process_dir": "\\brave",
     "path_contains": "brave"},                   # linux
    {"name": "chromium", "process_dir": "chromium",
     "path_contains": "chromium"},
    {"name": "firefox.exe", "process_dir": "\\mozilla firefox\\",
     "signer": "Mozilla", "path_contains": "firefox"},
    {"name": "firefox", "process_dir": "\\firefox\\",
     "path_contains": "firefox"},                 # linux /usr/lib/firefox
    {"name": "thunderbird.exe", "process_dir": "thunderbird",
     "signer": "Mozilla", "path_contains": "thunderbird"},
    {"name": "thunderbird", "process_dir": "thunderbird",
     "path_contains": "thunderbird"},
    {"name": "opera.exe", "process_dir": "\\opera",
     "path_contains": "opera"},
    {"name": "launcher.exe", "process_dir": "\\opera",
     "path_contains": "opera"},
    {"name": "opera", "process_dir": "\\opera",
     "path_contains": "opera"},                   # linux

    # messaging / wallets / tools — dir + object anchored
    {"name": "discord.exe", "process_dir": "\\discord",
     "path_contains": "discord"},
    {"name": "discord", "process_dir": "\\discord",
     "path_contains": "discord"},
    {"name": "telegram.exe", "process_dir": "\\telegram",
     "path_contains": "telegram"},
    {"name": "telegram", "process_dir": "\\telegram",
     "path_contains": "telegram"},
    {"name": "signal.exe", "process_dir": "\\signal",
     "path_contains": "signal"},
    {"name": "slack.exe", "process_dir": "\\slack",
     "path_contains": "slack"},
    {"name": "filezilla.exe", "process_dir": "filezilla",
     "path_contains": "filezilla"},
    {"name": "winscp.exe", "process_dir": "winscp",
     "path_contains": "winscp"},
    {"name": "postman.exe", "process_dir": "\\postman",
     "path_contains": "postman"},
    {"name": "insomnia.exe", "process_dir": "\\insomnia",
     "path_contains": "insomnia"},
    {"name": "bitwarden.exe", "process_dir": "\\bitwarden",
     "path_contains": "bitwarden"},
    {"name": "1password.exe", "process_dir": "\\1password",
     "path_contains": "1password"},
    {"name": "exodus.exe", "process_dir": "\\exodus",
     "path_contains": "exodus"},
    {"name": "electrum.exe", "process_dir": "\\electrum",
     "path_contains": "electrum"},
    {"name": "electrum", "process_dir": "\\electrum",
     "path_contains": "electrum"},
    {"name": "steam.exe", "process_dir": "\\steam\\",
     "path_contains": "steam"},
    {"name": "steamwebhelper.exe", "process_dir": "\\steam\\",
     "path_contains": "steam"},
    # JetBrains ships many exe names (idea64, pycharm64, ...) — scope by
    # process + object dirs instead of enumerating binaries
    {"process_contains": "jetbrains", "path_contains": "jetbrains"},

    # DPAPI master keys + Credential Manager: legitimate reads flow through
    # lsass/vaultsvc — a user process touching Protect/Credentials/Vault
    # files directly is the tell
    {"name": "lsass.exe", "process_dir": "\\windows\\system32\\",
     "signer": "Microsoft", "path_contains": "microsoft/"},
    {"name": "svchost.exe", "process_dir": "\\windows\\system32\\",
     "signer": "Microsoft", "path_contains": "microsoft/"},
]


@dataclass
class AccessEvent:
    ts: float
    path: str
    process: str        # exe path or "?" (degraded backend)
    pid: int
    access: str         # "read" | "write" | "delete" | "perm-change" |
                        # "sacl-reapply" | "debug-launch" | ...
    user: str = ""
    honey: bool = False
    detail: str = ""    # flag + parent info for debug-launch, etc.

    def to_jsonl(self):
        return json.dumps(self.__dict__, separators=(",", ":"))


class Allowlist:
    def __init__(self, state_dir, extra=None, runner=None, platform=None):
        self.rules = list(DEFAULT_ALLOW)
        cfg = state_dir / "allowlist.json"
        if cfg.exists():
            try:
                self.rules += json.loads(cfg.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        if extra:
            self.rules += extra
        self.self_pid = os.getpid()
        self.runner = runner
        self.platform = platform or platforms.PLATFORM
        self._signer_cache = {}

    def allows(self, ev):
        if ev.pid and ev.pid == self.self_pid:
            return True
        proc_norm = ev.process.replace("/", "\\").lower()
        base = proc_norm.rsplit("\\", 1)[-1]
        proc_dir = (proc_norm.rsplit("\\", 1)[0] + "\\"
                    if "\\" in proc_norm else "")
        obj = ev.path.replace("\\", "/").lower()
        for r in self.rules:
            if not self._match(r, base, proc_dir, proc_norm, obj, ev.process):
                continue
            return True
        return False

    def _match(self, r, base, proc_dir, proc_norm, obj, proc_raw):
        name = r.get("name", "").lower()
        if name and base != name:
            return False
        pdir = r.get("process_dir")
        if pdir and pdir.lower() not in proc_dir:
            return False
        psub = r.get("process_contains")
        if psub and psub.lower() not in proc_norm:
            return False
        sub = r.get("path_contains")
        if sub and sub.lower() not in obj:
            return False
        signer = r.get("signer")
        if signer:
            subject = self._signer(proc_raw)
            if not subject or signer.lower() not in subject.lower():
                return False
        return True

    def _signer(self, exe_path):
        """Authenticode subject CN, or None. Cached; fails closed."""
        if exe_path in self._signer_cache:
            return self._signer_cache[exe_path]
        subject = None
        if self.platform == "windows" and exe_path and "?" not in exe_path:
            esc = exe_path.replace("'", "''")
            ps = ("$s=Get-AuthenticodeSignature -FilePath '%s';"
                  "if ($s.Status -eq 'Valid' -and $s.SignerCertificate)"
                  " { $s.SignerCertificate.Subject }" % esc)
            rc, out, _ = platforms.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-Command", ps], timeout=30, runner=self.runner)
            if rc == 0 and out.strip():
                subject = out.strip().splitlines()[0].strip()
        self._signer_cache[exe_path] = subject
        return subject


# ------------------------------------------------------------- backends
class WindowsEventBackend:
    name = "windows-4663+4688"

    def __init__(self, roots, env=None, runner=None):
        self.roots = [str(r).lower() for r in roots]
        self.runner = runner
        self.env = env
        self.last_record = 0
        self.last_poll = time.time()
        self.installed = False
        self._marker_dirs = None

    def install(self):
        """Enable File System + Process Creation auditing, drop a
        read/write SACL per root, and put an inheritable ObjectInherit/
        NoPropagateInherit marker on each file root's PARENT dir so
        atomically-replaced stores (temp+rename) are born audited."""
        actions = []
        rc, out, err = platforms.run(
            ["auditpol", "/set", f"/subcategory:{AUDIT_SUBCATEGORY_GUID}",
             "/success:enable"], runner=self.runner)
        actions.append(f"auditpol file-system rc={rc} {err.strip()}")
        actions += self._enable_process_creation()
        for root in self.roots:
            actions.append(self._sacl(root, add=True))
        self._marker_dirs = self._compute_markers()
        for d in self._marker_dirs:
            actions.append(self._marker_sacl(d, add=True))
        for d in (r for r in self.roots if os.path.isdir(r)):
            actions.append(self._propagate_sacl(d, add=True))
        self.installed = True
        return actions

    def uninstall(self):
        actions = [self._sacl(r, add=False) for r in self.roots]
        markers = (self._marker_dirs
                   if self._marker_dirs is not None
                   else self._compute_markers())
        for d in markers:
            actions.append(self._marker_sacl(d, add=False))
        for d in (r for r in self.roots if os.path.isdir(r)):
            actions.append(self._propagate_sacl(d, add=False))
        actions += self._restore_process_creation()
        self.installed = False
        return actions

    def _compute_markers(self):
        """Parent dirs of FILE roots needing the born-audited marker.
        Dir roots already propagate to children via OICI; a parent that is
        itself a root is likewise covered. The home dir is excluded —
        stray honeytokens there aren't atomically rewritten by apps, and a
        marker on ~ would audit every file the user creates."""
        home = str(platforms.home(self.env)).lower().rstrip("\\/")
        dir_roots = {r for r in self.roots if os.path.isdir(r)}
        markers = set()
        for r in self.roots:
            if r in dir_roots:
                continue
            parent = str(Path(r).parent).lower()
            if parent != home and parent not in dir_roots:
                markers.add(parent)
        return sorted(markers)

    # ---- 4688 process-creation auditing (with prior-state restore) ----
    def _audit_state_path(self):
        return platforms.state_dir(self.env) / "audit_policy_state.json"

    def _enable_process_creation(self):
        acts = []
        state = {}
        # record prior Process Creation inclusion so uninstall restores it
        rc, out, _ = platforms.run(
            ["auditpol", "/get", f"/subcategory:{PROC_CREATION_GUID}", "/r"],
            runner=self.runner)
        had = None
        if rc == 0 and out:
            for row in csv.reader(io.StringIO(out)):
                if PROC_CREATION_GUID.strip("{}").lower() in \
                        ",".join(row).lower():
                    inc = row[4].strip().lower() if len(row) > 4 else ""
                    had = ("success" in inc)
        state["proc_creation_had_success"] = had
        rc, out, _ = platforms.run(
            ["reg", "query", _CMDLINE_REG, "/v", _CMDLINE_VAL],
            runner=self.runner)
        m = re.search(r"0x([0-9a-fA-F]+)", out or "")
        state["cmdline_was"] = int(m.group(1), 16) if (rc == 0 and m) \
            else None
        # 4688 volume on a dev box (builds/npm/cargo spawn thousands of
        # processes) rolls the default ~20MB Security log in hours —
        # record the current max and raise it; restore on uninstall.
        rc, out, _ = platforms.run(["wevtutil", "gl", "Security"],
                                   runner=self.runner)
        m = re.search(r"maxSize:\s*(\d+)", out or "")
        state["log_max_was"] = int(m.group(1)) if (rc == 0 and m) else None
        try:
            self._audit_state_path().parent.mkdir(parents=True,
                                                  exist_ok=True)
            self._audit_state_path().write_text(json.dumps(state),
                                                encoding="utf-8")
        except OSError:
            pass
        rc, _, err = platforms.run(
            ["auditpol", "/set", f"/subcategory:{PROC_CREATION_GUID}",
             "/success:enable"], runner=self.runner)
        acts.append(f"auditpol process-creation rc={rc} {err.strip()}")
        rc, _, err = platforms.run(
            ["reg", "add", _CMDLINE_REG, "/v", _CMDLINE_VAL, "/t",
             "REG_DWORD", "/d", "1", "/f"], runner=self.runner)
        acts.append(f"reg cmdline-in-4688 rc={rc} {err.strip()}")
        acts.append(
            "NOTE: 4688 logs RAW command lines to the Security log "
            "(admin-only to read; secrets can appear there — alerts "
            "redact them, the log itself does not)")
        if not state.get("log_max_was") or \
                state["log_max_was"] < LOG_MAX_BYTES:
            rc, _, err = platforms.run(
                ["wevtutil", "sl", "Security", f"/ms:{LOG_MAX_BYTES}"],
                runner=self.runner)
            acts.append(f"security-log size -> {LOG_MAX_BYTES}B rc={rc} "
                        f"{err.strip()}")
        return acts

    def _restore_process_creation(self):
        p = self._audit_state_path()
        try:
            state = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        acts = []
        if state.get("proc_creation_had_success") is False:
            rc, _, err = platforms.run(
                ["auditpol", "/set", f"/subcategory:{PROC_CREATION_GUID}",
                 "/success:disable"], runner=self.runner)
            acts.append(f"auditpol process-creation restore rc={rc} "
                        f"{err.strip()}")
        if state.get("cmdline_was") is None:
            rc, _, err = platforms.run(
                ["reg", "delete", _CMDLINE_REG, "/v", _CMDLINE_VAL, "/f"],
                runner=self.runner)
            acts.append(f"reg cmdline restore (absent) rc={rc} "
                        f"{err.strip()}")
        else:
            rc, _, err = platforms.run(
                ["reg", "add", _CMDLINE_REG, "/v", _CMDLINE_VAL, "/t",
                 "REG_DWORD", "/d", str(state["cmdline_was"]), "/f"],
                runner=self.runner)
            acts.append(f"reg cmdline restore rc={rc} {err.strip()}")
        if state.get("log_max_was"):
            rc, _, err = platforms.run(
                ["wevtutil", "sl", "Security",
                 f"/ms:{state['log_max_was']}"], runner=self.runner)
            acts.append(f"security-log size restore "
                        f"({state['log_max_was']}B) rc={rc} "
                        f"{err.strip()}")
        try:
            p.unlink()
        except OSError:
            pass
        return acts

    def _sacl(self, path, add):
        """Set/remove a Success audit rule for Everyone on `path`."""
        esc = path.replace("'", "''")
        verb = "AddAuditRule" if add else "RemoveAuditRuleAll"
        ps = (
            "$p='%s';"
            "$d=(Get-Item -LiteralPath $p -Force).PSIsContainer;"
            "$fl=if($d){'ContainerInherit,ObjectInherit'}else{'None'};"
            "$rule=New-Object System.Security.AccessControl."
            "FileSystemAuditRule('Everyone','Read,Write,Delete,"
            "ChangePermissions,TakeOwnership',$fl,'None','Success');"
            "$acl=Get-Acl -LiteralPath $p -Audit;"
            "$acl.%s($rule);"
            "Set-Acl -LiteralPath $p -AclObject $acl" % (esc, verb))
        rc, out, err = platforms.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=60, runner=self.runner)
        return f"sacl {'add' if add else 'del'} {path}: rc={rc} {err.strip()}"

    def _marker_sacl(self, path, add):
        """ObjectInherit+NoPropagateInherit rule on a parent dir — files
        created directly inside (a freshly-renamed Local State, Login
        Data, ...) are born with the audit SACL; subfolders unaffected."""
        esc = path.replace("'", "''")
        verb = "AddAuditRule" if add else "RemoveAuditRuleAll"
        ps = (
            "$p='%s';"
            "$rule=New-Object System.Security.AccessControl."
            "FileSystemAuditRule('Everyone','Read,Write,Delete,"
            "ChangePermissions,TakeOwnership','ObjectInherit',"
            "'NoPropagateInherit','Success');"
            "$acl=Get-Acl -LiteralPath $p -Audit;"
            "$acl.%s($rule);"
            "Set-Acl -LiteralPath $p -AclObject $acl" % (esc, verb))
        rc, out, err = platforms.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=60, runner=self.runner)
        return f"marker-sacl {'add' if add else 'del'} {path}: " \
               f"rc={rc} {err.strip()}"

    _PROPAGATE_CAP = 500     # children stamped per dir root

    def _propagate_sacl(self, dirpath, add):
        """Stamp/remove the audit rule on EXISTING children of a dir root.

        Inheritance only reaches children created AFTER the parent's rule
        is set — Set-Acl does not propagate to pre-existing children, so
        the DPAPI master keys / leveldb files already sitting in a dir
        root would stay unaudited without this."""
        esc = dirpath.replace("'", "''")
        verb = "AddAuditRule" if add else "RemoveAuditRuleAll"
        ps = (
            "$root='%s';"
            "$kids=@(Get-ChildItem -LiteralPath $root -Recurse -Force "
            "-ErrorAction SilentlyContinue);"
            "$kids | Select-Object -First %d |"
            "ForEach-Object{$p=$_.FullName;"
            "$flags=if($_.PSIsContainer){'ContainerInherit,ObjectInherit'}"
            "else{'None'};"
            "$rule=New-Object System.Security.AccessControl."
            "FileSystemAuditRule('Everyone','Read,Write,Delete,"
            "ChangePermissions,TakeOwnership',$flags,'None','Success');"
            "$acl=Get-Acl -LiteralPath $p -Audit;$acl.%s($rule);"
            "Set-Acl -LiteralPath $p -AclObject $acl};"
            "if($kids.Count -gt %d){'TRUNCATED '+$kids.Count}"
            % (esc, self._PROPAGATE_CAP, verb, self._PROPAGATE_CAP))
        rc, out, err = platforms.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=120, runner=self.runner)
        action = f"propagate-{'add' if add else 'del'} {dirpath}: " \
                 f"rc={rc} {err.strip()}"
        m = re.search(r"TRUNCATED (\d+)", out or "")
        if m:
            action += (f" — WARNING: capped, stamped "
                       f"{self._PROPAGATE_CAP} of {m.group(1)} children; "
                       f"the rest are unaudited until replaced")
        return action

    # FileSystemRights bit values we set — the Everyone+Success+
    # ChangePermissions+TakeOwnership combo is distinctive enough to serve
    # as the "our rule" marker. MISSINGM = parent-dir born-audit rule.
    _VERIFY_PS = (
        "$f=@(%s);$m=@(%s);"
        "foreach($p in $f){try{$hit=$false;"
        "foreach($r in (Get-Acl -LiteralPath $p -Audit).Audit){"
        "if($r.IdentityReference -match 'Everyone' -and $r.AuditFlags "
        "-match 'Success' -and ($r.FileSystemRights -band 262144) -and "
        "($r.FileSystemRights -band 524288)){$hit=$true}};"
        "if(-not $hit){'MISSING: '+$p}}catch{'MISSING: '+$p}};"
        "foreach($p in $m){try{$hit=$false;"
        "foreach($r in (Get-Acl -LiteralPath $p -Audit).Audit){"
        "if($r.IdentityReference -match 'Everyone' -and $r.AuditFlags "
        "-match 'Success' -and ($r.FileSystemRights -band 262144) -and "
        "($r.FileSystemRights -band 524288) -and $r.PropagationFlags "
        "-match 'NoPropagateInherit'){$hit=$true}};"
        "if(-not $hit){'MISSINGM: '+$p}}catch{'MISSINGM: '+$p}}")

    def verify(self):
        """(path, kind) list whose audit rules are gone — file SACLs lost
        to atomic replace, or parent-dir marker rules removed. Only when
        installed: a bare `watch --once` must not mutate ACLs."""
        if not self.installed or not self.roots:
            return []
        markers = (self._marker_dirs
                   if self._marker_dirs is not None
                   else self._compute_markers())
        fmt = lambda xs: "@(" + ", ".join(
            "'" + x.replace("'", "''") + "'" for x in xs) + ")"
        rc, out, _ = platforms.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             self._VERIFY_PS % (fmt(self.roots), fmt(markers))],
            timeout=120, runner=self.runner)
        if rc != 0:
            return []
        res = []
        for ln in out.splitlines():
            if ln.startswith("MISSINGM: "):
                res.append((ln[10:], "marker"))
            elif ln.startswith("MISSING: "):
                res.append((ln[9:], "file"))
        return res

    def reapply(self, path, kind="file"):
        return (self._marker_sacl(path, add=True) if kind == "marker"
                else self._sacl(path, add=True))

    def poll(self):
        """Fetch new 4663 events touching protected roots.

        First poll seeds the watermark from a bounded lookback; after that
        we query strictly by `EventRecordID > N` — Security-log events that
        flush late still carry higher record IDs, so a time window can
        never drop them."""
        if self.last_record:
            q = (f"*[System[(EventID=4663 or EventID=4688) and "
                 f"(EventRecordID > {self.last_record})]]")
        else:
            window_ms = int(max(60_000,
                                (time.time() - self.last_poll + 5) * 1500))
            q = ("*[System[(EventID=4663 or EventID=4688) and "
                 f"TimeCreated[timediff(@SystemTime) <= {window_ms}]]]")
        self.last_poll = time.time()
        rc, out, _ = platforms.run(
            ["wevtutil", "qe", "Security", f"/q:{q}", "/f:xml",
             "/e:Events", "/c:500", "/rd:true"], runner=self.runner)
        if rc != 0 or "<Event" not in out:
            return []
        return self._parse(out)

    def _parse(self, xml_text):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            # wevtutil sometimes emits bare <Event>..</Event> stream
            try:
                root = ET.fromstring("<Events>" + xml_text + "</Events>")
            except ET.ParseError:
                return []
        events = []
        newest = self.last_record
        for ev in root.iter(f"{_EVENT_NS}Event"):
            sys_el = ev.find(f"{_EVENT_NS}System")
            data = {d.get("Name"): (d.text or "")
                    for d in ev.iter(f"{_EVENT_NS}Data")}
            rid, eid = 0, 0
            if sys_el is not None:
                rec = sys_el.find(f"{_EVENT_NS}EventRecordID")
                rid = int(rec.text) if rec is not None and rec.text else 0
                eid_el = sys_el.find(f"{_EVENT_NS}EventID")
                if eid_el is not None and eid_el.text:
                    eid = int(eid_el.text)
            if rid and rid <= self.last_record:
                continue
            newest = max(newest, rid)   # batch update — wevtutil /rd:true
                                        # returns NEWEST first; updating the
                                        # watermark mid-loop would skip the
                                        # rest of this same batch
            if eid == 4688:
                hit = self._event_4688(data)
                if hit:
                    events.append(hit)
                continue
            obj = data.get("ObjectName", "")
            if not obj or not self._in_roots(obj):
                continue
            try:
                mask = int(data.get("AccessMask", "0x0"), 16)
                pid = int(data.get("ProcessId", "0x0"), 16)
            except ValueError:
                mask, pid = 0, 0
            events.append(AccessEvent(
                ts=time.time(), path=obj,
                process=data.get("ProcessName", "?"), pid=pid,
                access=self._access(mask),
                user=data.get("SubjectUserName", "")))
        self.last_record = newest
        return events

    @staticmethod
    def _event_4688(data):
        """Process creation -> flagged browser launch, or None.

        4688 persists after the process exits (unlike a process snapshot)
        and carries the CREATOR's name — a parent that's already dead gets
        a real name instead of '?'."""
        newproc = data.get("NewProcessName", "")
        name = newproc.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if name not in procwatch.BROWSER_NAMES:
            return None
        cmd = data.get("CommandLine", "")
        flag = procwatch.bad_flag(cmd)
        if not flag:
            return None
        parent = (data.get("ParentProcessName")
                  or data.get("CreatorProcessName") or "?")
        pname = parent.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if pname in procwatch.OK_PARENTS:
            return None
        sev = ("debug-launch" if procwatch.real_profile(cmd)
               else "debug-launch-info")
        try:
            pid = int(data.get("NewProcessId", "0x0"), 16)
        except ValueError:
            pid = 0
        return AccessEvent(
            # command lines can carry secrets (curl -H "Authorization:
            # Bearer …", mysql -p…) — the Security log holds them raw,
            # alerts.jsonl must not
            ts=time.time(), path=secrets.redact(cmd)[:200],
            process=newproc, pid=pid,
            access=sev, user=data.get("SubjectUserName", ""),
            detail=f"flag={flag} parent={pname}")

    def _in_roots(self, obj):
        o = obj.lower()
        return any(o.startswith(r) for r in self.roots)

    @staticmethod
    def _access(mask):
        if mask & (AM_WRITE_DAC | AM_WRITE_OWNER):
            return "perm-change"
        if mask & AM_DELETE:
            return "delete"
        if mask & (AM_WRITE | AM_APPEND):
            return "write"
        if mask & AM_READ:
            return "read"
        return f"mask:{mask:#x}"


class LinuxAuditBackend:
    name = "linux-auditd"

    def __init__(self, roots, env=None, runner=None):
        self.roots = [str(r) for r in roots]
        self.runner = runner
        self.installed = False

    def install(self):
        out = []
        for r in self.roots:
            rc, _, err = platforms.run(
                ["auditctl", "-w", r, "-k", "tokenwatch", "-p", "rwa"],
                runner=self.runner)
            out.append(f"auditctl {r}: rc={rc} {err.strip()}")
        self.installed = True
        return out

    def uninstall(self):
        out = []
        for r in self.roots:
            rc, _, _ = platforms.run(
                ["auditctl", "-W", r, "-k", "tokenwatch", "-p", "rwa"],
                runner=self.runner)
            out.append(f"auditctl -W {r}: rc={rc}")
        self.installed = False
        return out

    def poll(self):
        rc, out, _ = platforms.run(
            ["ausearch", "-k", "tokenwatch", "-ts", "recent", "-i"],
            runner=self.runner)
        if rc != 0 or not out.strip():
            return []
        return self._parse(out)

    def verify(self):
        """auditctl -w watches bind to the inode — an atomically replaced
        file silently drops the watch, same as the Windows SACL case."""
        if not self.installed:
            return []
        rc, out, _ = platforms.run(["auditctl", "-l"], runner=self.runner)
        if rc != 0:
            return []
        return [(r, "file") for r in self.roots if r not in out]

    def reapply(self, path, kind="file"):
        rc, _, err = platforms.run(
            ["auditctl", "-w", path, "-k", "tokenwatch", "-p", "rwa"],
            runner=self.runner)
        return f"auditctl -w {path}: rc={rc} {err.strip()}"

    @staticmethod
    def _parse(text):
        events = []
        import re
        for rec in text.split("----"):
            names = re.findall(r'\bname="([^"]+)"', rec)
            name = names[-1] if names else None  # last PATH item = target
            exe = re.search(r'\bexe="([^"]+)"', rec)
            pid = re.search(r'\bpid=(\d+)', rec)
            syscall = re.search(r'\bsyscall=(\w+)', rec)
            if not name:
                continue
            sc = syscall.group(1) if syscall else ""
            is_write = sc in ("creat", "rename", "renameat", "unlink",
                              "unlinkat", "chmod", "fchmod", "setxattr",
                              "truncate") or (
                sc in ("open", "openat") and
                ("O_WRONLY" in rec or "O_RDWR" in rec))
            access = "write" if is_write else "read"
            events.append(AccessEvent(
                ts=time.time(), path=name,
                process=exe.group(1) if exe else "?",
                pid=int(pid.group(1)) if pid else 0,
                access=access))
        return events


class SnapshotBackend:
    """Degraded: detects writes/deletes only — reads are invisible."""

    name = "snapshot-degraded"

    def __init__(self, roots, env=None, runner=None):
        self.roots = [Path(r) for r in roots]
        self.snap = {}

    def install(self):
        self._take()
        return ["snapshot baseline taken — NOTE: reads are NOT detectable "
                "in degraded mode"]

    def uninstall(self):
        self.snap = {}
        return ["snapshot state cleared"]

    def verify(self):
        return []   # no kernel watches to drift — snapshot re-takes anyway

    def reapply(self, path, kind="file"):
        return ""

    def _take(self):
        for root in self.roots:
            files = [root] if root.is_file() else list(
                root.rglob("*")) if root.is_dir() else []
            for f in files:
                if not f.is_file():
                    continue
                try:
                    st = f.stat()
                    h = hashlib.sha256(f.read_bytes()).hexdigest()
                    self.snap[str(f)] = (st.st_size, st.st_mtime_ns, h)
                except OSError:
                    continue

    def poll(self):
        events = []
        seen = set()
        for root in self.roots:
            files = [root] if root.is_file() else list(
                root.rglob("*")) if root.is_dir() else []
            for f in files:
                if not f.is_file():
                    continue
                key = str(f)
                seen.add(key)
                try:
                    st = f.stat()
                    h = hashlib.sha256(f.read_bytes()).hexdigest()
                except OSError:
                    continue
                if key in self.snap and self.snap[key] != (
                        st.st_size, st.st_mtime_ns, h):
                    events.append(AccessEvent(time.time(), key, "?", 0,
                                              "write"))
                self.snap[key] = (st.st_size, st.st_mtime_ns, h)
        for key in set(self.snap) - seen:
            events.append(AccessEvent(time.time(), key, "?", 0, "delete"))
            del self.snap[key]
        return events


def pick_backend(platform, roots, env=None, runner=None):
    if platform == "windows":
        return WindowsEventBackend(roots, env=env, runner=runner)
    if platform == "linux" and platforms.which("auditctl", runner=runner):
        return LinuxAuditBackend(roots, env=env, runner=runner)
    return SnapshotBackend(roots, env=env, runner=runner)


class Watcher:
    """Install backends, poll, allowlist-filter, append alerts.jsonl.

    housekeeping_secs gates the non-poll checks: SACL/watch drift repair
    (atomic file replacement silently drops the audit rule) and browser
    debug-port launch inspection (ABE-era cookie theft rides through the
    real signed browser binary, invisible to file watch)."""

    def __init__(self, paths, honey_paths=(), env=None, runner=None,
                 platform=None, state_dir=None, housekeeping_secs=60):
        self.platform = platform or platforms.PLATFORM
        self.env = env if env is not None else os.environ
        self.state = state_dir or platforms.state_dir(self.env)
        self.state.mkdir(parents=True, exist_ok=True)
        self.honey = {str(p).lower() for p in honey_paths}
        self.runner = runner
        self.backend = pick_backend(self.platform, paths, env=self.env,
                                    runner=runner)
        self.allowlist = Allowlist(self.state, runner=runner,
                                   platform=self.platform)
        self.alert_log = self.state / "alerts.jsonl"
        self.hk_secs = housekeeping_secs
        self._last_hk = 0.0
        self._seen_pids = set()

    def install(self):
        return self.backend.install()

    def uninstall(self):
        return self.backend.uninstall()

    def _housekeeping(self, alerts):
        """Self-generated signals appended straight to alerts (no
        allowlist pass — these events are ours by construction)."""
        if time.time() - self._last_hk < self.hk_secs:
            return
        self._last_hk = time.time()

        # 1. drift: reapply silently-dropped audit rules; the reapply
        #    event itself is the second tamper signal (alongside
        #    WRITE_DAC) — a SACL that keeps disappearing is an attacker
        #    or a program atomically rewriting the store
        verify = getattr(self.backend, "verify", None)
        if verify:
            for item in verify():
                p, kind = item if isinstance(item, tuple) else (item, "file")
                act = self.backend.reapply(p, kind)
                alerts.append(AccessEvent(
                    time.time(), str(p), "tokenwatch", os.getpid(),
                    "sacl-reapply", detail=str(act)))

        # 2. browser debug-port launches — on Windows these come from 4688
        #    events in the poll stream (survive process exit, real parent
        #    name); the snapshot scan only runs on degraded backends
        if not isinstance(self.backend, WindowsEventBackend):
            for s in procwatch.scan(runner=self.runner,
                                    platform=self.platform):
                if s["pid"] in self._seen_pids:
                    continue
                if len(self._seen_pids) > 4096:
                    self._seen_pids.clear()
                self._seen_pids.add(s["pid"])
                sev = ("debug-launch" if procwatch.real_profile(
                    s["cmdline"]) else "debug-launch-info")
                alerts.append(AccessEvent(
                    time.time(), secrets.redact(s["cmdline"])[:200],
                    s.get("exe") or s["name"], s["pid"], sev,
                    detail=f"flag={s['flag']} "
                           f"parent={s.get('parent', '?')}({s['ppid']})"))

    def poll_once(self):
        """One poll cycle -> list of NON-allowlisted events (alerts)."""
        alerts = []
        for ev in self.backend.poll():
            if ev.access in _SELF_EVENTS:
                alerts.append(ev)   # detection events, not file access
                continue
            if str(ev.path).lower() in self.honey:
                ev.honey = True
            if self.allowlist.allows(ev):
                continue
            alerts.append(ev)
        self._housekeeping(alerts)
        if alerts:
            with self.alert_log.open("a", encoding="utf-8") as fh:
                for ev in alerts:
                    fh.write(ev.to_jsonl() + "\n")
        return alerts

    def serve(self, interval=30, on_alert=None):
        self.install()
        try:
            while True:
                for ev in self.poll_once():
                    (on_alert or self._print)(ev)
                time.sleep(interval)
        except KeyboardInterrupt:
            return

    @staticmethod
    def _print(ev):
        tag = "HONEYTOKEN" if ev.honey else "ALERT"
        print(f"[{tag}] {ev.access} {ev.path} <- {ev.process} (pid {ev.pid})")
