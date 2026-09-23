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
import hashlib
import json
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from . import platforms

AUDIT_SUBCATEGORY_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"  # File System
_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

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
]


@dataclass
class AccessEvent:
    ts: float
    path: str
    process: str        # exe path or "?" (degraded backend)
    pid: int
    access: str         # "read" | "write" | "delete" | "perm-change" | ...
    user: str = ""
    honey: bool = False

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
    name = "windows-4663"

    def __init__(self, roots, env=None, runner=None):
        self.roots = [str(r).lower() for r in roots]
        self.runner = runner
        self.env = env
        self.last_record = 0
        self.last_poll = time.time()
        self.installed = False

    def install(self):
        """Enable File System auditing + drop a read/write SACL per root."""
        actions = []
        rc, out, err = platforms.run(
            ["auditpol", "/set", f"/subcategory:{AUDIT_SUBCATEGORY_GUID}",
             "/success:enable"], runner=self.runner)
        actions.append(f"auditpol rc={rc} {err.strip()}")
        for root in self.roots:
            actions.append(self._sacl(root, add=True))
        self.installed = True
        return actions

    def uninstall(self):
        actions = [self._sacl(r, add=False) for r in self.roots]
        self.installed = False
        return actions

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

    def poll(self):
        """Fetch new 4663 events touching protected roots.

        First poll seeds the watermark from a bounded lookback; after that
        we query strictly by `EventRecordID > N` — Security-log events that
        flush late still carry higher record IDs, so a time window can
        never drop them."""
        if self.last_record:
            q = (f"*[System[(EventID=4663) and "
                 f"(EventRecordID > {self.last_record})]]")
        else:
            window_ms = int(max(60_000,
                                (time.time() - self.last_poll + 5) * 1500))
            q = ("*[System[(EventID=4663) and "
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
            rid = 0
            if sys_el is not None:
                rec = sys_el.find(f"{_EVENT_NS}EventRecordID")
                rid = int(rec.text) if rec is not None and rec.text else 0
            if rid and rid <= self.last_record:
                continue
            newest = max(newest, rid)   # batch update — wevtutil /rd:true
                                        # returns NEWEST first; updating the
                                        # watermark mid-loop would skip the
                                        # rest of this same batch
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

    def install(self):
        out = []
        for r in self.roots:
            rc, _, err = platforms.run(
                ["auditctl", "-w", r, "-k", "tokenwatch", "-p", "rwa"],
                runner=self.runner)
            out.append(f"auditctl {r}: rc={rc} {err.strip()}")
        return out

    def uninstall(self):
        out = []
        for r in self.roots:
            rc, _, _ = platforms.run(
                ["auditctl", "-W", r, "-k", "tokenwatch", "-p", "rwa"],
                runner=self.runner)
            out.append(f"auditctl -W {r}: rc={rc}")
        return out

    def poll(self):
        rc, out, _ = platforms.run(
            ["ausearch", "-k", "tokenwatch", "-ts", "recent", "-i"],
            runner=self.runner)
        if rc != 0 or not out.strip():
            return []
        return self._parse(out)

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
    """Install backends, poll, allowlist-filter, append alerts.jsonl."""

    def __init__(self, paths, honey_paths=(), env=None, runner=None,
                 platform=None, state_dir=None):
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

    def install(self):
        return self.backend.install()

    def uninstall(self):
        return self.backend.uninstall()

    def poll_once(self):
        """One poll cycle -> list of NON-allowlisted events (alerts)."""
        alerts = []
        for ev in self.backend.poll():
            if str(ev.path).lower() in self.honey:
                ev.honey = True
            if self.allowlist.allows(ev):
                continue
            alerts.append(ev)
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
