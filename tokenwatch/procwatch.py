"""Browser-process launch inspection — the ABE-era cookie-theft path.

Since Chrome's App-Bound Encryption, stealers relaunch the browser with
--remote-debugging-port / --headless and pull decrypted cookies over
DevTools. The file reader is then the real, signed browser binary — file
watch + allowlists can't see it. This module scans process command lines
on the watch loop's housekeeping cadence and flags browsers started with
those flags when the parent isn't the user's shell or a known dev tool.

Windows: Get-CimInstance Win32_Process (per-poll CIM query; reads of
same-user processes need no elevation). POSIX: `ps -axo pid,ppid,comm,args`.
Everything goes through the injectable runner so tests can fake it.
"""
import csv
import io
import re
from . import platforms

# browser process basenames we care about (launcher.exe = Opera's real bin)
BROWSER_NAMES = {
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "chromium.exe",
    "firefox.exe", "vivaldi.exe", "thorium.exe", "arc.exe", "launcher.exe",
    # posix names
    "chrome", "chromium", "firefox", "brave", "opera", "msedge",
    "vivaldi", "google-chrome",
}

BAD_FLAGS = (
    "--remote-debugging-port",
    "--remote-debugging-pipe",
    "--remote-debugging-address",
    "--headless",
)

# Legit parents: the user's own shells, desktops, IDEs, and dev tooling
# that spawn browsers for debugging (playwright/puppeteer live under
# node/python). Services and script hosts are deliberately NOT here —
# wscript/rundll32/svchost spawning a flagged browser IS the tell.
OK_PARENTS = {
    # user shells / session launchers
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "windowsterminal.exe", "wt.exe", "sihost.exe", "startmenuexperiencehost.exe",
    "sh", "bash", "zsh", "fish", "login", "launchd", "systemd", "init",
    "open", "finder",
    # dev tools that legitimately drive browsers
    "code.exe", "cursor.exe", "windsurf.exe", "zed.exe", "node.exe",
    "python.exe", "python", "py.exe", "idea64.exe", "pycharm64.exe",
    "webstorm64.exe", "devenv.exe", "rider64.exe", "goland64.exe",
    "code", "node",
    # browsers spawning their own helper procs
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "firefox.exe",
    "thunderbird.exe", "chromium.exe", "chrome", "chromium", "firefox",
    "brave", "opera",
}


def bad_flag(cmdline):
    """Return the suspicious flag found in a command line, or None."""
    cl = (cmdline or "").lower()
    for f in BAD_FLAGS:
        if f in cl:
            return f
    return None


# what "the victim's real profile" looks like in a path — cover both the
# Windows dir-tree forms (Google\Chrome\User Data, Mozilla\Firefox) and
# the dot-config forms (~/.config/google-chrome, ~/.mozilla)
_REAL_PROFILE_MARKERS = (
    "user data", "google\\chrome", "google-chrome", "microsoft\\edge",
    "microsoft-edge", "brave", "chromium", "opera", "vivaldi", "thorium",
    "arc", "mozilla", "firefox", "thunderbird",
)


def _udd(cmdline):
    """Extract --user-data-dir= / -profile target, or None.

    The value may be quoted AND contain spaces (a real profile dir like
    User Data) — a naive non-space match truncates the real profile path
    and misjudges it as a fresh profile."""
    cl = cmdline or ""
    m = re.search(r'--user-data-dir\s*=\s*(?:"([^"]*)"|(\S+))',
                  cl, re.IGNORECASE)
    if not m:
        m = re.search(r'(?:^|\s)-profile\s+(?:"([^"]*)"|(\S+))',
                      cl, re.IGNORECASE)
    if not m:
        return None
    return m.group(1) or m.group(2)


def real_profile(cmdline):
    """Does the launch target the victim's actual profile?

    No --user-data-dir => the browser opens its default (real) profile.
    A user-data-dir pointing at a real browser profile tree => real.
    A user-data-dir into temp/scratch => fresh automation profile — the
    Playwright/Puppeteer/Selenium shape, which can't hold victim cookies.
    """
    target = _udd(cmdline)
    if target is None:
        return True
    p = target.replace("/", "\\").lower()
    return any(k in p for k in _REAL_PROFILE_MARKERS)


def suspicious(cmdline, parent_name):
    """Flag a browser launch? cmdline has a debug/headless flag AND the
    parent isn't a shell/dev tool."""
    flag = bad_flag(cmdline)
    if not flag:
        return None
    if (parent_name or "").lower() in OK_PARENTS:
        return None
    return flag


def classify(cmdline, parent_name):
    """-> "real" | "fresh" | None.

    real  = debug flag + real profile + non-shell parent  -> COMPROMISED
    fresh = debug flag + throwaway profile                -> info only
    None  = nothing suspicious
    """
    if not suspicious(cmdline, parent_name):
        return None
    return "real" if real_profile(cmdline) else "fresh"


# ------------------------------------------------------------------ windows
_PS_BROWSER_QUERY = (
    "$names=@('chrome.exe','msedge.exe','brave.exe','opera.exe',"
    "'chromium.exe','firefox.exe','vivaldi.exe','thorium.exe','arc.exe',"
    "'launcher.exe');"
    "Get-CimInstance Win32_Process | Where-Object {"
    "$names -contains $_.Name.ToLower()} | Select-Object "
    "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
    "ConvertTo-Csv -NoTypeInformation")

_PS_PARENT_QUERY = (
    "$ids=@(%s);"
    "Get-CimInstance Win32_Process | Where-Object {$ids -contains "
    "$_.ProcessId} | Select-Object ProcessId,Name | "
    "ConvertTo-Csv -NoTypeInformation")


def _ps(argv_ps, runner):
    rc, out, _ = platforms.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", argv_ps],
        timeout=60, runner=runner)
    return out if rc == 0 else ""


def _scan_windows(runner):
    out = _ps(_PS_BROWSER_QUERY, runner)
    rows = list(csv.DictReader(io.StringIO(out))) if out.strip() else []
    flagged = []
    for r in rows:
        cmd = r.get("CommandLine") or ""
        flag = bad_flag(cmd)
        if not flag:
            continue
        flagged.append({
            "pid": int(r.get("ProcessId") or 0),
            "ppid": int(r.get("ParentProcessId") or 0),
            "name": (r.get("Name") or "?").lower(),
            "exe": r.get("ExecutablePath") or r.get("Name") or "?",
            "cmdline": cmd,
            "flag": flag,
        })
    if not flagged:
        return []
    # one follow-up query resolves all parents at once
    ids = ",".join(str(f["ppid"]) for f in flagged if f["ppid"])
    parents = {}
    if ids:
        pout = _ps(_PS_PARENT_QUERY % ids, runner)
        for pr in (csv.DictReader(io.StringIO(pout)) if pout.strip() else []):
            parents[int(pr.get("ProcessId") or 0)] = (
                pr.get("Name") or "?").lower()
    out_events = []
    for f in flagged:
        f["parent"] = parents.get(f["ppid"], "?")
        if f["parent"] in OK_PARENTS:
            continue
        out_events.append(f)
    return out_events


# -------------------------------------------------------------------- posix
def _scan_posix(runner):
    rc, out, _ = platforms.run(
        ["ps", "-axo", "pid=,ppid=,comm=,args="], runner=runner)
    if rc != 0 or not out.strip():
        return []
    procs = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        procs[pid] = {"pid": pid, "ppid": ppid,
                      "name": parts[2].rsplit("/", 1)[-1].lower(),
                      "exe": parts[2], "cmdline": parts[3]}
    flagged = []
    for p in procs.values():
        if p["name"] not in BROWSER_NAMES:
            continue
        flag = bad_flag(p["cmdline"])
        if not flag:
            continue
        parent = procs.get(p["ppid"], {})
        p["parent"] = parent.get("name", "?")
        p["flag"] = flag
        if p["parent"] in OK_PARENTS:
            continue
        flagged.append(p)
    return flagged


def scan(runner=None, platform=None):
    """-> list of dicts {pid, ppid, name, exe, cmdline, flag, parent}."""
    platform = platform or platforms.PLATFORM
    if platform == "windows":
        return _scan_windows(runner)
    return _scan_posix(runner)
