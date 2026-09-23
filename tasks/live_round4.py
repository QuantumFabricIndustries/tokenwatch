"""Scoped live proof — round 4.

Scope (per request): Edge Login Data + Local State, Microsoft\\Protect.
NO Cookies (write volume floods the Security log).

Proves:
  1. SACL drift repair — force an atomic replace on the real Local State
     (temp-write + os.replace = exactly what Chromium does), confirm the
     housekeeping pass detects the missing SACL and reapplies it.
  2. Foreign reads of Login Data / Local State / Protect alert with
     process attribution (powershell + python readers).
  3. debug-launch: msedge spawned with --remote-debugging-port --headless
     under a NON-allowlisted parent (wscript) -> alert. Uses a throwaway
     --user-data-dir so the real profile is untouched.
  4. teardown: SACLs removed.

Runs unelevated for the procwatch demo; the SACL portion self-elevates
via Start-Process -Verb RunAs (one UAC prompt) and logs to
%TEMP%\\tw_round4.log.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tokenwatch import watch, platforms, procwatch

LOCAL = os.environ["LOCALAPPDATA"]
ROAM = os.environ["APPDATA"]
TEMP = os.environ["TEMP"]
LOG = Path(TEMP) / "tw_round4.log"

TARGETS = [
    Path(LOCAL) / "Microsoft/Edge/User Data/Default/Login Data",
    Path(LOCAL) / "Microsoft/Edge/User Data/Local State",
    Path(ROAM) / "Microsoft/Protect",
]

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not Path(EDGE).exists():
    EDGE = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"


def out(msg):
    print(msg, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")


def elevated_proof():
    state = Path(TEMP) / "tw_state"
    state.mkdir(exist_ok=True)
    w = watch.Watcher([str(t) for t in TARGETS if t.exists()],
                      env=dict(os.environ), platform="windows",
                      state_dir=state, housekeeping_secs=2)
    out(f"backend: {w.backend.name} roots={len(w.backend.roots)}")
    for act in w.install():
        out(f"  install: {act}")

    # drain setup noise (our own SACL-install WRITE_DACs flush late)
    time.sleep(3)
    w.poll_once()
    (state / "alerts.jsonl").unlink(missing_ok=True)
    out("--- baseline drained ---")

    # ---- 1. drift: atomic-replace the real Local State (bytes preserved)
    ls = TARGETS[1]
    tmp = ls.with_name("Local State.twtmp")
    shutil.copyfile(ls, tmp)
    os.replace(tmp, ls)          # same mechanism as Chromium's safe write
    out("forced atomic replace on Local State (content identical)")
    time.sleep(4)
    alerts = w.poll_once()
    reapplied = [a for a in alerts if a.access == "sacl-reapply"]
    out(f"drift check: {len(reapplied)} sacl-reapply event(s)")
    for a in reapplied:
        out(f"  reapply: {a.path} | {a.detail}")

    # ---- 2. foreign reads
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"Get-Content -LiteralPath '{TARGETS[0]}' "
                    "-TotalCount 1 -ErrorAction SilentlyContinue"],
                   capture_output=True)
    # python reader on Local State
    try:
        TARGETS[1].read_bytes()[:16]
    except OSError as e:
        out(f"  python read failed: {e}")
    # read a file inside Protect (dir SACL -> child inherits)
    prot = TARGETS[2]
    inner = next(prot.rglob("*"), None)
    if inner and inner.is_file():
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Get-Content -LiteralPath '{inner}' -TotalCount 1"
                        " -ErrorAction SilentlyContinue"],
                       capture_output=True)
    time.sleep(4)
    alerts = w.poll_once()
    reads = [a for a in alerts if a.access in ("read", "write")]
    out(f"foreign reads: {len(reads)} alert(s)")
    for a in reads:
        out(f"  {a.access} {a.path} <- {a.process} pid={a.pid}")

    # ---- 3. debug-launch: wscript (non-allowlisted) spawns headless edge
    pd = Path(TEMP) / "tw_edge_pd"
    pd.mkdir(exist_ok=True)
    vbs = Path(TEMP) / "tw_spawn.vbs"
    vbs.write_text(
        'CreateObject("WScript.Shell").Run """' + EDGE + '"" '
        '--remote-debugging-port=9222 --headless=new '
        f'--user-data-dir={pd} about:blank", 0, False\n',
        encoding="utf-8")
    subprocess.run(["wscript", str(vbs)], capture_output=True)
    time.sleep(6)               # let edge come up + housekeeping cadence
    alerts = w.poll_once() + w.poll_once()
    dl = [a for a in alerts if a.access == "debug-launch"]
    out(f"debug-launch: {len(dl)} alert(s)")
    for a in dl:
        out(f"  {a.detail} | {a.path[:120]}")
    subprocess.run(["taskkill", "/F", "/PID",
                    str(dl[0].pid)] if dl else ["cmd", "/c", "rem"],
                   capture_output=True)

    # ---- 4. teardown
    for act in w.uninstall():
        out(f"  uninstall: {act}")
    vbs.unlink(missing_ok=True)
    out("DONE")


def procwatch_demo():
    """Unelevated half: prove procwatch flags the wscript-spawned edge."""
    pd = Path(TEMP) / "tw_edge_pd"
    pd.mkdir(exist_ok=True)
    vbs = Path(TEMP) / "tw_spawn.vbs"
    vbs.write_text(
        'CreateObject("WScript.Shell").Run """' + EDGE + '"" '
        '--remote-debugging-port=9222 --headless=new '
        f'--user-data-dir={pd} about:blank", 0, False\n',
        encoding="utf-8")
    subprocess.run(["wscript", str(vbs)], capture_output=True)
    time.sleep(6)
    hits = procwatch.scan(platform="windows")
    print(f"procwatch hits: {len(hits)}")
    for h in hits:
        print(f"  {h['name']} pid={h['pid']} flag={h['flag']} "
              f"parent={h['parent']}")
    for h in hits:
        subprocess.run(["taskkill", "/F", "/PID", str(h["pid"])],
                       capture_output=True)
    vbs.unlink(missing_ok=True)


def main():
    if "--elevated" in sys.argv:
        elevated_proof()
        return
    if "--procwatch" in sys.argv:
        procwatch_demo()
        return
    # default: relaunch self elevated, then print the log
    LOG.unlink(missing_ok=True)
    subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"Start-Process -FilePath '{sys.executable}' -ArgumentList "
         f"'\"{__file__}\" --elevated' -Verb RunAs -Wait"],
        check=False)
    if LOG.exists():
        print(LOG.read_text(encoding="utf-8"))
    else:
        print("no log — UAC denied or elevated run failed")


if __name__ == "__main__":
    main()
