"""Scoped live proof — round 5 (4688 + born-audited + severity split).

Scope: Edge Login Data + Local State, Microsoft\\Protect.
NO Cookies (write volume floods the Security log).

Proves:
  1. Born-audited stores — parent-dir marker SACL (ObjectInherit +
     NoPropagateInherit) means an atomic temp+os.replace on Local State
     produces a NEW file that already carries the audit rule. Verified by
     verify() returning clean AND a foreign read on the replaced file
     alerting immediately (the old 60s drift window is gone).
  2. Foreign reads alert with process attribution: powershell on
     Login Data, a CHILD python.exe process on Local State (the
     last-round in-process read was correctly self-pid-exempted), and
     powershell on a real Protect\\<SID>\\<key> FILE (last round probed
     the SID dir).
  3. 4688 process-creation detection: msedge spawned with
     --remote-debugging-port by a wscript parent that EXITS before the
     poll — the event still fires (it persists post-exit) and names the
     dead creator. Real profile -> debug-launch; temp --user-data-dir ->
     debug-launch-info.
  4. teardown: file SACLs + marker SACLs removed, audit policy restored.
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

    # ---- 1. born-audited: atomic-replace the real Local State (exactly
    #         Chromium's safe-write). The User Data marker SACL means the
    #         new file carries the audit rule at creation — no window.
    ls = TARGETS[1]
    tmp = ls.with_name("Local State.twtmp")
    shutil.copyfile(ls, tmp)
    os.replace(tmp, ls)
    out("forced atomic replace on Local State (content identical)")
    missing = w.backend.verify()
    out(f"verify after replace: {missing or 'clean — marker inherited'}")
    # structural proof: a foreign read on the REPLACED file alerts
    # immediately — before any housekeeping pass could run
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"Get-Content -LiteralPath '{ls}' -TotalCount 1 "
                    "-ErrorAction SilentlyContinue"], capture_output=True)
    time.sleep(4)
    alerts = w.poll_once()
    born = [a for a in alerts if a.access in ("read", "write")
            and "local state" in a.path.lower()]
    out(f"born-audited read on NEW Local State: {len(born)} alert(s)")
    for a in born:
        out(f"  {a.access} {a.path} <- {a.process} pid={a.pid}")
    if not born:
        out("  !! marker did NOT cover the replace — window still open")

    # ---- 2. foreign reads
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    f"Get-Content -LiteralPath '{TARGETS[0]}' "
                    "-TotalCount 1 -ErrorAction SilentlyContinue"],
                   capture_output=True)
    # python reader as a CHILD process — in-process reads are correctly
    # self-pid exempted (that was last round's script bug)
    subprocess.run([sys.executable, "-c",
                    f"open(r'{ls}', 'rb').read(16)"],
                   capture_output=True)
    # real Protect\<SID>\<key> FILE (rglob returns the SID dir first)
    prot = TARGETS[2]
    inner = next((p for p in prot.rglob("*") if p.is_file()), None)
    if inner:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Get-Content -LiteralPath '{inner}' -TotalCount 1"
                        " -ErrorAction SilentlyContinue"],
                       capture_output=True)
    else:
        out("  no file under Protect to probe")
    time.sleep(4)
    alerts = w.poll_once()
    reads = [a for a in alerts if a.access in ("read", "write")]
    out(f"foreign reads: {len(reads)} alert(s)")
    for a in reads:
        out(f"  {a.access} {a.path} <- {a.process} pid={a.pid}")

    # ---- 3. 4688 debug-launch — wscript parent exits instantly; the
    #         event persists in the log AND names the dead creator.
    #         real profile -> debug-launch ; temp udd -> info
    pd = Path(TEMP) / "tw_edge_pd"
    pd.mkdir(exist_ok=True)
    vbs = Path(TEMP) / "tw_spawn.vbs"
    vbs.write_text(
        'CreateObject("WScript.Shell").Run """' + EDGE + '"" '
        '--remote-debugging-port=9223 --headless=new about:blank", '
        '0, False\n',
        encoding="utf-8")                       # NO user-data-dir = real
    vbs2 = Path(TEMP) / "tw_spawn2.vbs"
    vbs2.write_text(
        'CreateObject("WScript.Shell").Run """' + EDGE + '"" '
        '--remote-debugging-port=9224 --headless=new '
        f'--user-data-dir={pd} about:blank", 0, False\n',
        encoding="utf-8")                       # temp udd = automation
    subprocess.run(["wscript", str(vbs)], capture_output=True)
    subprocess.run(["wscript", str(vbs2)], capture_output=True)
    time.sleep(6)
    alerts = w.poll_once() + w.poll_once()
    dl = [a for a in alerts if a.access == "debug-launch"]
    info = [a for a in alerts if a.access == "debug-launch-info"]
    out(f"debug-launch (real profile): {len(dl)} alert(s)")
    for a in dl:
        out(f"  {a.detail} | {a.path[:120]}")
    out(f"debug-launch-info (temp profile): {len(info)} alert(s)")
    for a in info:
        out(f"  {a.detail} | {a.path[:120]}")
    for a in dl + info:                        # clean up spawned edges
        if a.pid:
            subprocess.run(["taskkill", "/F", "/PID", str(a.pid)],
                           capture_output=True)

    # ---- 4. teardown
    for act in w.uninstall():
        out(f"  uninstall: {act}")
    vbs.unlink(missing_ok=True)
    vbs2.unlink(missing_ok=True)
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
