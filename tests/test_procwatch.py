import tempfile
import unittest
from pathlib import Path

from tokenwatch import procwatch, watch, cli, score
from tokenwatch.platforms import Runner


class TestFlagLogic(unittest.TestCase):
    def test_bad_flags(self):
        for cl in ("chrome.exe --remote-debugging-port=9222",
                   "msedge --remote-debugging-pipe",
                   "chrome --headless=new about:blank"):
            self.assertIsNotNone(procwatch.bad_flag(cl))
        for cl in ("chrome.exe about:blank",
                   "msedge.exe --profile-directory=Default",
                   ""):
            self.assertIsNone(procwatch.bad_flag(cl))

    def test_parent_gate(self):
        cl = "chrome.exe --remote-debugging-port=9222"
        # shells / dev tools -> allowed
        for p in ("cmd.exe", "powershell.exe", "explorer.exe",
                  "code.exe", "cursor.exe", "node.exe", "python.exe"):
            self.assertIsNone(procwatch.suspicious(cl, p), p)
        # script hosts / services / unknown -> flagged
        for p in ("wscript.exe", "cscript.exe", "mshta.exe",
                  "rundll32.exe", "svchost.exe", "evil.exe", "?", ""):
            self.assertIsNotNone(procwatch.suspicious(cl, p), p)


class TestProfileClassify(unittest.TestCase):
    """The real-vs-fresh profile discriminator: automation tools launch
    with a throwaway --user-data-dir; a stealer needs the victim's real
    profile because that's where the cookies live."""
    CL = "chrome.exe --remote-debugging-port=9222"

    def test_no_udd_is_real_profile(self):
        self.assertTrue(procwatch.real_profile(self.CL))

    def test_udd_at_real_profile_is_real(self):
        cl = (self.CL + ' --user-data-dir="C:\\Users\\reven\\AppData\\'
              'Local\\Google\\Chrome\\User Data"')
        self.assertTrue(procwatch.real_profile(cl))

    def test_udd_to_temp_is_fresh(self):
        for cl in (self.CL + ' --user-data-dir=C:\\Temp\\pw-xyz',
                   self.CL + ' --user-data-dir="/tmp/pw-profile"',
                   self.CL + ' --user-data-dir="C:\\scratch\\prof"'):
            self.assertFalse(procwatch.real_profile(cl), cl)

    def test_classify(self):
        # debug flag + real profile + bad parent -> "real" (COMPROMISED)
        self.assertEqual(procwatch.classify(self.CL, "wscript.exe"),
                         "real")
        # debug flag + temp profile + bad parent -> "fresh" (info only)
        self.assertEqual(procwatch.classify(
            self.CL + " --user-data-dir=C:\\Temp\\x", "wscript.exe"),
            "fresh")
        # shell parent -> nothing, regardless of profile
        self.assertIsNone(procwatch.classify(self.CL, "cmd.exe"))
        # no flag -> nothing
        self.assertIsNone(procwatch.classify("chrome.exe about:blank",
                                             "wscript.exe"))


BROWSER_CSV = (
    '"ProcessId","ParentProcessId","Name","ExecutablePath","CommandLine"\r\n'
    '"4242","3131","chrome.exe",'
    '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",'
    '"chrome.exe --remote-debugging-port=9222 --headless"\r\n'
    '"5555","1","msedge.exe","C:\\Program Files\\Microsoft\\Edge\\'
    'Application\\msedge.exe","msedge.exe about:blank"\r\n')

PARENT_CSV = (
    '"ProcessId","Name"\r\n'
    '"3131","wscript.exe"\r\n'
    '"1","System"\r\n')


class ProcRunner(Runner):
    """powershell: browser CSV on the proc query, parent CSV on the
    id-filtered follow-up."""
    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "powershell":
            cmd = argv[-1]
            if "$ids=@(" in cmd:
                return 0, PARENT_CSV, ""
            if "Win32_Process" in cmd:
                return 0, BROWSER_CSV, ""
        return 0, "", ""


class TestWindowsScan(unittest.TestCase):
    def test_flags_wscript_spawned_chrome(self):
        hits = procwatch.scan(runner=ProcRunner(), platform="windows")
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["name"], "chrome.exe")
        self.assertEqual(h["parent"], "wscript.exe")
        self.assertEqual(h["flag"], "--remote-debugging-port")
        # clean msedge (no flag) not reported at all
        self.assertFalse(any(h["name"] == "msedge.exe" for h in hits))


PS_OUT = """  4242    99 chrome /opt/google/chrome/chrome --remote-debugging-port=9222
    99     1 wscript /usr/bin/wscript
  5555   100 firefox /usr/lib/firefox/firefox
   100     1 bash /bin/bash
"""


class PsRunner(Runner):
    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "ps":
            return 0, PS_OUT, ""
        return 0, "", ""


class TestPosixScan(unittest.TestCase):
    def test_ps_parsing_and_parent_gate(self):
        hits = procwatch.scan(runner=PsRunner(), platform="linux")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["parent"], "wscript")
        self.assertEqual(hits[0]["flag"], "--remote-debugging-port")


# ------------------------------------------------------------ watch wiring
class DriftRunner(Runner):
    """Verify reports a path missing its audit rule; everything else ok.
    marker_mode -> emits MISSINGM: (parent-dir marker) instead."""
    def __init__(self, missing):
        super().__init__()
        self.missing = missing
        self.marker_mode = False

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "powershell":
            cmd = argv[-1]
            if "Get-Acl" in cmd:
                pfx = "MISSINGM: " if self.marker_mode else "MISSING: "
                return 0, f"{pfx}{self.missing}\n", ""
            if "Win32_Process" in cmd:
                return 0, "", ""
            return 0, "", ""
        if argv[0] == "wevtutil":
            return 1, "", ""
        return 0, "", ""


class TestDriftRepair(unittest.TestCase):
    ROOT = "c:\\users\\reven\\.aws"

    def test_missing_sacl_reapplied_and_logged(self):
        with tempfile.TemporaryDirectory() as td:
            r = DriftRunner(self.ROOT)
            w = watch.Watcher([self.ROOT], runner=r, env={"HOME": td},
                              platform="windows", state_dir=Path(td),
                              housekeeping_secs=0)
            w.install()
            r.calls.clear()
            alerts = w.poll_once()
            reapplied = [a for a in alerts if a.access == "sacl-reapply"]
            self.assertEqual(len(reapplied), 1)
            self.assertEqual(reapplied[0].path, self.ROOT)
            # reapply ran an AddAuditRule powershell
            self.assertTrue(any("AddAuditRule" in c[-1] for c in r.calls
                                if c[0] == "powershell"))
            log = (Path(td) / "alerts.jsonl").read_text()
            self.assertIn("sacl-reapply", log)

    def test_no_verify_when_not_installed(self):
        """watch --once must not mutate ACLs as a side effect."""
        with tempfile.TemporaryDirectory() as td:
            r = DriftRunner(self.ROOT)
            w = watch.Watcher([self.ROOT], runner=r, env={"HOME": td},
                              platform="windows", state_dir=Path(td),
                              housekeeping_secs=0)
            alerts = w.poll_once()          # no install() call
            self.assertEqual(alerts, [])
            self.assertFalse(any("AddAuditRule" in c[-1] for c in r.calls
                                 if c[0] == "powershell"))

    def test_missing_marker_reapplied_with_marker_rule(self):
        """MISSINGM: -> reapply writes the ObjectInherit/NoPropagateInherit
        marker rule, not the plain file SACL."""
        with tempfile.TemporaryDirectory() as td:
            marker_dir = "c:\\users\\reven\\appdata\\local\\microsoft\\" \
                         "edge\\user data"
            r = DriftRunner(marker_dir)
            r.marker_mode = True
            w = watch.Watcher([self.ROOT], runner=r, env={"HOME": td},
                              platform="windows", state_dir=Path(td),
                              housekeeping_secs=0)
            w.install()
            r.calls.clear()
            alerts = w.poll_once()
            reapplied = [a for a in alerts if a.access == "sacl-reapply"]
            self.assertEqual(len(reapplied), 1)
            self.assertEqual(reapplied[0].path, marker_dir)
            ps = [c[-1] for c in r.calls if c[0] == "powershell"
                  and "AddAuditRule" in c[-1]]
            self.assertTrue(any("NoPropagateInherit" in s for s in ps))

    def test_housekeeping_cadence(self):
        with tempfile.TemporaryDirectory() as td:
            r = DriftRunner(self.ROOT)
            w = watch.Watcher([self.ROOT], runner=r, env={"HOME": td},
                              platform="windows", state_dir=Path(td),
                              housekeeping_secs=9999)
            w.install()
            r.calls.clear()
            w.poll_once()                    # first poll: housekeeping runs
            # the verify script's own signature — install/reapply powershell
            # also contains Get-Acl, so match on "$f=@(" specifically
            n_verify = sum(1 for c in r.calls if c[0] == "powershell"
                           and "$f=@(" in c[-1])
            self.assertEqual(n_verify, 1)
            r.calls.clear()
            w.poll_once()                    # inside cadence: skipped
            self.assertFalse(any("$f=@(" in c[-1] for c in r.calls
                                 if c[0] == "powershell"))


FIXTURE_4688 = Path(__file__).parent / "fixtures" / "wevtutil_4688.xml"


class ProcWatchRunner(Runner):
    """Clean SACLs + the 4688 fixture on wevtutil (the event-driven path —
    a process snapshot can't see a browser that already exited)."""
    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "wevtutil":
            return 0, FIXTURE_4688.read_text(encoding="utf-8"), ""
        return 0, "", ""


class TestDebugLaunchAlert(unittest.TestCase):
    def test_4688_real_profile_alert_and_watermark_dedupe(self):
        with tempfile.TemporaryDirectory() as td:
            w = watch.Watcher(["c:\\x"], runner=ProcWatchRunner(),
                              env={"HOME": td}, platform="windows",
                              state_dir=Path(td), housekeeping_secs=9999)
            alerts = w.poll_once()
            dl = [a for a in alerts if a.access == "debug-launch"]
            self.assertEqual(len(dl), 1)
            self.assertIn("--remote-debugging-port", dl[0].path)
            self.assertIn("wscript.exe", dl[0].detail)  # dead parent, real
                                                      # name from 4688
            info = [a for a in alerts
                    if a.access == "debug-launch-info"]
            self.assertEqual(len(info), 1)      # temp --user-data-dir
            # watermark advances past the batch — no re-alert
            self.assertEqual(w.poll_once(), [])

    def test_posix_fallback_uses_snapshot_scan(self):
        """No 4688 off Windows — the procwatch ps-scan still runs there."""
        with tempfile.TemporaryDirectory() as td:
            w = watch.Watcher(["/nonexistent"], runner=PsRunner(),
                              env={"HOME": td}, platform="linux",
                              state_dir=Path(td), housekeeping_secs=0)
            alerts = w.poll_once()
            dl = [a for a in alerts if a.access == "debug-launch"]
            self.assertEqual(len(dl), 1)
            self.assertIn("wscript", dl[0].detail)

    def test_alert_rule_mapping(self):
        ev = {"access": "debug-launch", "honey": False}
        self.assertEqual(cli._alert_rule(ev), "debug-launch")
        self.assertEqual(cli._alert_rule({"access": "debug-launch-info"}),
                         "debug-launch-info")
        self.assertEqual(cli._alert_rule({"access": "sacl-reapply"}),
                         "sacl-reapply")
        self.assertEqual(cli._alert_rule({"access": "perm-change"}),
                         "perm-change")
        self.assertEqual(cli._alert_rule({"access": "read"}),
                         "unauthorized-read")
        self.assertEqual(cli._alert_rule({"access": "read",
                                          "honey": True}),
                         "honeytoken-read")

    def test_scoring_semantics(self):
        from tokenwatch.score import Finding
        # debug-launch = observed theft-attempt class -> COMPROMISED
        _, v = score.score([Finding("debug-launch", "p")])
        self.assertEqual(v, "COMPROMISED")
        # fresh-profile variant = automation-shaped -> info only
        _, v = score.score([Finding("debug-launch-info", "p")])
        self.assertEqual(v, "HARDENED")
        # sacl-reapply = signal only, never forces the verdict
        _, v = score.score([Finding("sacl-reapply", "p")])
        self.assertEqual(v, "HARDENED")


if __name__ == "__main__":
    unittest.main()
