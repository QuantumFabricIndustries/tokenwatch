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
    """Verify reports ROOT missing its SACL; everything else succeeds."""
    def __init__(self, missing):
        super().__init__()
        self.missing = missing

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "powershell":
            cmd = argv[-1]
            if "Get-Acl" in cmd:
                return 0, f"MISSING: {self.missing}\n", ""
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
            # also contains Get-Acl, so match on "$paths=@(" specifically
            n_verify = sum(1 for c in r.calls if c[0] == "powershell"
                           and "$paths=@(" in c[-1])
            self.assertEqual(n_verify, 1)
            r.calls.clear()
            w.poll_once()                    # inside cadence: skipped
            self.assertFalse(any("$paths=@(" in c[-1] for c in r.calls
                                 if c[0] == "powershell"))


class ProcWatchRunner(Runner):
    """Clean SACLs + flagged chrome launch."""
    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "powershell":
            cmd = argv[-1]
            if "$ids=@(" in cmd:
                return 0, PARENT_CSV, ""
            if "Win32_Process" in cmd:
                return 0, BROWSER_CSV, ""
        if argv[0] == "wevtutil":
            return 1, "", ""
        return 0, "", ""


class TestDebugLaunchAlert(unittest.TestCase):
    def test_alert_and_dedupe(self):
        with tempfile.TemporaryDirectory() as td:
            w = watch.Watcher(["c:\\x"], runner=ProcWatchRunner(),
                              env={"HOME": td}, platform="windows",
                              state_dir=Path(td), housekeeping_secs=0)
            alerts = w.poll_once()
            dl = [a for a in alerts if a.access == "debug-launch"]
            self.assertEqual(len(dl), 1)
            self.assertIn("--remote-debugging-port", dl[0].path)
            self.assertIn("wscript", dl[0].detail)
            # same pid is not re-alerted on the next poll
            self.assertEqual(w.poll_once(), [])

    def test_alert_rule_mapping(self):
        ev = {"access": "debug-launch", "honey": False}
        self.assertEqual(cli._alert_rule(ev), "debug-launch")
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
        # sacl-reapply = signal only, never forces the verdict
        _, v = score.score([Finding("sacl-reapply", "p")])
        self.assertEqual(v, "HARDENED")


if __name__ == "__main__":
    unittest.main()
