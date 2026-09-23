import tempfile
import unittest
from pathlib import Path

from tokenwatch import watch
from tokenwatch.platforms import Runner

FIXTURE = Path(__file__).parent / "fixtures" / "wevtutil_4663.xml"
ROOT = "c:\\users\\reven\\.aws"


class FakeRunner(Runner):
    """Returns canned wevtutil XML; powershell -> canned signer subject."""
    def __init__(self, xml=""):
        super().__init__()
        self.xml = xml

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "wevtutil":
            return (0, self.xml, "") if self.xml else (1, "", "")
        if argv[0] == "auditpol":
            return 0, "", ""
        if argv[0] == "powershell":
            cmd = argv[-1]
            if "Get-AuthenticodeSignature" in cmd:
                if "Windows Defender" in cmd or "\\Windows\\" in cmd:
                    return 0, "CN=Microsoft Windows, O=Microsoft\n", ""
                return 0, "", ""          # unsigned/invalid -> empty subject
            return 0, "", ""
        return 0, "", ""


class TestWindowsBackend(unittest.TestCase):
    def test_parse_filters_to_protected_roots(self):
        be = watch.WindowsEventBackend([ROOT], runner=FakeRunner())
        events = be._parse(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(len(events), 3)  # notepad/other dir excluded
        self.assertTrue(all(e.path.lower().startswith(ROOT) for e in events))

    def test_access_classification(self):
        be = watch.WindowsEventBackend([ROOT], runner=FakeRunner())
        events = be._parse(FIXTURE.read_text(encoding="utf-8"))
        by_pid = {e.pid: e for e in events}
        self.assertEqual(by_pid[0x1F90].access, "read")
        self.assertEqual(by_pid[0x444].access, "perm-change")

    def test_record_watermark_dedupes(self):
        be = watch.WindowsEventBackend([ROOT], runner=FakeRunner())
        first = be._parse(FIXTURE.read_text(encoding="utf-8"))
        second = be._parse(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(len(first), 3)
        self.assertEqual(len(second), 0)

    def test_poll_uses_wevtutil(self):
        r = FakeRunner(FIXTURE.read_text(encoding="utf-8"))
        be = watch.WindowsEventBackend([ROOT], runner=r)
        events = be.poll()
        self.assertEqual(len(events), 3)
        self.assertTrue(any(c[0] == "wevtutil" for c in r.calls))

    def test_install_runs_auditpol_and_sacl(self):
        r = FakeRunner()
        be = watch.WindowsEventBackend([ROOT], runner=r)
        be.install()
        tools = {c[0] for c in r.calls}
        self.assertIn("auditpol", tools)
        self.assertIn("powershell", tools)
        sacl = [c for c in r.calls if c[0] == "powershell"]
        self.assertTrue(any("AddAuditRule" in c[-1] for c in sacl))
        # files can't take inheritance flags — script must branch on it
        self.assertTrue(any("PSIsContainer" in c[-1] for c in sacl))


class TestAllowlist(unittest.TestCase):
    def _ev(self, proc, pid=100, path="C:\\Users\\reven\\.aws\\credentials"):
        return watch.AccessEvent(0, path, proc, pid, "read")

    def _al(self, td, runner=None):
        return watch.Allowlist(Path(td), runner=runner, platform="windows")

    def test_default_allows_defender_signed(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        self.assertTrue(al.allows(self._ev(
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18"
            "\\MsMpEng.exe")))

    def test_defender_unsigned_denied(self):
        """Right name + right dir but no valid signature -> deny."""
        with tempfile.TemporaryDirectory() as td:
            class UnsigRunner(FakeRunner):
                def run(self, argv, timeout=30):
                    if argv[0] == "powershell":
                        return 0, "", ""
                    return super().run(argv, timeout)
            al = self._al(td, UnsigRunner())
        self.assertFalse(al.allows(self._ev(
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18"
            "\\MsMpEng.exe")))

    def test_stealer_not_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        self.assertFalse(al.allows(self._ev("C:\\evil\\stealer.exe")))

    def test_name_spoof_in_wrong_dir_denied(self):
        """claude.exe in %TEMP% is not Claude."""
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        self.assertFalse(al.allows(self._ev(
            "C:\\Users\\reven\\AppData\\Local\\Temp\\claude.exe")))

    def test_agent_in_real_dir_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        self.assertTrue(al.allows(self._ev(
            "C:\\Users\\reven\\AppData\\Local\\Programs\\cursor\\Cursor.exe")))

    def test_node_pinned_to_install_dir(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        ok = self._ev("C:\\Program Files\\nodejs\\node.exe",
                      path="C:\\Users\\reven\\.claude\\x.json")
        bad_dir = self._ev("C:\\x\\node.exe",
                           path="C:\\Users\\reven\\.claude\\x.json")
        bad_obj = self._ev("C:\\Program Files\\nodejs\\node.exe",
                           path="C:\\Users\\reven\\.aws\\credentials")
        self.assertTrue(al.allows(ok))
        self.assertFalse(al.allows(bad_dir))
        self.assertFalse(al.allows(bad_obj))

    def test_self_pid_allowed(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td, FakeRunner())
        self.assertTrue(al.allows(self._ev("python.exe", pid=os.getpid())))

    def test_user_allowlist_file(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "allowlist.json"
            cfg.write_text(json.dumps([{"name": "myagent.exe"}]))
            al = self._al(td, FakeRunner())
        self.assertTrue(al.allows(self._ev("C:\\bin\\myagent.exe")))


class TestWatcher(unittest.TestCase):
    def test_poll_once_filters_and_logs(self):
        with tempfile.TemporaryDirectory() as td:
            r = FakeRunner(FIXTURE.read_text(encoding="utf-8"))
            w = watch.Watcher([ROOT], runner=r, env={"HOME": td},
                              platform="windows", state_dir=Path(td))
            alerts = w.poll_once()
            # stealer + perm-change alert; MsMpEng allowlisted
            self.assertEqual(len(alerts), 2)
            self.assertTrue((Path(td) / "alerts.jsonl").exists())
            log = (Path(td) / "alerts.jsonl").read_text()
            self.assertIn("stealer.exe", log)
            self.assertNotIn("MsMpEng", log)

    def test_honey_flag(self):
        with tempfile.TemporaryDirectory() as td:
            hp = "c:\\users\\reven\\.aws\\credentials"
            w = watch.Watcher([ROOT], honey_paths=[hp],
                              env={"HOME": td}, platform="windows",
                              state_dir=Path(td))
            ev = watch.AccessEvent(0, hp, "x.exe", 1, "read")
            self.assertIn(hp.lower(), w.honey)


class TestSnapshotBackend(unittest.TestCase):
    def test_detects_write_and_delete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / ".aws"
            root.mkdir()
            f = root / "credentials"
            f.write_text("orig")
            be = watch.SnapshotBackend([root])
            be.install()
            self.assertEqual(be.poll(), [])
            f.write_text("changed!")
            evs = be.poll()
            self.assertTrue(any(e.access == "write" for e in evs))
            f.unlink()
            evs = be.poll()
            self.assertTrue(any(e.access == "delete" for e in evs))

    def test_silent_on_stable(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("same")
            be = watch.SnapshotBackend([f])
            be.install()
            self.assertEqual(be.poll(), [])


class TestLinuxParser(unittest.TestCase):
    def test_ausearch_parse(self):
        text = """----
type=SYSCALL ... syscall=openat success=yes pid=4242 exe="/usr/bin/cat"
type=PATH ... item=0 name="/home/u/.aws" nametype=PARENT
type=PATH ... item=1 name="/home/u/.aws/credentials" nametype=NORMAL
type=PROCTITLE ... key="tokenwatch"
----
type=SYSCALL ... syscall=unlink pid=555 exe="/bin/rm"
type=PATH ... item=0 name="/home/u/.ssh" nametype=PARENT
type=PATH ... item=1 name="/home/u/.ssh/id_rsa" nametype=DELETE
type=PROCTITLE ... key="tokenwatch"
"""
        evs = watch.LinuxAuditBackend._parse(text)
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0].process, "/usr/bin/cat")
        self.assertEqual(evs[0].access, "read")
        self.assertEqual(evs[1].access, "write")


if __name__ == "__main__":
    unittest.main()
