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

    def test_poll_queries_by_record_id_after_first(self):
        """First poll seeds watermark via time window; later polls query
        strictly EventRecordID > N — late-flushed events can't be dropped."""
        r = FakeRunner(FIXTURE.read_text(encoding="utf-8"))
        be = watch.WindowsEventBackend([ROOT], runner=r)
        be.poll()                          # seeds last_record = 99104
        be.poll()
        qs = [c[3] for c in r.calls if c[0] == "wevtutil"]
        self.assertIn("timediff", qs[0])   # windowed seed query
        self.assertIn("EventRecordID > 99104", qs[-1])

    def test_install_runs_auditpol_and_sacl(self):
        with tempfile.TemporaryDirectory() as td:
            r = FakeRunner()
            be = watch.WindowsEventBackend([ROOT], runner=r,
                                           env={"HOME": td})
            be.install()
            tools = {c[0] for c in r.calls}
            self.assertIn("auditpol", tools)
            self.assertIn("powershell", tools)
            self.assertIn("reg", tools)      # cmdline-in-4688 value
            sacl = [c for c in r.calls if c[0] == "powershell"]
            self.assertTrue(any("AddAuditRule" in c[-1] for c in sacl))
            # files can't take inheritance flags — script must branch
            self.assertTrue(any("PSIsContainer" in c[-1] for c in sacl))
            # process-creation auditing + command-line capture enabled
            ap = [c for c in r.calls if c[0] == "auditpol"]
            self.assertTrue(any(watch.PROC_CREATION_GUID in " ".join(c)
                                and "/success:enable" in c for c in ap))
            self.assertTrue(any("ProcessCreationIncludeCmdLine_Enabled"
                                in " ".join(c) for c in r.calls
                                if c[0] == "reg"))


FIXTURE_4688 = Path(__file__).parent / "fixtures" / "wevtutil_4688.xml"


class Test4688Parsing(unittest.TestCase):
    """Process-creation events: persist after the process exits (a
    snapshot misses it) and carry the creator's real name."""

    def _evs(self):
        be = watch.WindowsEventBackend([ROOT], runner=FakeRunner())
        return be._parse(FIXTURE_4688.read_text(encoding="utf-8"))

    def test_real_profile_debug_launch(self):
        dl = [e for e in self._evs() if e.access == "debug-launch"]
        self.assertEqual(len(dl), 1)
        self.assertEqual(dl[0].pid, 0x1A2B)
        self.assertIn("chrome.exe", dl[0].process.lower())
        self.assertIn("wscript.exe", dl[0].detail)

    def test_fresh_profile_is_info_not_compromise(self):
        info = [e for e in self._evs()
                if e.access == "debug-launch-info"]
        self.assertEqual(len(info), 1)
        self.assertIn("msedge.exe", info[0].process.lower())

    def test_clean_and_nonbrowser_dropped(self):
        # 4 events in fixture -> exactly 2 surfaced; clean chrome and
        # notepad-with-a-flag never reach the event list
        self.assertEqual(len(self._evs()), 2)

    def test_cmdline_secrets_redacted_before_log(self):
        """4688 command lines can carry secrets — the alert stores only
        the masked form."""
        tok = "ghp_" + "Ab1" * 13
        ev = watch.WindowsEventBackend._event_4688({
            "NewProcessName": "C:\\Program Files\\Google\\Chrome\\"
                              "Application\\chrome.exe",
            "CommandLine": "chrome.exe --remote-debugging-port=1 "
                           f"https://{tok}@github.com/o/r",
            "ParentProcessName": "C:\\Windows\\System32\\wscript.exe",
            "NewProcessId": "0x99",
        })
        self.assertIsNotNone(ev)
        self.assertNotIn(tok, ev.path)
        self.assertIn("ghp_", ev.path)       # masked prefix survives


class TestMarkerSacls(unittest.TestCase):
    """Inheritable parent-dir rule: files created by atomic replace are
    born audited — the drift window is closed structurally."""

    def _install(self, roots, td):
        r = FakeRunner()
        be = watch.WindowsEventBackend(roots, runner=r,
                                       env={"HOME": td})
        be.install()
        return [c[-1] for c in r.calls if c[0] == "powershell"]

    def test_file_root_parent_gets_marker(self):
        with tempfile.TemporaryDirectory() as td:
            root = str(Path(td) / "store" / "creds.json")
            ps = self._install([root], td)
            self.assertTrue(any(
                "NoPropagateInherit" in s and "AddAuditRule" in s
                and "store" in s for s in ps))

    def test_dir_root_needs_no_marker(self):
        """Dir roots get OICI — children already inherit."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "store"
            d.mkdir()
            ps = self._install([str(d)], td)
            self.assertFalse(any("NoPropagateInherit" in s for s in ps))

    def test_home_dir_never_marked(self):
        """~/.env.backup's parent is ~ — marking it would audit every
        file the user creates; strays aren't app-rewritten anyway."""
        with tempfile.TemporaryDirectory() as td:
            root = str(Path(td) / ".env.backup")
            ps = self._install([root], td)
            self.assertFalse(any("NoPropagateInherit" in s for s in ps))

    def test_dir_root_children_stamped_at_install(self):
        """Inheritance only reaches NEW children — existing files inside
        a dir root (Protect\\<SID>\\key, leveldb) must be stamped at
        install or they stay unaudited."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "store"
            d.mkdir()
            (d / "key1").write_text("x")
            ps = self._install([str(d)], td)
            self.assertTrue(any(
                "Get-ChildItem" in s and "Recurse" in s
                and "AddAuditRule" in s for s in ps))

    def test_propagate_cap_warns_loudly(self):
        """Truncation is not silent — the install action names the root,
        the cap, and the real child count."""
        class TruncRunner(FakeRunner):
            def run(self, argv, timeout=30):
                if argv[0] == "powershell" and \
                        "Get-ChildItem" in argv[-1]:
                    return 0, "TRUNCATED 620\n", ""
                return super().run(argv, timeout)
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "store"
            d.mkdir()
            r = TruncRunner()
            be = watch.WindowsEventBackend([str(d)], runner=r,
                                           env={"HOME": td})
            acts = be.install()
            self.assertTrue(any(
                "WARNING" in a and "620" in a and str(d).lower() in a
                for a in acts))

    def test_log_size_recorded_raised_restored(self):
        """4688 volume rolls the ~20MB default Security log in hours —
        install raises it, uninstall restores the recorded value."""
        class GlRunner(FakeRunner):
            def run(self, argv, timeout=30):
                if argv[0] == "wevtutil" and argv[1] == "gl":
                    return 0, "name: Security\nmaxSize: 20971520\n", ""
                return super().run(argv, timeout)
        with tempfile.TemporaryDirectory() as td:
            r = GlRunner()
            be = watch.WindowsEventBackend([ROOT], runner=r,
                                           env={"HOME": td})
            be.install()
            self.assertTrue(any(
                c[0] == "wevtutil" and c[1] == "sl"
                and f"/ms:{watch.LOG_MAX_BYTES}" in c for c in r.calls))
            r.calls.clear()
            be.uninstall()
            self.assertTrue(any(
                c[0] == "wevtutil" and c[1] == "sl"
                and "/ms:20971520" in c for c in r.calls))


class TestAuditStateRestore(unittest.TestCase):
    """install() records prior Process-Creation auditing state;
    uninstall() restores it instead of leaving the machine louder."""

    def test_state_saved_and_restored(self):
        with tempfile.TemporaryDirectory() as td:
            r = FakeRunner()
            be = watch.WindowsEventBackend([ROOT], runner=r,
                                           env={"HOME": td})
            be.install()
            state = Path(td) / ".tokenwatch" / "audit_policy_state.json"
            self.assertTrue(state.exists())
            r.calls.clear()
            be.uninstall()
            self.assertFalse(state.exists())
            # FakeRunner: reg query -> empty -> value was absent ->
            # restore deletes it rather than writing a bogus value
            self.assertTrue(any(c[0] == "reg" and "delete" in c
                                for c in r.calls))
            # prior "Success" unknown -> do NOT blindly disable
            self.assertFalse(any("/success:disable" in " ".join(c)
                                 for c in r.calls))


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


class SignedRunner(FakeRunner):
    """Authenticode: returns a Google/Microsoft/Mozilla subject for the
    matching install dirs; everything else unsigned."""
    def run(self, argv, timeout=30):
        if argv[0] == "powershell" and \
                "Get-AuthenticodeSignature" in argv[-1]:
            cmd = argv[-1]
            for marker, cn in (("\\Google\\Chrome\\", "CN=Google LLC"),
                               ("\\Mozilla Firefox\\", "CN=Mozilla"),
                               ("\\Windows\\System32\\", "CN=Microsoft"),
                               ("\\Windows\\", "CN=Microsoft")):
                if marker.lower() in cmd.lower():
                    return 0, cn + "\n", ""
            return 0, "", ""
        return super().run(argv, timeout)


class TestStealerAllowlist(unittest.TestCase):
    """New stores' legitimate readers allowlisted; everything else alerts."""

    def _al(self, td):
        return watch.Allowlist(Path(td), runner=SignedRunner(),
                               platform="windows")

    def _ev(self, proc, path, pid=100):
        return watch.AccessEvent(0, path, proc, pid, "read")

    CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    LSASS = "C:\\Windows\\System32\\lsass.exe"

    def test_chrome_allowed_on_own_profile(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertTrue(al.allows(self._ev(
                self.CHROME,
                "C:\\Users\\reven\\AppData\\Local\\Google\\Chrome\\"
                "User Data\\Default\\Login Data")))

    def test_chrome_denied_off_profile(self):
        """A real chrome.exe touching .aws is still suspicious."""
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertFalse(al.allows(self._ev(
                self.CHROME, "C:\\Users\\reven\\.aws\\credentials")))

    def test_unsigned_chrome_denied(self):
        """chrome.exe in the right dir but unsigned -> deny (fail closed)."""
        with tempfile.TemporaryDirectory() as td:
            al = watch.Allowlist(Path(td), runner=FakeRunner(),
                                 platform="windows")
            self.assertFalse(al.allows(self._ev(
                self.CHROME,
                "C:\\Users\\reven\\AppData\\Local\\Google\\Chrome\\"
                "User Data\\Local State")))

    def test_lsass_reads_dpapi(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertTrue(al.allows(self._ev(
                self.LSASS,
                "C:\\Users\\reven\\AppData\\Roaming\\Microsoft\\Protect\\"
                "S-1-5-21\\mk-guid")))

    def test_user_proc_on_dpapi_denied(self):
        """The whole point: a random user process on Protect/ = stealer."""
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertFalse(al.allows(self._ev(
                "C:\\Users\\reven\\AppData\\Local\\Temp\\upd.exe",
                "C:\\Users\\reven\\AppData\\Roaming\\Microsoft\\Protect\\"
                "S-1-5-21\\mk-guid")))

    def test_discord_own_leveldb(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertTrue(al.allows(self._ev(
                "C:\\Users\\reven\\AppData\\Local\\Discord\\app-1.0\\"
                "Discord.exe",
                "C:\\Users\\reven\\AppData\\Roaming\\discord\\"
                "Local Storage\\leveldb\\0005.ldb")))

    def test_spoofed_discord_denied(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertFalse(al.allows(self._ev(
                "C:\\Temp\\Discord.exe",
                "C:\\Users\\reven\\AppData\\Roaming\\discord\\"
                "Local Storage\\leveldb\\0005.ldb")))

    def test_firefox_signed(self):
        with tempfile.TemporaryDirectory() as td:
            al = self._al(td)
            self.assertTrue(al.allows(self._ev(
                "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
                "C:\\Users\\reven\\AppData\\Roaming\\Mozilla\\Firefox\\"
                "Profiles\\abc.default\\logins.json")))


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
