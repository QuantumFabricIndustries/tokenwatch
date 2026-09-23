"""perms + honey + score + end-to-end audit — all synthetic fixtures."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tokenwatch import cli, honey, perms, platforms, score
from tokenwatch.platforms import Runner


class FakeRunner(Runner):
    def __init__(self, icacls_out=""):
        super().__init__()
        self.icacls = icacls_out

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "icacls":
            return 0, self.icacls, ""
        return 0, "", ""


ICACLS_CLEAN = """C:\\x NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
    BUILTIN\\Administrators:(OI)(CI)(F)
    REVEN\\reven:(OI)(CI)(F)
"""

ICACLS_LOOSE = """C:\\x NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
    BUILTIN\\Users:(I)(RX)
    Everyone:(R)
"""


def fake_env(home, state=None):
    return {"HOME": str(home), "USERPROFILE": str(home),
            "USERNAME": "reven", "USERDOMAIN": "REVEN",
            "APPDATA": str(home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "TOKENWATCH_HOME": str(state or home / ".tokenwatch")}


class TestPermsWindows(unittest.TestCase):
    def test_clean_acl(self):
        r = FakeRunner(ICACLS_CLEAN)
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("x")
            issues = perms._windows_issues(
                f, env=fake_env(Path(td)), runner=r)
            self.assertEqual(issues, [])

    def test_foreign_trustee_flagged(self):
        r = FakeRunner(ICACLS_LOOSE)
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("x")
            issues = perms._windows_issues(
                f, env=fake_env(Path(td)), runner=r)
            self.assertEqual(len(issues), 2)
            self.assertTrue(any("Everyone" in i.detail for i in issues))

    def test_lockdown_argv(self):
        r = FakeRunner()
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("x")
            act = perms._windows_fix(f, env=fake_env(Path(td)), runner=r)
            self.assertIsNotNone(act)
            argv = r.calls[0]
            self.assertIn("/inheritance:r", argv)
            grants = [a for a in argv if ":(OI)(CI)F" in a]
            self.assertEqual(len(grants), 3)
            self.assertTrue(all(g.startswith(("REVEN\\reven:", "SYSTEM:",
                                             "Administrators:"))
                                for g in grants))


@unittest.skipIf(platforms.IS_WINDOWS,
                 "POSIX mode bits not settable on Windows")
class TestPermsPosix(unittest.TestCase):
    def test_loose_mode_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("x")
            os.chmod(f, 0o644)
            self.assertTrue(perms._posix_issue(f))

    def test_lockdown(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "creds"
            f.write_text("x")
            os.chmod(f, 0o644)
            perms._posix_fix(f)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)


class TestHoney(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.home = Path(self.td.name)
        self.env = fake_env(self.home)

    def tearDown(self):
        self.td.cleanup()

    def test_plant_status_clean(self):
        planted, skipped = honey.plant(env=self.env)
        self.assertTrue(len(planted) >= 4)
        rows = dict((i, s) for i, p, s in honey.status(env=self.env))
        self.assertEqual(set(rows.values()), {"ARMED"})
        removed = honey.clean(env=self.env)
        self.assertEqual(len(removed), len(planted))
        self.assertEqual(honey.status(env=self.env), [])

    def test_never_overwrites_real_store(self):
        (self.home / ".aws").mkdir()
        real = self.home / ".aws" / "credentials"
        real.write_text("real creds")
        planted, skipped = honey.plant(env=self.env)
        self.assertTrue(any("real file exists" in s for s in skipped))
        self.assertEqual(real.read_text(), "real creds")

    def test_modified_canary_flagged(self):
        honey.plant(env=self.env)
        env_file = self.home / ".tokenwatch" / "honey" / ".env"
        env_file.write_text("tampered")
        rows = dict((i, s) for i, p, s in honey.status(env=self.env))
        self.assertEqual(rows["honey-env"], "TOUCHED/MODIFIED")


class TestScore(unittest.TestCase):
    def test_tiers(self):
        from tokenwatch.score import Finding
        self.assertEqual(score.score([]), (0, "HARDENED"))
        self.assertEqual(score.score([Finding("perm-loose-file", "p")]),
                         (40, "EXPOSED"))
        self.assertEqual(score.score([Finding("perm-loose-file", "p"),
                                      Finding("mcp-plaintext-key", "p")]),
                         (70, "HIGH RISK"))
        _, v = score.score([Finding("honeytoken-read", "p")])
        self.assertEqual(v, "COMPROMISED")

    def test_rule_caps(self):
        from tokenwatch.score import Finding
        many = [Finding("context-secret", f"p{i}") for i in range(10)]
        total, _ = score.score(many)
        self.assertLessEqual(total, 70)   # capped, not 350


class TestAuditE2E(unittest.TestCase):
    def test_audit_clean_home(self):
        with tempfile.TemporaryDirectory() as td:
            env = fake_env(Path(td))
            rep = cli._run_audit(env)
            self.assertEqual(rep.verdict, "HARDENED")
            self.assertEqual(rep.score, 0)

    def test_audit_finds_context_secret(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            d = home / ".claude" / "projects"
            d.mkdir(parents=True)
            (d / "sess.jsonl").write_text(
                'user pasted: sk-ant-api03-' + 'a1B2c3D4' * 6)
            rep = cli._run_audit(fake_env(home))
            rules = {f.rule for f in rep.findings}
            self.assertIn("context-secret", rep.findings[0].rule or rules)
            self.assertIn("context-secret", rules)

    def test_audit_finds_mcp_plaintext(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            mc = home / ".cursor"
            mc.mkdir()
            (mc / "mcp.json").write_text(
                '{"mcpServers":{"x":{"env":{"KEY":"AKIAIOSFODNN7EXAMPLE"}}}}')
            rep = cli._run_audit(fake_env(home))
            self.assertTrue(any(f.rule == "mcp-plaintext-key"
                                for f in rep.findings))

    def test_env_secret_finding(self):
        with tempfile.TemporaryDirectory() as td:
            env = fake_env(Path(td))
            env["OPENAI_API_KEY"] = "sk-proj-abc123"
            rep = cli._run_audit(env)
            self.assertTrue(any(f.rule == "env-secret"
                                for f in rep.findings))

    def test_paths_cmd(self):
        self.assertEqual(cli.main(["paths"]), 0)


if __name__ == "__main__":
    unittest.main()
