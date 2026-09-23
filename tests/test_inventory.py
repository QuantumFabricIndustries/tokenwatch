import tempfile
import unittest
from pathlib import Path

from tokenwatch import inventory


def fake_env(home):
    return {"HOME": str(home), "USERPROFILE": str(home),
            "APPDATA": str(home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(home / "AppData" / "Local")}


class TestInventory(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.home = Path(self.td.name)
        self.env = fake_env(self.home)

    def tearDown(self):
        self.td.cleanup()

    def test_discovers_dotfile_stores(self):
        (self.home / ".aws").mkdir()
        (self.home / ".aws" / "credentials").write_text("[default]")
        (self.home / ".claude").mkdir()
        (self.home / ".claude" / ".credentials.json").write_text("{}")
        found = {r.spec.id for r in inventory.discover(env=self.env)}
        self.assertIn("aws", found)
        self.assertIn("claude-code-creds", found)

    def test_posix_fallback_on_windows(self):
        # dotfile stores (~/.ssh etc.) resolve on Windows too — that's where
        # they actually live under USERPROFILE
        (self.home / ".ssh").mkdir()
        found = {r.spec.id for r in
                 inventory.discover(env=self.env, platform="windows")}
        self.assertIn("ssh", found)

    def test_appdata_stores_windows(self):
        claude = self.home / "AppData" / "Roaming" / "Claude"
        claude.mkdir(parents=True)
        found = {r.spec.id for r in
                 inventory.discover(env=self.env, platform="windows")}
        self.assertIn("claude-desktop", found)

    def test_sensitive_vs_context(self):
        (self.home / ".aws").mkdir()
        (self.home / ".aws" / "credentials").write_text("x")
        (self.home / ".claude").mkdir()
        res = inventory.discover(env=self.env)
        sens = {r.spec.id for r in res if r.spec.sensitive}
        ctx = {r.spec.id for r in res if r.spec.kind == "context"}
        self.assertIn("aws", sens)
        self.assertIn("claude-code-dir", ctx)

    def test_context_files_walk(self):
        d = self.home / ".claude" / "projects"
        d.mkdir(parents=True)
        (d / "sess1.jsonl").write_text("chat")
        res = inventory.discover(env=self.env)
        files = list(inventory.context_files(res))
        self.assertIn(d / "sess1.jsonl", files)

    def test_sensitive_paths(self):
        (self.home / ".aws").mkdir()
        res = inventory.discover(env=self.env)
        self.assertIn(self.home / ".aws",
                      inventory.sensitive_paths(res))


if __name__ == "__main__":
    unittest.main()
