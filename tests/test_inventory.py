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

    def test_tokenreplay_graph_store(self):
        """The sibling tool's tenant-wide Graph credential is watched and
        secret-scanned - the two tools cover each other."""
        (self.home / ".tokenreplay").mkdir()
        g = self.home / ".tokenreplay" / "graph.json"
        g.write_text('{"tenant": "t"}')
        for plat in ("windows", "linux"):
            res = [r for r in inventory.discover(env=self.env,
                                                 platform=plat)
                   if r.spec.id == "tokenreplay-graph"]
            self.assertEqual([r.path for r in res], [g], plat)
            self.assertTrue(res[0].spec.sensitive)
            self.assertIn(g, set(inventory.context_files(res)))

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


class TestStealerTargets(unittest.TestCase):
    """Browser/messaging/wallet/OS-cred stores — the classic infostealer
    surface. Multi-segment globs must resolve to concrete files."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.home = Path(self.td.name)
        self.env = fake_env(self.home)

    def tearDown(self):
        self.td.cleanup()

    def test_chrome_profile_globs(self):
        ud = self.home / "AppData" / "Local" / "Google" / "Chrome" \
            / "User Data"
        (ud / "Default" / "Network").mkdir(parents=True)
        (ud / "Profile 1").mkdir(parents=True)
        (ud / "Local State").write_text('{"os_crypt":{}}')
        (ud / "Default" / "Network" / "Cookies").write_text("x")
        (ud / "Default" / "Login Data").write_text("x")
        (ud / "Profile 1" / "Login Data").write_text("x")
        res = inventory.discover(env=self.env, platform="windows")
        paths = [r.path for r in res if r.spec.id == "chrome-secrets"]
        self.assertIn(ud / "Local State", paths)
        self.assertIn(ud / "Default" / "Network" / "Cookies", paths)
        # both profiles' Login Data resolved via mid-path glob
        self.assertIn(ud / "Default" / "Login Data", paths)
        self.assertIn(ud / "Profile 1" / "Login Data", paths)

    def test_firefox_profile_globs(self):
        prof = self.home / "AppData" / "Roaming" / "Mozilla" / "Firefox" \
            / "Profiles" / "abc.default-release"
        prof.mkdir(parents=True)
        (prof / "logins.json").write_text("{}")
        (prof / "key4.db").write_text("x")
        (prof / "cookies.sqlite").write_text("x")
        res = inventory.discover(env=self.env, platform="windows")
        paths = {r.path.name for r in res
                 if r.spec.id == "firefox-secrets"}
        self.assertEqual(paths, {"logins.json", "key4.db",
                                 "cookies.sqlite"})

    def test_discord_variant_glob(self):
        for var in ("discord", "discordcanary"):
            d = self.home / "AppData" / "Roaming" / var \
                / "Local Storage" / "leveldb"
            d.mkdir(parents=True)
        res = inventory.discover(env=self.env, platform="windows")
        hits = [r for r in res if r.spec.id == "discord-tokens"]
        self.assertEqual(len(hits), 2)

    def test_win_cred_infra(self):
        for sub in ("Protect", "Credentials"):
            (self.home / "AppData" / "Roaming" / "Microsoft"
             / sub).mkdir(parents=True)
        res = inventory.discover(env=self.env, platform="windows")
        self.assertTrue(any(r.spec.id == "win-cred-infra" for r in res))

    def test_steam_pf86_token(self):
        pf = self.home / "pf86"
        self.env["ProgramFiles(x86)"] = str(pf)
        (pf / "Steam" / "config").mkdir(parents=True)
        (pf / "Steam" / "ssfn12345").write_text("x")
        res = inventory.discover(env=self.env, platform="windows")
        paths = {r.path for r in res if r.spec.id == "steam-session"}
        self.assertIn(pf / "Steam" / "config", paths)
        self.assertIn(pf / "Steam" / "ssfn12345", paths)

    def test_posix_wallet_stores(self):
        (self.home / ".electrum" / "wallets").mkdir(parents=True)
        (self.home / ".config" / "solana").mkdir(parents=True)
        (self.home / ".config" / "solana" / "id.json").write_text("[1,2,3]")
        (self.home / ".config" / "filezilla").mkdir(parents=True)
        res = inventory.discover(env=self.env, platform="linux")
        ids = {r.spec.id for r in res}
        self.assertIn("electrum-wallet", ids)
        self.assertIn("solana-keypair", ids)
        self.assertIn("filezilla", ids)

    def test_new_agent_tools(self):
        (self.home / ".config" / "opencode").mkdir(parents=True)
        (self.home / ".qwen").mkdir()
        (self.home / ".factory").mkdir()
        res = inventory.discover(env=self.env, platform="linux")
        ids = {r.spec.id for r in res}
        self.assertIn("opencode", ids)
        self.assertIn("qwen-code", ids)
        self.assertIn("factory", ids)


if __name__ == "__main__":
    unittest.main()
