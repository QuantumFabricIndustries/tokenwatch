"""channel.py — proxy/hosts/root-CA tamper checks, all via fake runner."""
import tempfile
import unittest
from pathlib import Path

from tokenwatch import channel
from tokenwatch.platforms import Runner


class FakeRunner(Runner):
    def __init__(self, reg="", netsh="", cert_user="", cert_machine=""):
        super().__init__()
        self.reg, self.netsh = reg, netsh
        self.cert_user, self.cert_machine = cert_user, cert_machine

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "reg":
            return 0, self.reg, ""
        if argv[0] == "netsh":
            return 0, self.netsh, ""
        if argv[0] == "certutil":
            if "-user" in argv:
                return 0, self.cert_user, ""
            return 0, self.cert_machine, ""
        return 0, "", ""


REG_PROXY_ON = r"""
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    10.6.6.6:8888
    AutoConfigURL    REG_SZ    http://evil.example/pac.js
"""
REG_PROXY_OFF = r"""
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x0
"""
NETSH_PROXY = "\nWinHTTP Proxy settings\n    Proxy Server(s) :  10.6.6.6:8888\n"
NETSH_DIRECT = "\nWinHTTP Proxy settings\n    Direct access (no proxy server).\n"
CERT_USER = ("================ Certificate 0 ================\n"
             "Serial Number: aa\nIssuer: CN=EvilCorp Root\n"
             "Subject: CN=EvilCorp Root CA\n")
CERT_MACHINE_MITM = ("================ Certificate 0 ================\n"
                     "Issuer: CN=mitmproxy\nSubject: CN=mitmproxy, O=mitmproxy\n")


class TestChannel(unittest.TestCase):
    def test_env_proxy(self):
        env = {"HTTPS_PROXY": "http://10.6.6.6:8888"}
        f = channel._env_proxies(env)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "proxy-env")

    def test_wininet_enabled(self):
        f = channel._wininet(FakeRunner(reg=REG_PROXY_ON))
        rules = {x.rule for x in f}
        self.assertIn("proxy-system", rules)
        self.assertTrue(any("10.6.6.6" in x.detail for x in f))
        self.assertTrue(any("pac.js" in x.detail for x in f))

    def test_wininet_off(self):
        self.assertEqual(channel._wininet(FakeRunner(reg=REG_PROXY_OFF)), [])

    def test_winhttp(self):
        f = channel._winhttp(FakeRunner(netsh=NETSH_PROXY))
        self.assertEqual(len(f), 1)
        self.assertEqual(channel._winhttp(FakeRunner(netsh=NETSH_DIRECT)),
                         [])

    def test_hosts_hijack_and_sinkhole(self):
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "System32" / "drivers" / "etc" / "hosts"
            hp.parent.mkdir(parents=True)
            hp.write_text(
                "127.0.0.1 localhost\n"
                "10.6.6.6 api.anthropic.com\n"
                "0.0.0.0 openai.com\n"
                "192.168.1.50 mynas.local\n")
            env = {"SystemRoot": td}
            f = channel._hosts(env, None, "windows")
            hijack = [x for x in f if x.rule == "hosts-hijack"]
            self.assertEqual(len(hijack), 2)
            self.assertTrue(any("redirect" in x.detail for x in hijack))
            self.assertTrue(any("sinkhole" in x.detail for x in hijack))
            # non-provider custom mapping -> informational
            self.assertTrue(any(x.rule == "hosts-entry" and "mynas" in
                                x.detail for x in f))

    def test_hosts_clean(self):
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "System32" / "drivers" / "etc" / "hosts"
            hp.parent.mkdir(parents=True)
            hp.write_text("127.0.0.1 localhost\n# comment only\n")
            self.assertEqual(
                channel._hosts({"SystemRoot": td}, None, "windows"), [])

    def test_root_cas(self):
        r = FakeRunner(cert_user=CERT_USER, cert_machine=CERT_MACHINE_MITM)
        f = channel._root_cas(r)
        rules = {x.rule for x in f}
        self.assertIn("user-root-ca", rules)
        self.assertIn("proxy-root-ca", rules)
        self.assertTrue(any("EvilCorp" in x.detail for x in f))

    def test_audit_windows_full(self):
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "System32" / "drivers" / "etc" / "hosts"
            hp.parent.mkdir(parents=True)
            hp.write_text("127.0.0.1 localhost\n")
            env = {"SystemRoot": td, "ALL_PROXY": "socks5://evil"}
            r = FakeRunner(reg=REG_PROXY_ON, netsh=NETSH_DIRECT,
                           cert_user=CERT_USER)
            rules = {x.rule for x in channel.audit(env=env, runner=r,
                                                   platform="windows")}
            self.assertIn("proxy-env", rules)
            self.assertIn("proxy-system", rules)
            self.assertIn("user-root-ca", rules)
            self.assertNotIn("hosts-hijack", rules)


if __name__ == "__main__":
    unittest.main()
