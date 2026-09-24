import tempfile
import unittest
from pathlib import Path

from tokenwatch import secrets


class TestSecrets(unittest.TestCase):
    def test_provider_patterns(self):
        cases = {
            "aws-access-key": "aws_access_key_id = AKIAVK6M4HX7PTWD2QRY",
            "anthropic-key":  "key: sk-ant-api03-" + "a1B2c3D4" * 6,
            "github-pat":     "token github_pat_" + "Ab1" * 22,
            "private-key-hdr": "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
            "hf-token":       "hf_" + "aB3d" * 9,
            "stripe-key":     "sk_live_" + "xY9z" * 6,
        }
        for name, text in cases.items():
            hits = secrets.scan_text(text, "f")
            self.assertTrue(any(h.pattern == name for h in hits),
                            f"{name} not detected in {text!r}")

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        hits = secrets.scan_text(f"auth: {jwt}", "f")
        self.assertTrue(any(h.pattern == "jwt" for h in hits))

    def test_generic_entropy_gate(self):
        # high-entropy assignment -> hit
        hits = secrets.scan_text(
            'api_key = "Kx9mZ2pQ7vN4wL8jR3tY6uI1oP5aS0"', "f")
        self.assertTrue(any(h.generic for h in hits))
        # placeholders -> no hit
        for bogus in ['api_key = "changeme"', 'token = "${TOKEN}"',
                      'password = "your_password_here"',
                      'secret = "xxxxxxxxxxxxxxxx"']:
            self.assertFalse(secrets.scan_text(bogus, "f"), bogus)

    def test_mask_never_leaks_full_value(self):
        secret = "sk-ant-api03-" + "a1B2c3D4" * 6
        hits = secrets.scan_text(f"key={secret}", "f")
        for h in hits:
            self.assertNotIn(secret, h.masked)
            self.assertIn("...", h.masked)

    def test_redact_cmdline_secrets(self):
        """4688 command lines carry secrets — alerts.jsonl must hold only
        masked forms."""
        tok = "ghp_" + "Ab1" * 13
        line = f'git clone https://{tok}@github.com/o/r && curl -H "x"'
        out = secrets.redact(line)
        self.assertNotIn(tok, out)
        self.assertIn("ghp_", out)            # masked form keeps prefix
        self.assertIn("git clone", out)       # non-secret text preserved
        # nothing to redact -> identity
        self.assertEqual(secrets.redact("cmd /c dir"), "cmd /c dir")
        # generic assignment secrets redact too
        secret = "Kx9mZ2pQ7vN4wL8jR3tY6uI1oP5aS0"
        out = secrets.redact(f'run --arg api_key="{secret}"')
        self.assertNotIn(secret, out)

    def test_scan_blob_binary(self):
        blob = (b"SQLite format 3\x00" + b"\x00" * 200 +
                b"sk-proj-" + b"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8" +
                b"\x00" * 200)
        hits = secrets.scan_blob(blob, "state.vscdb")
        self.assertTrue(any("openai" in h.pattern for h in hits))

    def test_doc_examples_and_placeholders_excluded(self):
        # AWS's canonical docs pair — must NOT count as findings
        self.assertEqual(
            secrets.scan_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
                              "f"), [])
        self.assertEqual(
            secrets.scan_text(
                "aws_secret_access_key = "
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "f"), [])
        # anything ending EXAMPLEKEY, sequential placeholders
        self.assertEqual(
            secrets.scan_text('key = "AKIA0123456789ABCDEF"', "f"), [])
        # but a live-looking AKIA still hits
        self.assertTrue(secrets.scan_text(
            "aws_access_key_id = AKIAVK6M4HX7PTWD2QRY", "f"))

    def test_dedupe_fingerprint_stable(self):
        val = "hf_" + "aB3d" * 9
        h1 = secrets.scan_text(f"t: {val}\nt: {val}", "f")
        self.assertEqual(len({h.fp for h in h1}), 1)   # same fp for same val
        self.assertEqual(len(h1), 2)                   # two positions, one val

    def test_scan_file_respects_size_cap(self):
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.log"
            big.write_bytes(b"A" * (secrets.MAX_FILE_BYTES + 1))
            self.assertEqual(secrets.scan_file(big, max_bytes=1024), [])

    def test_discord_tokens(self):
        # mfa.* variant and standard 24.6.27-part tokens
        hits = secrets.scan_text(
            "token = mfa." + "aB3-" * 15, "f")
        self.assertTrue(any(h.pattern == "discord-token" for h in hits))
        std = ("MTIzNDU2Nzg5MDEyMzQ1Njc4."
               "GaBcDe."
               + "xY9z" * 8)
        hits = secrets.scan_text(f"\"{std}\"", "f")
        self.assertTrue(any(h.pattern == "discord-token" for h in hits))

    def test_slack_xoxd_xapp(self):
        for tok in ("xoxd-" + "aB3" * 12, "xapp-" + "Z9y" * 12):
            hits = secrets.scan_text(f"t: {tok}", "f")
            self.assertTrue(any(h.pattern == "slack-token" for h in hits),
                            tok)

    def test_entra_client_secret(self):
        """Caught by shape anywhere (scripts, .env, notes) - not only
        under a client_secret key - and masked by redact()."""
        sec = "aB3" + "8Q~" + "Zx9_-.~Ab" * 3 + "Qw12"   # 3+1+Q~+31
        hits = secrets.scan_text(f"$s = '{sec}'", "f")
        self.assertTrue(any(h.pattern == "entra-client-secret"
                            for h in hits))
        red = secrets.redact(f"Connect-MgGraph -Secret {sec}")
        self.assertNotIn(sec[6:], red)
        # a DPAPI blob / cert thumbprint in graph.json is NOT a secret
        clean = ('{"client_secret_dpapi": "AQAAANCMnd8BFdERjHoAwE", '
                 '"cert_thumbprint": "' + "AB" * 20 + '"}')
        self.assertFalse(any(h.pattern == "entra-client-secret"
                             for h in secrets.scan_text(clean, "f")))

    def test_filezilla_pass(self):
        hits = secrets.scan_text(
            '<Server><Pass>Sup3rSecretFTP</Pass></Server>', "f")
        self.assertTrue(any(h.pattern == "filezilla-pass" for h in hits))
        # base64-encoded Pass doesn't match (value isn't plaintext)
        hits = secrets.scan_text(
            '<Pass encoding="base64">U3VwM3I=</Pass>', "f")
        self.assertFalse(any(h.pattern == "filezilla-pass" for h in hits))

    def test_generic_bare_pass(self):
        # rclone.conf uses `pass = ...` — bare 'pass' now in alternation
        hits = secrets.scan_text(
            "pass = " + "Kx9mZ2pQ7vN4wL8jR3tY", "f")
        self.assertTrue(any(h.generic for h in hits))
        # word-boundary: 'compass'/'bypass' must not trigger
        self.assertFalse(secrets.scan_text(
            'bypass = "Kx9mZ2pQ7vN4wL8jR3tY"', "f"))


if __name__ == "__main__":
    unittest.main()
