import tempfile
import unittest
from pathlib import Path

from tokenwatch import secrets


class TestSecrets(unittest.TestCase):
    def test_provider_patterns(self):
        cases = {
            "aws-access-key": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
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

    def test_scan_blob_binary(self):
        blob = (b"SQLite format 3\x00" + b"\x00" * 200 +
                b"sk-proj-" + b"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8" +
                b"\x00" * 200)
        hits = secrets.scan_blob(blob, "state.vscdb")
        self.assertTrue(any("openai" in h.pattern for h in hits))

    def test_scan_file_respects_size_cap(self):
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.log"
            big.write_bytes(b"A" * (secrets.MAX_FILE_BYTES + 1))
            self.assertEqual(secrets.scan_file(big, max_bytes=1024), [])


if __name__ == "__main__":
    unittest.main()
