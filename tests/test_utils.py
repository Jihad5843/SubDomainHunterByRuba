import json
import tempfile
import unittest
from pathlib import Path

from subdomainhunter.config import DEFAULTS, load, write_default
from subdomainhunter.utils import in_scope, normalize_domain, read_wordlist, safe_filename, unique


class UtilsTests(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("https://Example.COM/"), "example.com")
        self.assertEqual(normalize_domain("*.Example.COM"), "example.com")

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")

    def test_scope(self):
        self.assertTrue(in_scope("api.example.com", "example.com"))
        self.assertFalse(in_scope("example.com.evil.test", "example.com"))

    def test_unique(self):
        self.assertEqual(unique(["a", "b", "a"]), ["a", "b"])

    def test_wordlist(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "w.txt"
            p.write_text("api\n# comment\nmail\napi\n", encoding="utf-8")
            self.assertEqual(read_wordlist(p, "example.com"), ["api.example.com", "mail.example.com"])

    def test_config_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            write_default(p)
            cfg = load(p)
            self.assertEqual(cfg["workers"], DEFAULTS["workers"])

    def test_safe_filename(self):
        self.assertEqual(safe_filename("a/b:c"), "a_b_c")


if __name__ == "__main__":
    unittest.main()
