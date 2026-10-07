import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import subdomain_storm as storm
import rclib


def make_context(target="example.com", passive=True, wordlist=None, quiet=True):
    args = argparse.Namespace(
        passive=passive,
        wordlist=wordlist,
        quiet=quiet,
        threads=10,
        timeout=1.0,
    )
    return rclib.Context(args=args, tool="subdomain-storm", target=target)


class NormalizeTargetTests(unittest.TestCase):
    def test_normalizes_url_wildcard_and_idn(self):
        self.assertEqual(
            storm.normalize_target("https://*.Exämple.com:443/path"),
            "xn--exmple-cua.com",
        )

    def test_rejects_invalid_target(self):
        for value in ("example", "127.0.0.1", "bad_domain.example", "https://example.com:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                storm.normalize_target(value)

    def test_subdomain_match_requires_label_boundary(self):
        self.assertEqual(storm._is_subdomain("api.example.com", "example.com"), "api.example.com")
        self.assertIsNone(storm._is_subdomain("notexample.com", "example.com"))
        self.assertIsNone(storm._is_subdomain("example.com.evil", "example.com"))
        self.assertIsNone(storm._is_subdomain("example.com", "example.com"))


class SourceTests(unittest.TestCase):
    def test_crtsh_parsing_filters_out_of_scope_and_apex_names(self):
        payload = json.dumps([
            {"name_value": "www.example.com\n*.api.example.com\nexample.com"},
            {"name_value": "notexample.com\nwww.example.com.evil"},
            {"invalid": "entry"},
        ]).encode("utf-8")
        with patch.object(storm.urllib.request, "urlopen", return_value=io.BytesIO(payload)) as urlopen:
            self.assertEqual(
                storm.fetch_crtsh_names("example.com", 1.0),
                {"www.example.com", "api.example.com"},
            )
        urlopen.assert_called_once()

    def test_crtsh_response_is_size_limited(self):
        payload = b" " * (storm.MAX_CRT_RESPONSE_BYTES + 1)
        with patch.object(storm.urllib.request, "urlopen", return_value=io.BytesIO(payload)):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                storm.fetch_crtsh_names("example.com", 1.0)

    def test_wordlist_requires_valid_single_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.txt"
            path.write_text("www\n# comment\napi\nwww\n", encoding="utf-8")
            self.assertEqual(storm.load_wordlist(str(path)), ["www", "api"])
            path.write_text("api.example.com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                storm.load_wordlist(str(path))


class RunTests(unittest.TestCase):
    def test_passive_mode_does_not_resolve_names(self):
        ctx = make_context()
        with patch.object(storm, "fetch_crtsh_names", return_value={"www.example.com"}), \
                patch.object(storm, "resolves") as resolves, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(storm.run(ctx), 0)
        resolves.assert_not_called()
        self.assertEqual(ctx.data["subdomains"], ["www.example.com"])
        self.assertEqual(ctx.data["resolved_subdomains"], [])
        self.assertFalse(ctx.data["sources"]["dns"]["enabled"])

    def test_active_mode_combines_passive_and_resolved_names(self):
        ctx = make_context(passive=False)
        with patch.object(storm, "WORDS", ["www", "missing"]), \
                patch.object(storm, "fetch_crtsh_names", return_value={"api.example.com"}), \
                patch.object(storm, "resolves", side_effect=lambda name: name if name.startswith("www.") else None), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(storm.run(ctx), 0)
        self.assertEqual(
            ctx.data["subdomains"],
            ["api.example.com", "www.example.com"],
        )
        self.assertEqual(ctx.data["resolved_subdomains"], ["www.example.com"])

    def test_passive_source_failure_is_reported_as_failure(self):
        ctx = make_context()
        output = io.StringIO()
        with patch.object(storm, "fetch_crtsh_names", side_effect=ValueError("bad response")), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(storm.run(ctx), 1)
        self.assertIn("crt.sh unavailable", output.getvalue())
        self.assertFalse(ctx.data["sources"]["crt_sh"]["available"])

    def test_invalid_target_fails_before_network_access(self):
        ctx = make_context(target="notexample.com/path")
        with patch.object(storm, "fetch_crtsh_names") as fetch, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(storm.run(ctx), 2)
        fetch.assert_not_called()


class ArgumentTests(unittest.TestCase):
    def test_threads_and_timeout_are_bounded(self):
        for value in ("0", str(storm.MAX_THREADS + 1)):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                storm._positive_int(value)
        for value in ("0", str(storm.MAX_TIMEOUT + 1)):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                storm._timeout(value)


if __name__ == "__main__":
    unittest.main()
