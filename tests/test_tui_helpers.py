import json
import os
import shlex
import stat
import tempfile
import unittest

import tui


class CurlQuoting(unittest.TestCase):
    EVIL = {"name": "O'Brien", "note": "$(touch /tmp/pwned) `id` ; rm -rf /", "q": "a'; echo hacked; '"}

    def test_roundtrip_through_shell_parser(self):
        cmd = tui.format_curl_command({"method": "POST", "url": "https://h/fhir-r4/v1/Patient", "request_payload": self.EVIL})
        argv = shlex.split(cmd.replace("\\\n", " "))
        body = argv[argv.index("-d") + 1]
        self.assertEqual(json.loads(body), self.EVIL)           # body is one intact argument
        self.assertEqual(argv[argv.index("-X") + 1], "POST")

    def test_bad_method_and_url_are_neutralised(self):
        cmd = tui.format_curl_command({"method": "POST; rm -rf /", "url": "https://h/x'; id; '", "request_payload": {}})
        argv = shlex.split(cmd.replace("\\\n", " "))
        self.assertEqual(argv[argv.index("-X") + 1], "POST")
        self.assertEqual(argv[3], "https://h/x'; id; '")

    def test_masked_payload_is_flagged(self):
        cmd = tui.format_curl_command({"method": "POST", "url": "https://h", "request_payload": {}, "pii_masked": True})
        self.assertTrue(cmd.startswith("# NOTE"))


class DisplaySanitising(unittest.TestCase):
    def test_escape_sequences_removed(self):
        self.assertNotIn("\x1b", tui.sanitize_display("a\x1b]0;pwned\x07b\x9bc"))
        self.assertEqual(tui.sanitize_display("tab\tok"), "tab\tok")


class PrivateFiles(unittest.TestCase):
    def test_file_is_0600_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.txt")
            tui.write_private_file(p, "x")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            target = os.path.join(d, "target")
            open(target, "w").close()
            link = os.path.join(d, "link")
            os.symlink(target, link)
            with self.assertRaises(OSError):
                tui.write_private_file(link, "x")

    def test_state_dir_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("XDG_RUNTIME_DIR")
            os.environ["XDG_RUNTIME_DIR"] = d
            try:
                p = tui.private_state_dir()
            finally:
                if old is None:
                    os.environ.pop("XDG_RUNTIME_DIR")
                else:
                    os.environ["XDG_RUNTIME_DIR"] = old
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
