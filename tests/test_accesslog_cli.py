import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from accesslog_cli import basic_report, main, parse_access_log


class AccessLogCliTests(unittest.TestCase):
    def test_parse_access_log_skips_invalid_lines(self):
        entries = parse_access_log(
            [
                '127.0.0.1 - - [09/Jul/2026:16:00:00 +0000] "GET /home HTTP/1.1" 200 123',
                'invalid line',
            ]
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "127.0.0.1")
        self.assertEqual(entries[0]["endpoint"], "/home")

    def test_basic_report_counts_requests_unique_ips_and_top_endpoints(self):
        entries = [
            {"ip": "1.1.1.1", "endpoint": "/a"},
            {"ip": "2.2.2.2", "endpoint": "/a"},
            {"ip": "1.1.1.1", "endpoint": "/b"},
        ]

        report = basic_report(entries, top_n=2)

        self.assertEqual(report["total_requests"], 3)
        self.assertEqual(report["unique_ips"], 2)
        self.assertEqual(report["top_endpoints"], [("/a", 2), ("/b", 1)])

    def test_main_prints_report(self):
        content = '127.0.0.1 - - [09/Jul/2026:16:00:00 +0000] "GET /home HTTP/1.1" 200 123\n'
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "access.log"
            log_path.write_text(content, encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(log_path), "--top", "1"])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Total requests: 1", output)
        self.assertIn("Unique IPs: 1", output)
        self.assertIn("- /home: 1", output)


if __name__ == "__main__":
    unittest.main()
