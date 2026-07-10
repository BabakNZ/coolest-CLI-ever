import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from accesslog_cli import basic_report, main, parse_access_log


class AccessLogCliTests(unittest.TestCase):
    def test_parse_access_log_skips_invalid_lines(self):
        entries = list(parse_access_log(
            [
                '127.0.0.1 - - [09/Jul/2026:16:00:00 +0000] "GET /home HTTP/1.1" 200 123',
                'invalid line',
            ]
        ))

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "127.0.0.1")
        self.assertEqual(entries[0]["endpoint"], "/home")

    def test_basic_report_counts_requests_unique_ips_top_endpoints_and_percentages(self):
        entries = [
            {"ip": "1.1.1.1", "endpoint": "/a", "status": "200", "timestamp": "09/Jul/2026:01:00:00 +0000"},
            {"ip": "2.2.2.2", "endpoint": "/a", "status": "404", "timestamp": "09/Jul/2026:01:15:00 +0000"},
            {"ip": "1.1.1.1", "endpoint": "/b", "status": "500", "timestamp": "09/Jul/2026:03:00:00 +0000"},
        ]

        report = basic_report(entries, top_n=2, broken_lines=1)

        self.assertEqual(report["total_requests"], 3)
        self.assertEqual(report["unique_ips"], 2)
        self.assertEqual(report["broken_lines"], 1)
        self.assertEqual(report["top_endpoints"], [("/a", 2), ("/b", 1)])
        self.assertEqual(report["hourly_requests"][1], ("01", 2))
        self.assertEqual(report["hourly_requests"][3], ("03", 1))
        self.assertEqual(report["busiest_hours"], ["01"])
        self.assertEqual(report["quietest_hours"], ["03"])
        self.assertAlmostEqual(report["percent_4xx"], 33.33333333333333)
        self.assertAlmostEqual(report["percent_5xx"], 33.33333333333333)

    def test_main_prints_report(self):
        content = (
            '127.0.0.1 - - [09/Jul/2026:01:00:00 +0000] "GET /home HTTP/1.1" 404 123\n'
            '127.0.0.1 - - [09/Jul/2026:01:01:00 +0000] "GET /home HTTP/1.1" 500 123\n'
            '127.0.0.1 - - [09/Jul/2026:03:01:00 +0000] "GET /home HTTP/1.1" 200 123\n'
            'invalid line\n'
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "access.log"
            log_path.write_text(content, encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(log_path), "--top", "1"])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Total requests: 3", output)
        self.assertIn("Unique IPs: 1", output)
        self.assertIn("Broken lines: 1", output)
        self.assertIn("- /home: 3", output)
        self.assertIn("Requests by hour (scaled to 20 blocks):", output)
        self.assertIn("- 01: ████████████████████ (2)", output)
        self.assertIn("- 03: ██████████ (1)", output)
        self.assertIn("Busiest hour(s): 01 (2)", output)
        self.assertIn("Quietest hour(s): 03 (1)", output)
        self.assertIn("4xx responses: 33.33%", output)
        self.assertIn("5xx responses: 33.33%", output)


if __name__ == "__main__":
    unittest.main()
