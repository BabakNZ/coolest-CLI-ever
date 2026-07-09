"""Simple CLI and helpers for access log analysis."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse_access_log(lines: Iterable[str]) -> list[dict[str, str]]:
    """Parse access-log lines in common log format.

    Returns only valid parsed entries and skips malformed lines.
    """

    parsed: list[dict[str, str]] = []
    for line in lines:
        match = _LOG_PATTERN.match(line.strip())
        if not match:
            continue
        request = match.group("request")
        endpoint = ""
        parts = request.split()
        if len(parts) >= 2:
            endpoint = parts[1]
        parsed.append(
            {
                "ip": match.group("ip"),
                "timestamp": match.group("time"),
                "request": request,
                "endpoint": endpoint,
                "status": match.group("status"),
                "size": match.group("size"),
            }
        )
    return parsed


def basic_report(entries: list[dict[str, str]], top_n: int = 10) -> dict[str, object]:
    """Generate a basic report from parsed entries."""

    endpoint_counter = Counter(entry["endpoint"] for entry in entries if entry["endpoint"])
    return {
        "total_requests": len(entries),
        "unique_ips": len({entry["ip"] for entry in entries}),
        "top_endpoints": endpoint_counter.most_common(top_n),
    }


def _format_report(report: dict[str, object]) -> str:
    lines = [
        "Access Log Basic Report",
        "=======================",
        f"Total requests: {report['total_requests']}",
        f"Unique IPs: {report['unique_ips']}",
        "Top endpoints:",
    ]
    top_endpoints = report["top_endpoints"]
    if top_endpoints:
        for endpoint, count in top_endpoints:
            lines.append(f"- {endpoint}: {count}")
    else:
        lines.append("- No endpoints found")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze access logs and print a basic report")
    parser.add_argument("logfile", type=Path, help="Path to access log file")
    parser.add_argument("--top", type=int, default=10, help="Number of top endpoints to show")
    args = parser.parse_args(argv)

    if args.top <= 0:
        parser.error("--top must be a positive integer")

    with args.logfile.open("r", encoding="utf-8") as log_file:
        entries = parse_access_log(log_file)

    print(_format_report(basic_report(entries, top_n=args.top)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
