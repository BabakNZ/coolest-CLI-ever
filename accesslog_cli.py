from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

def parse_access_log(lines: Iterable[str]) -> Iterator[dict[str, str]]:
    for line in lines:
        line = line.strip()
        if not line:
            continue

        parts = line.split('"', 2)
        if len(parts) < 3:
            continue

        before_request, request, after_request = parts
        before_request_parts = before_request.split()
        if not before_request_parts:
            continue

        ip = before_request_parts[0]
        time_start = before_request.find("[")
        time_end = before_request.find("]", time_start + 1)
        if time_start == -1 or time_end == -1:
            continue

        response_parts = after_request.strip().split()
        if len(response_parts) < 2:
            continue

        status, size = response_parts[0], response_parts[1]
        if len(status) != 3 or not status.isdigit():
            continue

        endpoint = ""
        request_parts = request.split()
        if len(request_parts) >= 2:
            endpoint = request_parts[1]

        yield {
            "ip": ip,
            "timestamp": before_request[time_start + 1 : time_end],
            "request": request,
            "endpoint": endpoint,
            "status": status,
            "size": size,
        }


def basic_report(entries: Iterable[dict[str, str]], top_n: int = 10) -> dict[str, object]:
    """Generate a basic report from parsed entries."""

    total_requests = 0
    unique_ips: set[str] = set()
    endpoint_counter: Counter[str] = Counter()
    for entry in entries:
        total_requests += 1
        unique_ips.add(entry["ip"])
        if entry["endpoint"]:
            endpoint_counter[entry["endpoint"]] += 1

    return {
        "total_requests": total_requests,
        "unique_ips": len(unique_ips),
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

    if not args.logfile.is_file():
        parser.error(f"Log file '{args.logfile}' does not exist or is not a file")
    
    with args.logfile.open("r", encoding="utf-8") as log_file:
        print(_format_report(basic_report(parse_access_log(log_file), top_n=args.top)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
