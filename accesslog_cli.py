from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator


def _parse_access_log_line(line: str) -> dict[str, str] | None:
    line = line.strip()
    if not line:
        return None

    parts = line.split('"', 2)
    if len(parts) < 3:
        return None

    before_request, request, after_request = parts
    before_request_parts = before_request.split()
    if not before_request_parts:
        return None

    ip = before_request_parts[0]
    time_start = before_request.find("[")
    time_end = before_request.find("]", time_start + 1)
    if time_start == -1 or time_end == -1:
        return None

    response_parts = after_request.strip().split()
    if len(response_parts) < 2:
        return None

    status, size = response_parts[0], response_parts[1]
    if len(status) != 3 or not status.isdigit():
        return None

    endpoint = ""
    request_parts = request.split()
    if len(request_parts) >= 2:
        endpoint = request_parts[1]

    return {
        "ip": ip,
        "timestamp": before_request[time_start + 1 : time_end],
        "request": request,
        "endpoint": endpoint,
        "status": status,
        "size": size,
    }

def parse_access_log(lines: Iterable[str]) -> Iterator[dict[str, str]]:
    for line in lines:
        entry = _parse_access_log_line(line)
        if entry is not None:
            yield entry


def basic_report(
    entries: Iterable[dict[str, str]],
    top_n: int = 10,
    broken_lines: int = 0,
) -> dict[str, object]:
    """Generate a basic report from parsed entries."""

    total_requests = 0
    unique_ips: set[str] = set()
    endpoint_counter: Counter[str] = Counter()
    status_4xx = 0
    status_5xx = 0
    for entry in entries:
        total_requests += 1
        unique_ips.add(entry["ip"])
        if entry["endpoint"]:
            endpoint_counter[entry["endpoint"]] += 1
        status_code = entry.get("status", "")
        if status_code.startswith("4"):
            status_4xx += 1
        elif status_code.startswith("5"):
            status_5xx += 1

    if total_requests:
        percent_4xx = (status_4xx / total_requests) * 100
        percent_5xx = (status_5xx / total_requests) * 100
    else:
        percent_4xx = 0.0
        percent_5xx = 0.0

    return {
        "total_requests": total_requests,
        "unique_ips": len(unique_ips),
        "top_endpoints": endpoint_counter.most_common(top_n),
        "broken_lines": broken_lines,
        "percent_4xx": percent_4xx,
        "percent_5xx": percent_5xx,
    }


def analyze_access_log(lines: Iterable[str], top_n: int = 10) -> dict[str, object]:
    entries: list[dict[str, str]] = []
    broken_lines = 0

    for line in lines:
        entry = _parse_access_log_line(line)
        if entry is None:
            if line.strip():
                broken_lines += 1
            continue
        entries.append(entry)

    return basic_report(entries, top_n=top_n, broken_lines=broken_lines)


def _format_report(report: dict[str, object]) -> str:
    lines = [
        f"Total requests: {report['total_requests']}",
        f"Unique IPs: {report['unique_ips']}",
        f"Broken lines: {report['broken_lines']}",
        "Top endpoints:",
    ]
    top_endpoints = report["top_endpoints"]
    if top_endpoints:
        for endpoint, count in top_endpoints:
            lines.append(f"- {endpoint}: {count}")
    else:
        lines.append("- No endpoints found")
    lines.append(f"4xx responses: {report['percent_4xx']:.2f}%")
    lines.append(f"5xx responses: {report['percent_5xx']:.2f}%")
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
        print(_format_report(analyze_access_log(log_file, top_n=args.top)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
