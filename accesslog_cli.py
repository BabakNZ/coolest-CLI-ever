from __future__ import annotations

import argparse
import json
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


def _extract_hour(timestamp: str) -> str | None:
    if ":" not in timestamp:
        return None

    parts = timestamp.split(":", 2)
    if len(parts) < 2:
        return None

    hour = parts[1]
    if len(hour) != 2 or not hour.isdigit():
        return None

    return hour


def _format_endpoint_summary(top_endpoints: list[tuple[str, int]], max_items: int = 3) -> str:
    if not top_endpoints:
        return "none"

    return ", ".join(f"{endpoint} ({count})" for endpoint, count in top_endpoints[:max_items])


def _build_hourly_histogram(hourly_requests: list[tuple[str, int]]) -> list[dict[str, object]]:
    max_hour_count = max((count for _, count in hourly_requests), default=0)
    histogram: list[dict[str, object]] = []

    for hour, count in hourly_requests:
        percentage_of_peak = (count / max_hour_count * 100) if max_hour_count else 0.0
        if count > 0 and max_hour_count > 0:
            bar_length = max(1, round((count / max_hour_count) * 20))
            bar = "#" * bar_length
        else:
            bar_length = 0
            bar = ""

        histogram.append(
            {
                "hour": hour,
                "count": count,
                "bar_length": bar_length,
                "bar": bar,
                "percentage_of_peak": percentage_of_peak,
            }
        )

    return histogram

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
    hourly_counter: Counter[str] = Counter()
    status_4xx = 0
    status_5xx = 0
    for entry in entries:
        total_requests += 1
        unique_ips.add(entry["ip"])
        if entry["endpoint"]:
            endpoint_counter[entry["endpoint"]] += 1
        hour = _extract_hour(entry.get("timestamp", ""))
        if hour is not None:
            hourly_counter[hour] += 1
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

    hourly_requests = [(f"{hour:02d}", hourly_counter.get(f"{hour:02d}", 0)) for hour in range(24)]
    non_zero_hours = [(hour, count) for hour, count in hourly_requests if count > 0]
    if non_zero_hours:
        max_hour_count = max(count for _, count in non_zero_hours)
        min_hour_count = min(count for _, count in non_zero_hours)
        busiest_hours = [hour for hour, count in non_zero_hours if count == max_hour_count]
        quietest_hours = [hour for hour, count in non_zero_hours if count == min_hour_count]
    else:
        busiest_hours = []
        quietest_hours = []

    hourly_histogram = _build_hourly_histogram(hourly_requests)

    return {
        "total_requests": total_requests,
        "unique_ips": len(unique_ips),
        "top_endpoints": endpoint_counter.most_common(top_n),
        "broken_lines": broken_lines,
        "percent_4xx": percent_4xx,
        "percent_5xx": percent_5xx,
        "hourly_requests": hourly_requests,
        "hourly_histogram": hourly_histogram,
        "busiest_hours": busiest_hours,
        "quietest_hours": quietest_hours,
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
        "Access Log Summary",
        "==================",
        f"Requests: {report['total_requests']}   Unique IPs: {report['unique_ips']}   Broken lines: {report['broken_lines']}",
        f"Top endpoints: {_format_endpoint_summary(report['top_endpoints'])}",
        f"Hourly peak: {report['busiest_hours'][0] if report['busiest_hours'] else 'none'}",
    ]
    lines.append(f"Busiest hour(s): {', '.join(report['busiest_hours']) if report['busiest_hours'] else 'none'}")
    lines.append(f"Quietest hour(s): {', '.join(report['quietest_hours']) if report['quietest_hours'] else 'none'}")
    lines.append(f"4xx responses: {report['percent_4xx']:.2f}%")
    lines.append(f"5xx responses: {report['percent_5xx']:.2f}%")
    return "\n".join(lines)


def _write_json_report(report: dict[str, object], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze access logs and print a basic report")
    parser.add_argument("logfile", type=Path, help="Path to access log file")
    parser.add_argument("--top", type=int, default=10, help="Number of top endpoints to show")
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Path to write the full report JSON file",
    )
    args = parser.parse_args(argv)

    if args.top <= 0:
        parser.error("--top must be a positive integer")

    if not args.logfile.is_file():
        parser.error(f"Log file '{args.logfile}' does not exist or is not a file")

    json_output = args.json_output or args.logfile.with_name(f"{args.logfile.name}.json")

    with args.logfile.open("r", encoding="utf-8") as log_file:
        report = analyze_access_log(log_file, top_n=args.top)

    _write_json_report(report, json_output)
    print(_format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
