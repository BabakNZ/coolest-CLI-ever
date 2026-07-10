from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from datetime import datetime, timedelta
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


def _parse_timestamp(timestamp: str) -> datetime | None:
    try:
        return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _format_endpoint_summary(top_endpoints: list[tuple[str, int]], max_items: int = 3) -> str:
    if not top_endpoints:
        return "none"

    return ", ".join(f"{endpoint} ({count})" for endpoint, count in top_endpoints[:max_items])


def _build_hourly_heatmap(hourly_requests: list[tuple[str, int]]) -> list[dict[str, object]]:
    max_hour_count = max((count for _, count in hourly_requests), default=0)
    heatmap: list[dict[str, object]] = []

    for hour, count in hourly_requests:
        intensity = (count / max_hour_count) if max_hour_count else 0.0
        heatmap.append(
            {
                "hour": hour,
                "count": count,
                "intensity": intensity,
                "label": f"{hour}: {count}",
            }
        )

    return heatmap


def _format_window_timestamp(timestamp: datetime | None) -> str:
    if timestamp is None:
        return "none"

    return timestamp.strftime("%d/%b/%Y %H:%M:%S %z")


def _build_peak_5xx_window(
    entries: list[dict[str, str]],
    window_minutes: int,
) -> dict[str, object]:
    five_xx_entries: list[dict[str, object]] = []
    for entry in entries:
        if not entry.get("status", "").startswith("5"):
            continue

        timestamp = _parse_timestamp(entry.get("timestamp", ""))
        if timestamp is None:
            continue

        five_xx_entries.append(
            {
                "timestamp": timestamp,
                "ip": entry.get("ip", ""),
                "endpoint": entry.get("endpoint", ""),
                "status": entry.get("status", ""),
            }
        )

    five_xx_entries.sort(key=lambda item: item["timestamp"])
    window = timedelta(minutes=window_minutes)
    left = 0
    best_left = 0
    best_right = 0

    for right, current in enumerate(five_xx_entries):
        while left <= right and current["timestamp"] - five_xx_entries[left]["timestamp"] >= window:
            left += 1

        current_size = right - left + 1
        best_size = best_right - best_left
        if current_size > best_size:
            best_left = left
            best_right = right + 1

    peak_window_entries = five_xx_entries[best_left:best_right]
    peak_window_start = peak_window_entries[0]["timestamp"] if peak_window_entries else None
    peak_window_end = peak_window_entries[-1]["timestamp"] if peak_window_entries else None
    peak_endpoints = Counter(entry["endpoint"] for entry in peak_window_entries if entry["endpoint"])
    peak_ips = Counter(entry["ip"] for entry in peak_window_entries if entry["ip"])

    return {
        "window_minutes": window_minutes,
        "count": len(peak_window_entries),
        "start": _format_window_timestamp(peak_window_start),
        "end": _format_window_timestamp(peak_window_end),
        "endpoint_breakdown": peak_endpoints.most_common(5),
        "ip_breakdown": peak_ips.most_common(5),
        "statuses": Counter(entry["status"] for entry in peak_window_entries),
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
    peak_window_minutes: int = 60,
) -> dict[str, object]:
    """Generate a basic report from parsed entries."""

    entries = list(entries)
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

    hourly_heatmap = _build_hourly_heatmap(hourly_requests)
    peak_5xx_window = _build_peak_5xx_window(entries, peak_window_minutes)

    return {
        "total_requests": total_requests,
        "unique_ips": len(unique_ips),
        "top_endpoints": endpoint_counter.most_common(top_n),
        "broken_lines": broken_lines,
        "percent_4xx": percent_4xx,
        "percent_5xx": percent_5xx,
        "hourly_requests": hourly_requests,
        "hourly_heatmap": hourly_heatmap,
        "busiest_hours": busiest_hours,
        "quietest_hours": quietest_hours,
        "peak_5xx_window": peak_5xx_window,
    }


def analyze_access_log(
    lines: Iterable[str],
    top_n: int = 10,
    peak_window_minutes: int = 60,
) -> dict[str, object]:
    entries: list[dict[str, str]] = []
    broken_lines = 0

    for line in lines:
        entry = _parse_access_log_line(line)
        if entry is None:
            if line.strip():
                broken_lines += 1
            continue
        entries.append(entry)

    return basic_report(entries, top_n=top_n, broken_lines=broken_lines, peak_window_minutes=peak_window_minutes)


def _format_report(report: dict[str, object]) -> str:
    peak_window = report["peak_5xx_window"]
    endpoint_breakdown = ", ".join(f"{endpoint} ({count})" for endpoint, count in peak_window["endpoint_breakdown"]) if peak_window["endpoint_breakdown"] else "none"
    ip_breakdown = ", ".join(f"{ip} ({count})" for ip, count in peak_window["ip_breakdown"]) if peak_window["ip_breakdown"] else "none"
    lines = [
        "Access Log Summary",
        "==================",
        f"Requests: {report['total_requests']}   Unique IPs: {report['unique_ips']}   Broken lines: {report['broken_lines']}",
        f"Top endpoints: {_format_endpoint_summary(report['top_endpoints'])}",
        f"Hourly peak: {report['busiest_hours'][0] if report['busiest_hours'] else 'none'}",
        f"Peak 5xx window ({peak_window['window_minutes']} min): {peak_window['start']} -> {peak_window['end']} ({peak_window['count']} responses)",
    ]
    lines.append(f"Busiest hour(s): {', '.join(report['busiest_hours']) if report['busiest_hours'] else 'none'}")
    lines.append(f"Quietest hour(s): {', '.join(report['quietest_hours']) if report['quietest_hours'] else 'none'}")
    lines.append(f"4xx responses: {report['percent_4xx']:.2f}%")
    lines.append(f"5xx responses: {report['percent_5xx']:.2f}%")
    lines.append(f"5xx window endpoints: {endpoint_breakdown}")
    lines.append(f"5xx window IPs: {ip_breakdown}")
    return "\n".join(lines)


def _write_json_report(report: dict[str, object], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)


def _format_percentage(value: float) -> str:
    return f"{value:.2f}%"


def _build_html_report(report: dict[str, object]) -> str:
    top_endpoints = report["top_endpoints"]
    hourly_heatmap = report["hourly_heatmap"]
    peak_window = report["peak_5xx_window"]
    busiest_hours = ", ".join(report["busiest_hours"]) if report["busiest_hours"] else "none"
    quietest_hours = ", ".join(report["quietest_hours"]) if report["quietest_hours"] else "none"
    peak_endpoints = ", ".join(f"{html.escape(endpoint)} ({count})" for endpoint, count in peak_window["endpoint_breakdown"]) if peak_window["endpoint_breakdown"] else "none"
    peak_ips = ", ".join(f"{html.escape(ip)} ({count})" for ip, count in peak_window["ip_breakdown"]) if peak_window["ip_breakdown"] else "none"

    heatmap_cells = []
    for item in hourly_heatmap:
        hour = html.escape(item["hour"])
        count = item["count"]
        intensity = item["intensity"]
        heatmap_cells.append(
            f"<div class='hour-cell' style='--intensity:{intensity:.4f}' title='{hour}: {count}'><span class='hour-label'>{hour}</span><strong>{count}</strong></div>"
        )

    top_endpoint_rows = []
    for endpoint, count in top_endpoints:
        top_endpoint_rows.append(
            f"<li><span class='endpoint'>{html.escape(endpoint)}</span><span class='count'>{count}</span></li>"
        )

    template = f"""<!doctype html>
<html lang='en'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Access Log Report</title>
    <style>
        :root {{
            color-scheme: light;
            --bg: #f5f7fb;
            --panel: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --accent: #2563eb;
            --accent-soft: #dbeafe;
            --border: #dbe3ee;
            --bar: linear-gradient(90deg, #2563eb, #60a5fa);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: Inter, Segoe UI, Arial, sans-serif;
            background: radial-gradient(circle at top, #eef4ff 0, var(--bg) 45%, #eef2f7 100%);
            color: var(--text);
            padding: 32px;
        }}
        .wrap {{ max-width: 1200px; margin: 0 auto; }}
        .hero {{
            background: linear-gradient(135deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 28px;
            box-shadow: 0 18px 50px rgba(15, 23, 42, 0.08);
            margin-bottom: 24px;
        }}
        .title {{ margin: 0; font-size: 2rem; letter-spacing: -0.03em; }}
        .subtitle {{ margin: 8px 0 0; color: var(--muted); }}
        .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 24px 0; }}
        .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 18px; padding: 18px; }}
        .stat-label {{ color: var(--muted); font-size: 0.875rem; }}
        .stat-value {{ font-size: 1.8rem; font-weight: 700; margin-top: 6px; }}
        .grid {{ display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 20px; }}
        .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 22px; padding: 22px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.05); }}
        .card h2 {{ margin: 0 0 16px; font-size: 1.15rem; }}
        .meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-bottom: 20px; }}
        .meta div {{ background: #f8fbff; border: 1px solid var(--border); border-radius: 16px; padding: 14px; }}
        .meta span {{ display: block; color: var(--muted); font-size: 0.82rem; margin-bottom: 4px; }}
        .meta strong {{ font-size: 1.05rem; }}
        .heatmap {{
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
        }}
        .hour-cell {{
            min-height: 90px;
            padding: 14px;
            border-radius: 18px;
            border: 1px solid rgba(37, 99, 235, 0.12);
            background: color-mix(in srgb, #ffffff 20%, #2563eb calc(var(--intensity) * 80%));
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-shadow: 0 10px 25px rgba(15, 23, 42, calc(0.03 + (var(--intensity) * 0.10)));
        }}
        .hour-label {{ color: var(--muted); font-size: 0.82rem; letter-spacing: 0.04em; text-transform: uppercase; }}
        .hour-cell strong {{ font-size: 1.4rem; color: var(--text); }}
        .endpoints {{ list-style: none; padding: 0; margin: 0; }}
        .endpoints li {{ display: flex; justify-content: space-between; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }}
        .endpoints li:last-child {{ border-bottom: 0; }}
        .endpoint {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .count {{ color: var(--accent); font-weight: 700; }}
        .peak-box {{ margin-top: 16px; padding: 16px; border-radius: 18px; background: linear-gradient(135deg, #eff6ff 0%, #ffffff 100%); border: 1px solid var(--border); }}
        .peak-box p {{ margin: 0 0 8px; color: var(--muted); }}
        .peak-box strong {{ display: block; margin-bottom: 10px; font-size: 1.05rem; }}
        @media (max-width: 900px) {{
            .stats, .grid, .meta {{ grid-template-columns: 1fr; }}
            body {{ padding: 18px; }}
        }}
    </style>
</head>
<body>
    <div class='wrap'>
        <section class='hero'>
            <h1 class='title'>Access Log Report</h1>
            <p class='subtitle'>A compact view of requests, unique clients, broken lines, and hourly activity.</p>
            <div class='stats'>
                <div class='stat'><div class='stat-label'>Requests</div><div class='stat-value'>{report['total_requests']}</div></div>
                <div class='stat'><div class='stat-label'>Unique IPs</div><div class='stat-value'>{report['unique_ips']}</div></div>
                <div class='stat'><div class='stat-label'>Broken lines</div><div class='stat-value'>{report['broken_lines']}</div></div>
                <div class='stat'><div class='stat-label'>Hourly peak</div><div class='stat-value'>{html.escape(report['busiest_hours'][0] if report['busiest_hours'] else 'none')}</div></div>
            </div>
            <div class='meta'>
                <div><span>4xx responses</span><strong>{_format_percentage(report['percent_4xx'])}</strong></div>
                <div><span>5xx responses</span><strong>{_format_percentage(report['percent_5xx'])}</strong></div>
                <div><span>Busiest hour(s)</span><strong>{html.escape(busiest_hours)}</strong></div>
            </div>
            <div class='meta' style='grid-template-columns: 1fr;'>
                <div><span>Quietest hour(s)</span><strong>{html.escape(quietest_hours)}</strong></div>
            </div>
            <div class='peak-box'>
                <p>Peak 5xx window ({peak_window['window_minutes']} minutes)</p>
                <strong>{html.escape(peak_window['start'])} to {html.escape(peak_window['end'])} - {peak_window['count']} responses</strong>
                <p><span>Top 5xx endpoints:</span> {html.escape(peak_endpoints)}</p>
                <p><span>Top 5xx IPs:</span> {html.escape(peak_ips)}</p>
            </div>
        </section>

        <section class='grid'>
            <div class='card'>
                <h2>Hourly Activity</h2>
                <div class='heatmap'>
                    {''.join(heatmap_cells)}
                </div>
            </div>
            <div class='card'>
                <h2>Top Endpoints</h2>
                <ul class='endpoints'>
                    {''.join(top_endpoint_rows) if top_endpoint_rows else '<li><span>No endpoints found</span><span class="count">0</span></li>'}
                </ul>
            </div>
        </section>
    </div>
</body>
</html>"""

    return template


def _write_html_report(report: dict[str, object], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as html_file:
        html_file.write(_build_html_report(report))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze access logs and print a basic report")
    parser.add_argument("logfile", type=Path, help="Path to access log file")
    parser.add_argument("--top", type=int, default=10, help="Number of top endpoints to show")
    parser.add_argument(
        "--peak-window-minutes",
        type=int,
        default=60,
        help="Window size in minutes used to find the peak 5xx interval",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Path to write the full report JSON file",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        help="Path to write a presentable HTML report",
    )
    args = parser.parse_args(argv)

    if args.top <= 0:
        parser.error("--top must be a positive integer")

    if args.peak_window_minutes <= 0:
        parser.error("--peak-window-minutes must be a positive integer")

    if not args.logfile.is_file():
        parser.error(f"Log file '{args.logfile}' does not exist or is not a file")

    json_output = args.json_output or args.logfile.with_name(f"{args.logfile.name}.json")
    html_output = args.html_output or args.logfile.with_name(f"{args.logfile.stem}.html")

    with args.logfile.open("r", encoding="utf-8") as log_file:
        report = analyze_access_log(log_file, top_n=args.top, peak_window_minutes=args.peak_window_minutes)

    _write_json_report(report, json_output)
    _write_html_report(report, html_output)
    print(_format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
