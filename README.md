# coolest-CLI-ever

[![Status](https://img.shields.io/badge/status-active-success)](https://github.com/BabakNZ/coolest-CLI-ever)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

A clean, production-ready CLI tool for parsing access logs and generating comprehensive usage reports. This utility provides actionable insights from web server logs with both terminal and formatted report outputs.

---

## ✨ Features

- **Log Parsing**: Parse access logs in the common log format (Apache/Nginx)
- **Comprehensive Analysis**:
  - Total requests and unique IP tracking
  - Detection of malformed log entries
  - Top N most-trafficked endpoints (customizable, default: 10)
  - 4xx and 5xx response rate analysis
  - Advanced 5xx peak detection using sliding window algorithm with configurable time windows
  - Hourly traffic distribution and heatmap
  - Busiest and quietest hours identification
- **Multiple Output Formats**:
  - Terminal summary with key metrics
  - JSON report for programmatic consumption
  - Interactive HTML report with visual heatmaps

---

## 🚀 Quick Start

### Basic Usage

```bash
python accesslog_cli.py /path/to/access.log
```

### Optional Arguments

View top 5 endpoints instead of default 10:

```bash
python accesslog_cli.py /path/to/access.log --top 5
```

Specify custom JSON report output location:

```bash
python accesslog_cli.py /path/to/access.log --json-output /path/to/report.json
```

Specify custom HTML report output location:

```bash
python accesslog_cli.py /path/to/access.log --html-output /path/to/report.html
```

Configure the 5xx peak detection time window (in minutes):

```bash
python accesslog_cli.py /path/to/access.log --peak-window-minutes 60
```

---

## 🗂️ Libraries Used

This project utilizes Python's standard library exclusively for maximum portability and zero external dependencies:

| Library | Purpose |
|---------|---------|
| **argparse** | CLI argument parsing with automatic help documentation and type validation |
| **json** | Report serialization for data portability and tool integration |
| **pathlib** | Cross-platform file path handling and I/O operations |
| **collections.Counter** | Frequency analysis for endpoints, IPs, status codes, and traffic patterns |
| **datetime** | Timestamp parsing and time-based analysis for peak detection |
| **html** | Safe HTML escaping to prevent injection vulnerabilities |
| **typing** | Type hints for better code clarity and IDE support |

---

## ✏️ Design Highlights

- **No External Dependencies**: Uses only Python standard library for reliability and ease of deployment
- **Efficient Algorithms**: Sliding window technique for O(n) 5xx peak detection without nested loops
- **Robust Parsing**: Graceful handling of malformed log entries with detailed error tracking
- **Security Conscious**: HTML escaping for safe report generation from untrusted input
- **Type Hints**: Full type annotations for better code maintainability and IDE support
