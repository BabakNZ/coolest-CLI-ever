# coolest-CLI-ever

A clean starter CLI for parsing access logs and printing a basic usage report.

## Features

- Parse access logs (common log format)
- Generate a report:
  - total requests
  - number of unique IPs
  - broken lines
  - top N most-trafficked endpoints (default: 10)
  - percentage of 4xx responses
  - percentage of 5xx responses
  - 5xx peak analysis (uses sliding window to calculate and the time windows are configurable)
- Print a short summary to the terminal
- Write the full report to a JSON file next to the log by default
- Write a presentable HTML report next to the log by default

## Usage

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log
```

Optional:

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --top 5
```

Write the JSON report to a specific path:

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --json-output /path/to/report.json
```

Write the HTML report to a specific path:

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --html-output /path/to/report.html
```

Configure the 5xx peak time window

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --peak-window-minutes 60
```
