# coolest-CLI-ever

A clean starter CLI for parsing access logs and printing a basic usage report.

## Features

- Parse access logs (common log format)
- Generate a basic report:
  - total requests
  - number of unique IPs
  - broken lines
  - top N most-trafficked endpoints (default: 10)
  - percentage of 4xx responses
  - percentage of 5xx responses

## Usage

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log
```

Optional:

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --top 5
```
