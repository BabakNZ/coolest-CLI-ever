# coolest-CLI-ever

A clean starter CLI for parsing access logs and printing a basic usage report.

## Features

- Parse access logs (common log format)
- Generate a basic report:
  - total requests
  - number of unique IPs
  - top N most-used endpoints (default: 10)

## Usage

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log
```

Optional:

```bash
python /home/runner/work/coolest-CLI-ever/coolest-CLI-ever/accesslog_cli.py /path/to/access.log --top 5
```
