# LogPulse

[![CI](https://github.com/iamwaseem18/logpulse/actions/workflows/ci.yml/badge.svg)](https://github.com/iamwaseem18/logpulse/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Intelligent log analysis and anomaly detection CLI. Parse logs from multiple formats, detect traffic spikes, error bursts, IP floods, and slow requests using statistical methods - all from your terminal.

## Features

- **Multi-format parsing** - nginx combined, syslog/RFC 3164, JSON structured logs
- **Auto-detection** - automatically identifies log format from content
- **Statistical anomaly detection** - z-score based spike detection, error burst analysis
- **IP flood detection** - identifies unusual traffic patterns from specific sources
- **Performance analysis** - response time percentiles (p95/p99), slow request tracking
- **Rich terminal output** - color-coded tables, severity indicators, visual bars
- **Live tail mode** - real-time monitoring with anomaly alerts

## Architecture

```
logpulse/
  cli.py            Click-based CLI with analyze, summary, watch commands
  parsers/
    base.py          Abstract parser + LogEntry data model
    nginx.py         Nginx combined log format parser
    syslog.py        Syslog (BSD + generic timestamp) parser
    json_log.py      JSON structured log parser (auto-maps common field names)
  analyzer.py        Statistical analysis engine (z-score, frequency, windowed error rate)
  reporter.py        Rich terminal reporter (tables, bars, color-coded severity)
```

## Installation

```bash
# From source
git clone https://github.com/iamwaseem18/logpulse.git
cd logpulse
pip install -e .

# With dev dependencies
pip install -e ".[dev]"
```

## Usage

### Analyze a log file

```bash
# Auto-detect format and analyze
logpulse analyze access.log

# Specify format explicitly
logpulse analyze --format nginx /var/log/nginx/access.log
logpulse analyze --format json app-logs.jsonl
logpulse analyze --format syslog /var/log/syslog

# Custom thresholds
logpulse analyze access.log --z-threshold 3.0 --slow 500
```

### Quick summary

```bash
# Top error patterns
logpulse summary access.log --top 20
```

### Live monitoring

```bash
# Tail with real-time anomaly detection
logpulse watch /var/log/nginx/access.log --interval 3
```

### Sample output

```
+-----------------------+
| LogPulse Analysis     |
+-----------------------+

Total entries    42,891
Errors              847
Warnings          1,203
Time range       2024-10-11 00:00:01 - 2024-10-11 23:59:58
Avg response     127.3 ms
P95 response     892.1 ms
P99 response   2,341.0 ms

Anomalies Detected
+----------+----------------+---------------------------------------------+
| Severity | Category       | Description                                 |
+----------+----------------+---------------------------------------------+
| CRITICAL | spike          | Traffic spike at 14:00: 4,291 entries       |
|          |                | (z-score: 4.7, mean: 1,787)                |
| HIGH     | error_burst    | Error burst: 47 errors in 5 minutes         |
| HIGH     | slow_request   | 12 requests 3x slower than p99 (2,341ms)   |
| MEDIUM   | ip_flood       | Unusual traffic from 10.0.3.15: 892 reqs   |
+----------+----------------+---------------------------------------------+

HTTP Status Codes
+--------+-------+--------------------------------+
| Status | Count | Bar                            |
+--------+-------+--------------------------------+
| 200    | 38102 | ============================== |
| 301    |  1203 | ==                             |
| 404    |   847 | =                              |
| 500    |   412 | =                              |
| 502    |    89 |                                |
| 503    |    38 |                                |
+--------+-------+--------------------------------+
```

## Supported Log Formats

| Format | Example |
|--------|---------|
| **Nginx** | `192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /api HTTP/1.1" 200 532` |
| **Syslog** | `Oct 11 22:14:15 myhost sshd[1234]: Failed password for root` |
| **Generic** | `2024-10-11 14:30:00 ERROR [myapp] Connection refused` |
| **JSON** | `{"timestamp": "2024-10-11T14:30:00Z", "level": "error", "msg": "disk full"}` |

## Anomaly Detection Methods

- **Traffic spikes**: Z-score analysis on hourly request counts (configurable threshold)
- **Error bursts**: Sliding 5-minute window detecting concentrated error clusters
- **IP floods**: Z-score analysis on per-IP request frequency
- **Unusual status codes**: Flags uncommon HTTP status codes with significant occurrence
- **Slow requests**: Identifies requests exceeding 3x the p99 response time

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run with coverage
pytest --cov=logpulse --cov-report=term-missing
```

## License

MIT License - see [LICENSE](LICENSE) for details.
