"""Nginx combined log format parser."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from logpulse.parsers.base import BaseParser, LogEntry

# Nginx combined log format:
# 192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /api/v1/users HTTP/1.1" 200 532 "-" "curl/7.68"
NGINX_PATTERN = re.compile(
    r'(?P<ip>[\d.:a-fA-F]+)\s+'       # client IP
    r'(?P<ident>\S+)\s+'               # ident
    r'(?P<user>\S+)\s+'                # remote user
    r'\[(?P<time>[^\]]+)\]\s+'         # timestamp
    r'"(?P<request>[^"]*)"\s+'         # request line
    r'(?P<status>\d{3})\s+'            # status code
    r'(?P<size>\S+)'                   # response size
    r'(?:\s+"(?P<referer>[^"]*)"\s+'   # referer (optional)
    r'"(?P<agent>[^"]*)")?'            # user agent (optional)
    r'(?:\s+(?P<response_time>[\d.]+))?'  # response time (optional)
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class NginxParser(BaseParser):
    """Parser for nginx combined log format."""

    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = NGINX_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        try:
            timestamp = datetime.strptime(groups["time"], TIME_FORMAT)
        except (ValueError, KeyError):
            timestamp = None

        # Parse request line
        request = groups.get("request", "")
        parts = request.split()
        method = parts[0] if len(parts) >= 1 else None
        path = parts[1] if len(parts) >= 2 else None

        status = int(groups["status"])

        response_time = None
        if groups.get("response_time"):
            try:
                response_time = float(groups["response_time"]) * 1000  # to ms
            except ValueError:
                pass

        # Determine level from status
        if status >= 500:
            level = "ERROR"
        elif status >= 400:
            level = "WARNING"
        else:
            level = "INFO"

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=request,
            source="nginx",
            raw=line,
            method=method,
            path=path,
            status_code=status,
            response_time_ms=response_time,
            ip_address=groups.get("ip"),
            extras={
                "size": groups.get("size", "0"),
                "referer": groups.get("referer", ""),
                "user_agent": groups.get("agent", ""),
            },
        )
