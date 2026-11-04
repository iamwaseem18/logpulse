"""JSON structured log parser."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from logpulse.parsers.base import BaseParser, LogEntry

# Common field name mappings across log frameworks
TIMESTAMP_FIELDS = ("timestamp", "time", "ts", "@timestamp", "datetime", "date", "created")
LEVEL_FIELDS = ("level", "severity", "log_level", "loglevel", "lvl")
MESSAGE_FIELDS = ("message", "msg", "text", "log", "body")
SOURCE_FIELDS = ("source", "logger", "module", "component", "service", "app")

LEVEL_MAP = {
    "debug": "DEBUG",
    "info": "INFO",
    "information": "INFO",
    "notice": "INFO",
    "warning": "WARNING",
    "warn": "WARNING",
    "error": "ERROR",
    "err": "ERROR",
    "critical": "CRITICAL",
    "fatal": "CRITICAL",
    "emergency": "CRITICAL",
    "alert": "CRITICAL",
}


def _find_field(data: dict, candidates: tuple) -> Optional[str]:
    """Find first matching field name (case-insensitive)."""
    lower_keys = {k.lower(): k for k in data}
    for candidate in candidates:
        if candidate.lower() in lower_keys:
            return str(data[lower_keys[candidate.lower()]])
    return None


class JsonLogParser(BaseParser):
    """Parser for JSON-structured log lines (one JSON object per line)."""

    def parse_line(self, line: str) -> Optional[LogEntry]:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract timestamp
        timestamp = None
        ts_raw = _find_field(data, TIMESTAMP_FIELDS)
        if ts_raw:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    timestamp = datetime.strptime(ts_raw, fmt)
                    break
                except ValueError:
                    continue
            if timestamp is None:
                # Try epoch seconds/milliseconds
                try:
                    epoch = float(ts_raw)
                    if epoch > 1e12:
                        epoch /= 1000
                    timestamp = datetime.fromtimestamp(epoch)
                except (ValueError, OSError):
                    pass

        # Extract level
        level_raw = _find_field(data, LEVEL_FIELDS) or "INFO"
        level = LEVEL_MAP.get(level_raw.lower(), "INFO")

        # Extract message
        message = _find_field(data, MESSAGE_FIELDS) or json.dumps(data)

        # Extract source
        source = _find_field(data, SOURCE_FIELDS) or "json"

        # HTTP fields
        status_code = None
        for key in ("status", "status_code", "http_status", "statusCode"):
            if key in data:
                try:
                    status_code = int(data[key])
                except (ValueError, TypeError):
                    pass
                break

        response_time = None
        for key in ("response_time", "duration", "elapsed", "latency", "duration_ms"):
            if key in data:
                try:
                    response_time = float(data[key])
                except (ValueError, TypeError):
                    pass
                break

        method = data.get("method") or data.get("http_method")
        path = data.get("path") or data.get("url") or data.get("uri")
        ip = data.get("ip") or data.get("remote_addr") or data.get("client_ip")

        # Store remaining fields as extras
        known_keys = set()
        for group in (TIMESTAMP_FIELDS, LEVEL_FIELDS, MESSAGE_FIELDS, SOURCE_FIELDS):
            known_keys.update(k.lower() for k in group)
        known_keys.update(("status", "status_code", "response_time", "duration", "method", "path", "ip"))
        extras = {k: v for k, v in data.items() if k.lower() not in known_keys}

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            source=source,
            raw=line,
            method=method,
            path=path,
            status_code=status_code,
            response_time_ms=response_time,
            ip_address=ip,
            extras=extras,
        )
