"""Syslog / generic log format parser."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from logpulse.parsers.base import BaseParser, LogEntry

# Patterns for common syslog-like formats
# RFC 3164: Oct 11 22:14:15 mymachine su: 'su root' failed
# Generic: 2024-10-11 22:14:15 ERROR [module] message
SYSLOG_BSD = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)'
)

GENERIC_TIMESTAMP = re.compile(
    r'(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+'
    r'(?:(?P<level>DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|FATAL|EMERGENCY|ALERT)\s+)?'
    r'(?:\[(?P<source>[^\]]+)\]\s+)?'
    r'(?P<message>.*)'
)

LEVEL_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARNING": "WARNING",
    "WARN": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
}


class SyslogParser(BaseParser):
    """Parser for syslog and generic timestamped log formats."""

    def parse_line(self, line: str) -> Optional[LogEntry]:
        # Try generic timestamp format first (more common in app logs)
        match = GENERIC_TIMESTAMP.match(line)
        if match:
            return self._parse_generic(match, line)

        # Try BSD syslog format
        match = SYSLOG_BSD.match(line)
        if match:
            return self._parse_bsd(match, line)

        # Fallback: just capture as INFO message
        return LogEntry(
            level="INFO",
            message=line,
            source="unknown",
            raw=line,
        )

    def _parse_generic(self, match: re.Match, line: str) -> LogEntry:
        groups = match.groupdict()
        ts_str = groups["timestamp"]
        timestamp = None

        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                timestamp = datetime.strptime(ts_str.replace(",", ".").split(".")[0], fmt.split(".")[0])
                break
            except ValueError:
                continue

        level = LEVEL_MAP.get(groups.get("level", "").upper(), "INFO")

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=groups.get("message", ""),
            source=groups.get("source", "app"),
            raw=line,
        )

    def _parse_bsd(self, match: re.Match, line: str) -> LogEntry:
        groups = match.groupdict()

        # Parse timestamp (no year in BSD syslog)
        try:
            ts_str = f"{groups['month']} {int(groups['day']):2d} {groups['time']}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
        except (ValueError, KeyError):
            timestamp = None

        # Infer level from message content
        message = groups.get("message", "")
        level = "INFO"
        msg_lower = message.lower()
        if any(w in msg_lower for w in ("error", "fail", "fatal", "critical")):
            level = "ERROR"
        elif any(w in msg_lower for w in ("warn", "warning")):
            level = "WARNING"

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            source=groups.get("program", "syslog"),
            raw=line,
            extras={"host": groups.get("host", ""), "pid": groups.get("pid", "")},
        )
