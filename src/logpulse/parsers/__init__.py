"""Log format parsers."""

from logpulse.parsers.base import LogEntry, BaseParser
from logpulse.parsers.nginx import NginxParser
from logpulse.parsers.syslog import SyslogParser
from logpulse.parsers.json_log import JsonLogParser

PARSERS = {
    "nginx": NginxParser,
    "syslog": SyslogParser,
    "json": JsonLogParser,
}


def detect_format(line: str) -> str:
    """Auto-detect log format from a sample line."""
    stripped = line.strip()
    if stripped.startswith("{"):
        return "json"
    # Nginx combined: IP - - [timestamp] "METHOD path HTTP/x.x" status size ...
    if '" ' in stripped and stripped.count(" ") > 6:
        import re
        if re.match(r'[\d.:]+\s+-\s', stripped):
            return "nginx"
    return "syslog"


__all__ = ["LogEntry", "BaseParser", "NginxParser", "SyslogParser", "JsonLogParser", "PARSERS", "detect_format"]
