"""Base parser and log entry data model."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEntry:
    """Normalized log entry across all formats."""

    timestamp: Optional[datetime] = None
    level: str = "INFO"
    message: str = ""
    source: str = ""
    raw: str = ""
    # HTTP-specific fields
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    ip_address: Optional[str] = None
    # Extra metadata
    extras: dict = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        upper = self.level.upper()
        if upper in ("ERROR", "CRITICAL", "FATAL", "EMERGENCY", "ALERT"):
            return True
        if self.status_code and self.status_code >= 500:
            return True
        return False

    @property
    def is_warning(self) -> bool:
        if self.level.upper() in ("WARNING", "WARN"):
            return True
        if self.status_code and 400 <= self.status_code < 500:
            return True
        return False


class BaseParser(abc.ABC):
    """Abstract base parser for log formats."""

    @abc.abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line into a LogEntry, or None if unparseable."""
        ...

    def parse_file(self, filepath: str):
        """Yield LogEntry objects from a file."""
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                entry = self.parse_line(line)
                if entry:
                    yield entry
