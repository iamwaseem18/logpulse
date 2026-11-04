"""Log analysis engine with statistical anomaly detection."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

from logpulse.parsers.base import LogEntry


@dataclass
class Anomaly:
    """Detected anomaly in log data."""

    category: str  # spike, slow_request, ip_flood, error_burst, unusual_status
    severity: str  # low, medium, high, critical
    description: str
    timestamp: Optional[datetime] = None
    count: int = 1
    details: dict = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    total_entries: int = 0
    error_count: int = 0
    warning_count: int = 0
    time_range: Optional[tuple] = None

    # Distributions
    status_distribution: dict = field(default_factory=dict)
    level_distribution: dict = field(default_factory=dict)
    top_paths: list = field(default_factory=list)
    top_ips: list = field(default_factory=list)
    top_errors: list = field(default_factory=list)

    # Anomalies
    anomalies: List[Anomaly] = field(default_factory=list)

    # Timeline buckets (for hourly distribution)
    hourly_counts: dict = field(default_factory=dict)

    # Performance
    avg_response_time: Optional[float] = None
    p95_response_time: Optional[float] = None
    p99_response_time: Optional[float] = None
    slow_requests: list = field(default_factory=list)


class LogAnalyzer:
    """Analyze log entries for patterns and anomalies."""

    def __init__(self, z_threshold: float = 2.5, slow_threshold_ms: float = 1000.0):
        self.z_threshold = z_threshold
        self.slow_threshold_ms = slow_threshold_ms

    def analyze(self, entries: List[LogEntry]) -> AnalysisResult:
        """Run full analysis on a list of log entries."""
        result = AnalysisResult()

        if not entries:
            return result

        result.total_entries = len(entries)

        # Collect metrics
        status_counter = Counter()
        level_counter = Counter()
        path_counter = Counter()
        ip_counter = Counter()
        error_messages = Counter()
        response_times = []
        timestamps = []
        hourly_buckets = defaultdict(int)

        for entry in entries:
            level_counter[entry.level] += 1

            if entry.is_error:
                result.error_count += 1
                error_messages[entry.message[:120]] += 1
            elif entry.is_warning:
                result.warning_count += 1

            if entry.status_code:
                status_counter[entry.status_code] += 1

            if entry.path:
                path_counter[entry.path] += 1

            if entry.ip_address:
                ip_counter[entry.ip_address] += 1

            if entry.response_time_ms is not None:
                response_times.append(entry.response_time_ms)

            if entry.timestamp:
                timestamps.append(entry.timestamp)
                hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
                hourly_buckets[hour_key] += 1

        # Distributions
        result.status_distribution = dict(status_counter.most_common(20))
        result.level_distribution = dict(level_counter.most_common())
        result.top_paths = path_counter.most_common(10)
        result.top_ips = ip_counter.most_common(10)
        result.top_errors = error_messages.most_common(10)
        result.hourly_counts = dict(sorted(hourly_buckets.items()))

        # Time range
        if timestamps:
            result.time_range = (min(timestamps), max(timestamps))

        # Response time stats
        if response_times:
            response_times.sort()
            result.avg_response_time = sum(response_times) / len(response_times)
            result.p95_response_time = response_times[int(len(response_times) * 0.95)]
            result.p99_response_time = response_times[int(len(response_times) * 0.99)]

        # Anomaly detection
        result.anomalies = self._detect_anomalies(entries, hourly_buckets, ip_counter, response_times)

        # Slow requests
        if response_times:
            result.slow_requests = [
                e for e in entries
                if e.response_time_ms is not None and e.response_time_ms > self.slow_threshold_ms
            ][:20]

        return result

    def _detect_anomalies(
        self,
        entries: List[LogEntry],
        hourly_buckets: dict,
        ip_counter: Counter,
        response_times: list,
    ) -> List[Anomaly]:
        """Detect anomalies using statistical methods."""
        anomalies = []

        # 1. Traffic spike detection (z-score on hourly buckets)
        if len(hourly_buckets) >= 3:
            values = list(hourly_buckets.values())
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance) if variance > 0 else 0

            if std > 0:
                for hour, count in hourly_buckets.items():
                    z_score = (count - mean) / std
                    if z_score > self.z_threshold:
                        severity = "critical" if z_score > 4 else "high" if z_score > 3 else "medium"
                        anomalies.append(Anomaly(
                            category="spike",
                            severity=severity,
                            description=f"Traffic spike at {hour}: {count} entries (z-score: {z_score:.1f}, mean: {mean:.0f})",
                            count=count,
                            details={"z_score": round(z_score, 2), "hour": hour},
                        ))

        # 2. Error burst detection (windowed error rate)
        error_entries = [e for e in entries if e.is_error and e.timestamp]
        if len(error_entries) >= 5:
            # Sliding 5-minute window
            window = timedelta(minutes=5)
            for i, entry in enumerate(error_entries):
                window_end = entry.timestamp + window
                window_count = sum(
                    1 for e in error_entries[i:]
                    if e.timestamp <= window_end
                )
                if window_count >= 10:
                    anomalies.append(Anomaly(
                        category="error_burst",
                        severity="high",
                        description=f"Error burst: {window_count} errors in 5 minutes starting at {entry.timestamp}",
                        timestamp=entry.timestamp,
                        count=window_count,
                    ))
                    break  # report first burst only

        # 3. IP flood detection (z-score on IP frequency)
        if len(ip_counter) >= 3:
            values = list(ip_counter.values())
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance) if variance > 0 else 0

            if std > 0:
                for ip, count in ip_counter.most_common(5):
                    z_score = (count - mean) / std
                    if z_score > self.z_threshold:
                        anomalies.append(Anomaly(
                            category="ip_flood",
                            severity="medium",
                            description=f"Unusual traffic from {ip}: {count} requests (z-score: {z_score:.1f})",
                            count=count,
                            details={"ip": ip, "z_score": round(z_score, 2)},
                        ))

        # 4. Unusual status codes
        status_entries = [e for e in entries if e.status_code]
        if status_entries:
            status_counter = Counter(e.status_code for e in status_entries)
            unusual = [
                (code, cnt)
                for code, cnt in status_counter.items()
                if code not in (200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500)
            ]
            for code, cnt in unusual:
                if cnt >= 3:
                    anomalies.append(Anomaly(
                        category="unusual_status",
                        severity="low",
                        description=f"Unusual HTTP status {code}: {cnt} occurrences",
                        count=cnt,
                        details={"status_code": code},
                    ))

        # 5. Slow request anomalies
        if len(response_times) >= 10:
            sorted_times = sorted(response_times)
            p99 = sorted_times[int(len(sorted_times) * 0.99)]
            extreme_slow = [t for t in response_times if t > p99 * 3]
            if extreme_slow:
                anomalies.append(Anomaly(
                    category="slow_request",
                    severity="high",
                    description=f"{len(extreme_slow)} requests 3x slower than p99 ({p99:.0f}ms)",
                    count=len(extreme_slow),
                    details={"p99_ms": round(p99, 1), "max_ms": round(max(extreme_slow), 1)},
                ))

        return sorted(
            anomalies,
            key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.severity, 4),
        )
