"""Tests for the log analyzer."""

from datetime import datetime, timedelta

from logpulse.analyzer import LogAnalyzer
from logpulse.parsers.base import LogEntry


def _make_entries(n, level="INFO", status=200, base_time=None):
    """Helper to create test log entries."""
    base = base_time or datetime(2024, 10, 11, 12, 0, 0)
    return [
        LogEntry(
            timestamp=base + timedelta(seconds=i),
            level=level,
            message=f"test message {i}",
            status_code=status,
            path="/api/test",
            ip_address=f"10.0.0.{i % 5}",
        )
        for i in range(n)
    ]


class TestLogAnalyzer:
    def setup_method(self):
        self.analyzer = LogAnalyzer()

    def test_empty_entries(self):
        result = self.analyzer.analyze([])
        assert result.total_entries == 0
        assert result.error_count == 0

    def test_basic_counts(self):
        entries = _make_entries(50) + _make_entries(10, level="ERROR", status=500)
        result = self.analyzer.analyze(entries)
        assert result.total_entries == 60
        assert result.error_count == 10

    def test_status_distribution(self):
        entries = _make_entries(30, status=200) + _make_entries(5, status=404) + _make_entries(3, status=500)
        result = self.analyzer.analyze(entries)
        assert 200 in result.status_distribution
        assert 404 in result.status_distribution
        assert 500 in result.status_distribution

    def test_response_time_stats(self):
        entries = []
        for i in range(100):
            e = LogEntry(
                timestamp=datetime(2024, 10, 11, 12, i // 60, i % 60),
                level="INFO",
                message="req",
                response_time_ms=float(50 + i),
            )
            entries.append(e)
        result = self.analyzer.analyze(entries)
        assert result.avg_response_time is not None
        assert result.p95_response_time is not None
        assert result.p99_response_time is not None
        assert result.avg_response_time > 0

    def test_spike_detection(self):
        """Create a traffic spike and verify detection."""
        entries = []
        base = datetime(2024, 10, 11, 0, 0, 0)
        # Normal hours: 10 entries each
        for hour in range(23):
            for i in range(10):
                entries.append(LogEntry(
                    timestamp=base + timedelta(hours=hour, seconds=i),
                    level="INFO",
                    message="normal",
                ))
        # Spike hour: 200 entries
        for i in range(200):
            entries.append(LogEntry(
                timestamp=base + timedelta(hours=23, seconds=i),
                level="INFO",
                message="spike",
            ))

        result = self.analyzer.analyze(entries)
        spike_anomalies = [a for a in result.anomalies if a.category == "spike"]
        assert len(spike_anomalies) > 0

    def test_ip_flood_detection(self):
        """One IP with far more requests than others."""
        entries = []
        base = datetime(2024, 10, 11, 12, 0, 0)
        # Normal IPs: 5 requests each
        for ip_idx in range(20):
            for i in range(5):
                entries.append(LogEntry(
                    timestamp=base + timedelta(seconds=ip_idx * 10 + i),
                    level="INFO",
                    message="req",
                    ip_address=f"10.0.0.{ip_idx}",
                ))
        # Flood IP: 200 requests
        for i in range(200):
            entries.append(LogEntry(
                timestamp=base + timedelta(seconds=i),
                level="INFO",
                message="flood",
                ip_address="1.2.3.4",
            ))

        result = self.analyzer.analyze(entries)
        flood_anomalies = [a for a in result.anomalies if a.category == "ip_flood"]
        assert len(flood_anomalies) > 0
        assert any("1.2.3.4" in a.description for a in flood_anomalies)
