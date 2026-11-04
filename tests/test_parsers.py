"""Tests for log parsers."""

from logpulse.parsers.nginx import NginxParser
from logpulse.parsers.syslog import SyslogParser
from logpulse.parsers.json_log import JsonLogParser
from logpulse.parsers import detect_format


class TestNginxParser:
    def setup_method(self):
        self.parser = NginxParser()

    def test_parse_combined_format(self):
        line = '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 532 "-" "curl/7.68"'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.ip_address == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/api/users"
        assert entry.status_code == 200
        assert entry.level == "INFO"

    def test_parse_error_status(self):
        line = '10.0.0.1 - - [10/Oct/2024:14:00:00 +0000] "POST /api/submit HTTP/1.1" 500 0 "-" "python/3.9"'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.status_code == 500
        assert entry.level == "ERROR"
        assert entry.is_error

    def test_parse_404(self):
        line = '10.0.0.2 - - [10/Oct/2024:14:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.status_code == 404
        assert entry.level == "WARNING"
        assert entry.is_warning

    def test_invalid_line(self):
        entry = self.parser.parse_line("this is not a valid nginx log line")
        assert entry is None


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()

    def test_parse_generic_format(self):
        line = "2024-10-11 14:30:00 ERROR [myapp] Connection refused to database"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == "ERROR"
        assert "Connection refused" in entry.message
        assert entry.is_error

    def test_parse_warning(self):
        line = "2024-10-11 14:30:00 WARNING [cache] Cache miss rate above threshold"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == "WARNING"

    def test_parse_bsd_format(self):
        line = "Oct 11 22:14:15 myhost sshd[12345]: Failed password for root"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.source == "sshd"
        assert "Failed password" in entry.message

    def test_fallback_unparseable(self):
        line = "some random log text without timestamps"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == "INFO"


class TestJsonLogParser:
    def setup_method(self):
        self.parser = JsonLogParser()

    def test_parse_standard_json(self):
        line = '{"timestamp": "2024-10-11T14:30:00Z", "level": "error", "message": "disk full", "service": "api"}'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.level == "ERROR"
        assert entry.message == "disk full"
        assert entry.is_error

    def test_parse_with_http_fields(self):
        line = '{"time": "2024-10-11T14:30:00Z", "level": "info", "msg": "request", "status": 200, "method": "GET", "path": "/health"}'
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.status_code == 200
        assert entry.method == "GET"
        assert entry.path == "/health"

    def test_non_json_returns_none(self):
        entry = self.parser.parse_line("not json at all")
        assert entry is None

    def test_non_dict_returns_none(self):
        entry = self.parser.parse_line("[1, 2, 3]")
        assert entry is None


class TestFormatDetection:
    def test_detect_json(self):
        assert detect_format('{"level": "info", "msg": "hello"}') == "json"

    def test_detect_nginx(self):
        line = '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET / HTTP/1.1" 200 532'
        assert detect_format(line) == "nginx"

    def test_detect_syslog_fallback(self):
        assert detect_format("2024-10-11 14:30:00 ERROR something happened") == "syslog"
