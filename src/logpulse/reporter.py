"""Rich terminal output for analysis results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from logpulse.analyzer import AnalysisResult


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

LEVEL_COLORS = {
    "CRITICAL": "bold red",
    "ERROR": "red",
    "WARNING": "yellow",
    "INFO": "green",
    "DEBUG": "dim",
}


def print_summary(result: AnalysisResult, console: Console | None = None, top_n: int = 10) -> None:
    """Print a formatted analysis summary to the terminal."""
    console = console or Console()

    # Header
    console.print()
    console.print(Panel.fit(
        "[bold]LogPulse Analysis Report[/bold]",
        border_style="blue",
    ))

    # Overview
    overview = Table(show_header=False, box=None, padding=(0, 2))
    overview.add_column("label", style="bold")
    overview.add_column("value")
    overview.add_row("Total entries", f"{result.total_entries:,}")
    overview.add_row("Errors", f"[red]{result.error_count:,}[/red]")
    overview.add_row("Warnings", f"[yellow]{result.warning_count:,}[/yellow]")
    if result.time_range:
        start, end = result.time_range
        overview.add_row("Time range", f"{start} - {end}")
    if result.avg_response_time is not None:
        overview.add_row("Avg response", f"{result.avg_response_time:.1f} ms")
        overview.add_row("P95 response", f"{result.p95_response_time:.1f} ms")
        overview.add_row("P99 response", f"{result.p99_response_time:.1f} ms")
    console.print(overview)
    console.print()

    # Anomalies
    if result.anomalies:
        console.print("[bold]Anomalies Detected[/bold]", style="red")
        anomaly_table = Table(show_lines=True)
        anomaly_table.add_column("Severity", width=10)
        anomaly_table.add_column("Category", width=16)
        anomaly_table.add_column("Description")

        for anomaly in result.anomalies:
            color = SEVERITY_COLORS.get(anomaly.severity, "white")
            anomaly_table.add_row(
                Text(anomaly.severity.upper(), style=color),
                anomaly.category,
                anomaly.description,
            )
        console.print(anomaly_table)
        console.print()

    # Level distribution
    if result.level_distribution:
        level_table = Table(title="Log Level Distribution")
        level_table.add_column("Level", width=12)
        level_table.add_column("Count", justify="right")
        level_table.add_column("Percentage", justify="right")

        for level, count in sorted(
            result.level_distribution.items(),
            key=lambda x: {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3, "DEBUG": 4}.get(x[0], 5),
        ):
            pct = (count / result.total_entries * 100) if result.total_entries else 0
            color = LEVEL_COLORS.get(level, "white")
            level_table.add_row(
                Text(level, style=color),
                f"{count:,}",
                f"{pct:.1f}%",
            )
        console.print(level_table)
        console.print()

    # Status code distribution
    if result.status_distribution:
        status_table = Table(title="HTTP Status Codes")
        status_table.add_column("Status", width=8)
        status_table.add_column("Count", justify="right")
        status_table.add_column("Bar")

        max_count = max(result.status_distribution.values())
        for status, count in sorted(result.status_distribution.items()):
            bar_len = int(count / max_count * 30) if max_count else 0
            color = "red" if status >= 500 else "yellow" if status >= 400 else "green"
            bar = Text("=" * bar_len, style=color)
            status_table.add_row(str(status), f"{count:,}", bar)
        console.print(status_table)
        console.print()

    # Top paths
    if result.top_paths:
        path_table = Table(title=f"Top {min(top_n, len(result.top_paths))} Request Paths")
        path_table.add_column("Path")
        path_table.add_column("Count", justify="right")
        for path, count in result.top_paths[:top_n]:
            path_table.add_row(path, f"{count:,}")
        console.print(path_table)
        console.print()

    # Top IPs
    if result.top_ips:
        ip_table = Table(title=f"Top {min(top_n, len(result.top_ips))} IP Addresses")
        ip_table.add_column("IP Address")
        ip_table.add_column("Requests", justify="right")
        for ip, count in result.top_ips[:top_n]:
            ip_table.add_row(ip, f"{count:,}")
        console.print(ip_table)
        console.print()

    # Top errors
    if result.top_errors:
        error_table = Table(title=f"Top {min(top_n, len(result.top_errors))} Error Messages")
        error_table.add_column("Message", max_width=80)
        error_table.add_column("Count", justify="right")
        for msg, count in result.top_errors[:top_n]:
            error_table.add_row(msg, f"{count:,}")
        console.print(error_table)
        console.print()

    # Hourly timeline
    if result.hourly_counts:
        timeline_table = Table(title="Hourly Distribution")
        timeline_table.add_column("Hour")
        timeline_table.add_column("Count", justify="right")
        timeline_table.add_column("Activity")

        max_hourly = max(result.hourly_counts.values())
        for hour, count in list(result.hourly_counts.items())[-24:]:
            bar_len = int(count / max_hourly * 40) if max_hourly else 0
            bar = Text("=" * bar_len, style="blue")
            timeline_table.add_row(hour, f"{count:,}", bar)
        console.print(timeline_table)
        console.print()

    # Slow requests
    if result.slow_requests:
        slow_table = Table(title=f"Slow Requests (>{1000}ms)")
        slow_table.add_column("Time")
        slow_table.add_column("Path", max_width=40)
        slow_table.add_column("Duration (ms)", justify="right")
        slow_table.add_column("Status", justify="right")
        for entry in result.slow_requests[:10]:
            ts = str(entry.timestamp)[:19] if entry.timestamp else "-"
            slow_table.add_row(
                ts,
                entry.path or "-",
                f"{entry.response_time_ms:.0f}" if entry.response_time_ms else "-",
                str(entry.status_code or "-"),
            )
        console.print(slow_table)
        console.print()
