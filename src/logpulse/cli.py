"""LogPulse CLI - intelligent log analysis from the command line."""

from __future__ import annotations

import sys
import time

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from logpulse import __version__
from logpulse.analyzer import LogAnalyzer
from logpulse.parsers import PARSERS, detect_format
from logpulse.reporter import print_summary

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="logpulse")
def cli():
    """LogPulse - Intelligent log analysis and anomaly detection.

    Analyze log files, detect anomalies, and generate incident summaries
    with statistical pattern detection and rich terminal output.
    """
    pass


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["nginx", "syslog", "json", "auto"]),
    default="auto",
    help="Log format (default: auto-detect)",
)
@click.option("--top", "-n", default=10, help="Number of top items to display")
@click.option(
    "--z-threshold", default=2.5, type=float,
    help="Z-score threshold for anomaly detection (default: 2.5)",
)
@click.option(
    "--slow", default=1000.0, type=float,
    help="Slow request threshold in ms (default: 1000)",
)
def analyze(logfile: str, fmt: str, top: int, z_threshold: float, slow: float):
    """Analyze a log file for patterns and anomalies.

    Parses the log file, detects error patterns, traffic spikes,
    IP-based anomalies, and slow requests using statistical methods.
    """
    # Auto-detect or get parser
    if fmt == "auto":
        with open(logfile, "r", errors="replace") as f:
            sample = ""
            for line in f:
                line = line.strip()
                if line:
                    sample = line
                    break
        if not sample:
            console.print("[red]Error: Log file is empty[/red]")
            sys.exit(1)
        fmt = detect_format(sample)
        console.print(f"[dim]Auto-detected format: {fmt}[/dim]")

    parser = PARSERS[fmt]()

    # Parse entries
    with console.status("[bold blue]Parsing log file..."):
        entries = list(parser.parse_file(logfile))

    if not entries:
        console.print("[yellow]Warning: No parseable entries found[/yellow]")
        sys.exit(0)

    console.print(f"[green]Parsed {len(entries):,} entries[/green]")

    # Analyze
    with console.status("[bold blue]Analyzing patterns..."):
        analyzer = LogAnalyzer(z_threshold=z_threshold, slow_threshold_ms=slow)
        result = analyzer.analyze(entries)

    # Report
    print_summary(result, console=console, top_n=top)


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--top", "-n", default=10, help="Number of top items to display")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["nginx", "syslog", "json", "auto"]),
    default="auto",
    help="Log format (default: auto-detect)",
)
def summary(logfile: str, top: int, fmt: str):
    """Show a concise summary of error patterns.

    Quick overview of the most frequent errors and their counts.
    """
    if fmt == "auto":
        with open(logfile, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    fmt = detect_format(line)
                    break

    parser = PARSERS[fmt]()
    entries = list(parser.parse_file(logfile))

    if not entries:
        console.print("[yellow]No entries found[/yellow]")
        return

    analyzer = LogAnalyzer()
    result = analyzer.analyze(entries)

    # Compact summary
    console.print()
    console.print(f"[bold]Summary:[/bold] {result.total_entries:,} entries, "
                  f"[red]{result.error_count:,} errors[/red], "
                  f"[yellow]{result.warning_count:,} warnings[/yellow]")
    console.print()

    if result.top_errors:
        table = Table(title=f"Top {min(top, len(result.top_errors))} Error Patterns")
        table.add_column("#", justify="right", width=4)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Message")
        for i, (msg, count) in enumerate(result.top_errors[:top], 1):
            table.add_row(str(i), f"{count:,}", msg)
        console.print(table)

    if result.anomalies:
        console.print()
        console.print(f"[bold red]{len(result.anomalies)} anomalies detected[/bold red]")
        for a in result.anomalies[:5]:
            color = "red" if a.severity in ("critical", "high") else "yellow"
            console.print(f"  [{color}]{a.severity.upper()}[/{color}] {a.description}")


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["nginx", "syslog", "json", "auto"]),
    default="auto",
    help="Log format (default: auto-detect)",
)
@click.option("--interval", "-i", default=5, help="Refresh interval in seconds")
def watch(logfile: str, fmt: str, interval: int):
    """Live-tail a log file with real-time anomaly detection.

    Continuously monitors the log file for new entries and reports
    anomalies as they are detected.
    """
    if fmt == "auto":
        with open(logfile, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    fmt = detect_format(line)
                    break

    parser = PARSERS[fmt]()
    analyzer = LogAnalyzer()

    console.print(f"[bold blue]Watching {logfile}...[/bold blue] (Ctrl+C to stop)")
    console.print(f"[dim]Format: {fmt} | Refresh: {interval}s[/dim]")
    console.print()

    try:
        with open(logfile, "r", errors="replace") as f:
            # Seek to end
            f.seek(0, 2)

            window = []
            while True:
                new_lines = f.readlines()
                if new_lines:
                    for line in new_lines:
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        entry = parser.parse_line(line)
                        if entry:
                            window.append(entry)
                            # Color-coded live output
                            if entry.is_error:
                                console.print(f"[red]ERROR[/red] {entry.message[:120]}")
                            elif entry.is_warning:
                                console.print(f"[yellow]WARN [/yellow] {entry.message[:120]}")

                    # Keep window to last 1000 entries
                    if len(window) > 1000:
                        window = window[-1000:]

                    # Run analysis on window
                    if len(window) >= 10:
                        result = analyzer.analyze(window)
                        if result.anomalies:
                            for a in result.anomalies:
                                color = "red" if a.severity in ("critical", "high") else "yellow"
                                console.print(f"  [{color}]ANOMALY[/{color}] {a.description}")

                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching.[/dim]")


if __name__ == "__main__":
    cli()
