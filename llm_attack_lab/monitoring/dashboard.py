"""
Monitoring Dashboard Module

Provides a real-time CLI dashboard for monitoring
attack simulations and system health.
"""

import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

from .metrics import MetricsCollector, get_metrics_collector
from .logger import LabLogger, get_logger, MemoryHandler


console = Console()


class MonitoringDashboard:
    """
    Real-time monitoring dashboard for CLI.

    Displays:
    - Attack statistics and success rates
    - Defense effectiveness metrics
    - System health indicators
    - Recent security events
    - Performance metrics
    """

    def __init__(self, metrics: Optional[MetricsCollector] = None,
                 logger: Optional[LabLogger] = None):
        self.metrics = metrics or get_metrics_collector()
        self.logger = logger or get_logger()
        self._memory_handler = MemoryHandler(max_entries=100)
        self.logger.add_handler(self._memory_handler)
        self._running = False

    def create_layout(self) -> Layout:
        """Create the dashboard layout"""
        layout = Layout()

        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )

        layout["left"].split(
            Layout(name="attacks", ratio=1),
            Layout(name="defenses", ratio=1),
        )

        layout["right"].split(
            Layout(name="system", ratio=1),
            Layout(name="events", ratio=1),
        )

        return layout

    def render_header(self) -> Panel:
        """Render dashboard header"""
        uptime = self.metrics.get_all_metrics().get("uptime_seconds", 0)
        uptime_str = str(timedelta(seconds=int(uptime)))

        header_text = Text()
        header_text.append("LLM ATTACK LAB ", style="bold cyan")
        header_text.append("| MONITORING DASHBOARD ", style="white")
        header_text.append(f"| Uptime: {uptime_str} ", style="green")
        header_text.append(f"| {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")

        return Panel(header_text, style="blue")

    def render_attacks_panel(self) -> Panel:
        """Render attack statistics panel"""
        summary = self.metrics.get_attack_summary()

        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        table.add_column("Metric", style="white")
        table.add_column("Value", style="cyan", justify="right")

        table.add_row("Total Attacks", str(summary["total_attacks"]))
        table.add_row("Successful", str(summary["successful_attacks"]))
        table.add_row("Detected", str(summary["detected_attacks"]))

        success_style = "red" if summary["success_rate"] > 50 else "green"
        table.add_row("Success Rate", f"[{success_style}]{summary['success_rate']:.1f}%[/]")

        detect_style = "green" if summary["detection_rate"] > 70 else "yellow"
        table.add_row("Detection Rate", f"[{detect_style}]{summary['detection_rate']:.1f}%[/]")

        if summary["attack_duration"]["count"] > 0:
            table.add_row("Avg Duration", f"{summary['attack_duration']['avg']:.3f}s")

        return Panel(table, title="[ATK] Attack Statistics", border_style="red")

    def render_defenses_panel(self) -> Panel:
        """Render defense statistics panel"""
        summary = self.metrics.get_defense_summary()

        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        table.add_column("Metric", style="white")
        table.add_column("Value", style="cyan", justify="right")

        table.add_row("Total Requests", str(summary["total_requests"]))
        table.add_row("Blocked", str(summary["blocked_requests"]))
        table.add_row("Defense Actions", str(summary["total_defense_actions"]))

        block_style = "green" if summary["block_rate"] > 0 else "white"
        table.add_row("Block Rate", f"[{block_style}]{summary['block_rate']:.1f}%[/]")

        if summary["request_latency"]["count"] > 0:
            table.add_row("Avg Latency", f"{summary['request_latency']['avg']*1000:.1f}ms")

        return Panel(table, title="[DEF] Defense Statistics", border_style="green")

    def render_system_panel(self) -> Panel:
        """Render system health panel"""
        all_metrics = self.metrics.get_all_metrics()

        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        table.add_column("Metric", style="white")
        table.add_column("Value", style="cyan", justify="right")

        # Counters summary
        counter_count = len(all_metrics.get("counters", {}))
        gauge_count = len(all_metrics.get("gauges", {}))

        table.add_row("Active Counters", str(counter_count))
        table.add_row("Active Gauges", str(gauge_count))
        table.add_row("Uptime", f"{all_metrics['uptime_seconds']:.0f}s")

        # Add some key gauges if available
        for key, value in list(all_metrics.get("gauges", {}).items())[:3]:
            short_key = key.split("{")[0][-20:]
            table.add_row(short_key, f"{value:.2f}")

        return Panel(table, title="[SYS] System Health", border_style="blue")

    def render_events_panel(self) -> Panel:
        """Render recent events panel"""
        entries = self._memory_handler.get_entries(limit=10)

        if not entries:
            content = Text("No recent events", style="dim")
        else:
            lines = []
            for entry in reversed(entries[-8:]):
                level_style = {
                    "DEBUG": "dim",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "bold red",
                    "SECURITY": "bold magenta",
                }.get(entry.level, "white")

                time_str = entry.timestamp.split("T")[1][:8]
                lines.append(f"[dim]{time_str}[/] [{level_style}]{entry.level[:4]}[/] {entry.message[:40]}")

            content = Text("\n".join(lines))

        return Panel(content, title="[LOG] Recent Events", border_style="yellow")

    def render_footer(self) -> Panel:
        """Render dashboard footer"""
        footer_text = Text()
        footer_text.append("[Q] Quit ", style="dim")
        footer_text.append("[R] Refresh ", style="dim")
        footer_text.append("[E] Export Metrics ", style="dim")
        footer_text.append("[C] Clear Metrics", style="dim")

        return Panel(footer_text, style="dim")

    def render(self) -> Layout:
        """Render the full dashboard"""
        layout = self.create_layout()

        layout["header"].update(self.render_header())
        layout["attacks"].update(self.render_attacks_panel())
        layout["defenses"].update(self.render_defenses_panel())
        layout["system"].update(self.render_system_panel())
        layout["events"].update(self.render_events_panel())
        layout["footer"].update(self.render_footer())

        return layout

    def run(self, refresh_rate: float = 1.0):
        """Run the live dashboard"""
        self._running = True

        console.print("\n[bold cyan]Starting Monitoring Dashboard...[/]")
        console.print("[dim]Press Ctrl+C to exit[/]\n")

        try:
            with Live(self.render(), console=console, refresh_per_second=1/refresh_rate) as live:
                while self._running:
                    time.sleep(refresh_rate)
                    live.update(self.render())
        except KeyboardInterrupt:
            self._running = False
            console.print("\n[yellow]Dashboard stopped.[/]")

    def stop(self):
        """Stop the dashboard"""
        self._running = False

    def show_summary(self):
        """Show a static summary of metrics"""
        console.print("\n")
        console.print(self.render_header())
        console.print(self.render_attacks_panel())
        console.print(self.render_defenses_panel())
        console.print(self.render_system_panel())
        console.print(self.render_events_panel())

    def export_report(self, filepath: str = None) -> str:
        """Export a detailed metrics report"""
        report = []
        report.append("=" * 60)
        report.append("LLM ATTACK LAB - MONITORING REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 60)
        report.append("")

        # Attack Summary
        attack_summary = self.metrics.get_attack_summary()
        report.append("ATTACK STATISTICS")
        report.append("-" * 40)
        report.append(f"  Total Attacks:     {attack_summary['total_attacks']}")
        report.append(f"  Successful:        {attack_summary['successful_attacks']}")
        report.append(f"  Detected:          {attack_summary['detected_attacks']}")
        report.append(f"  Success Rate:      {attack_summary['success_rate']:.1f}%")
        report.append(f"  Detection Rate:    {attack_summary['detection_rate']:.1f}%")
        report.append("")

        # Defense Summary
        defense_summary = self.metrics.get_defense_summary()
        report.append("DEFENSE STATISTICS")
        report.append("-" * 40)
        report.append(f"  Total Requests:    {defense_summary['total_requests']}")
        report.append(f"  Blocked:           {defense_summary['blocked_requests']}")
        report.append(f"  Defense Actions:   {defense_summary['total_defense_actions']}")
        report.append(f"  Block Rate:        {defense_summary['block_rate']:.1f}%")
        report.append("")

        # All Metrics
        all_metrics = self.metrics.get_all_metrics()
        report.append("ALL COUNTERS")
        report.append("-" * 40)
        for key, value in sorted(all_metrics.get("counters", {}).items()):
            report.append(f"  {key}: {value}")
        report.append("")

        report.append("ALL GAUGES")
        report.append("-" * 40)
        for key, value in sorted(all_metrics.get("gauges", {}).items()):
            report.append(f"  {key}: {value}")
        report.append("")

        report.append("=" * 60)

        report_text = "\n".join(report)

        if filepath:
            with open(filepath, "w") as f:
                f.write(report_text)

        return report_text


def show_quick_stats():
    """Show quick stats in the console"""
    metrics = get_metrics_collector()
    dashboard = MonitoringDashboard(metrics)
    dashboard.show_summary()


def run_dashboard():
    """Run the live monitoring dashboard"""
    metrics = get_metrics_collector()
    dashboard = MonitoringDashboard(metrics)
    dashboard.run()
