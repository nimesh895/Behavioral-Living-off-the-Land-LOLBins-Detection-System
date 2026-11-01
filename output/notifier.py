"""Unified Alert Dispatcher integrating Console, JSON, and Markdown Report outputs with Timeline Reconstruction."""

import json
import logging
from pathlib import Path
from typing import Any

from output.markdown_report import MarkdownReportGenerator
from output.timeline import TimelineEntry, TimelineReconstructor
from storage.database import DatabaseManager
from utils.models import Alert, ProcessEvent, Severity

logger = logging.getLogger("lolbins-detector.output")


class AlertDispatcher:
    """Dispatches enriched security alerts to Console, JSON files, and Markdown SOC reports."""

    _SEVERITY_COLORS: dict[Severity, str] = {
        Severity.LOW: "\033[36m",       # Cyan
        Severity.MEDIUM: "\033[33m",    # Yellow
        Severity.HIGH: "\033[91m",      # Bright Red
        Severity.CRITICAL: "\033[41m",  # Red Background
    }
    _RESET_COLOR: str = "\033[0m"

    def __init__(
        self,
        console_alerts: bool = True,
        json_log_path: str | Path | None = None,
        markdown_reports_dir: str | Path | None = "reports",
        db_manager: DatabaseManager | None = None,
        timeline_window_seconds: float = 300.0,
    ) -> None:
        """Initialize the alert dispatcher.

        Args:
            console_alerts: Whether to print formatted alerts to standard output.
            json_log_path: Optional file path to append JSONL-formatted alerts.
            markdown_reports_dir: Optional directory to write Markdown SOC incident reports.
            db_manager: Optional DatabaseManager instance for historical timeline reconstruction.
            timeline_window_seconds: Lookback/lookahead window for timeline reconstruction (± 5-10 min).
        """
        self.console_alerts = console_alerts
        self.json_log_path = Path(json_log_path) if json_log_path else None
        self.markdown_reports_dir = (
            Path(markdown_reports_dir) if markdown_reports_dir else None
        )

        if self.json_log_path:
            self.json_log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.markdown_reports_dir:
            self.markdown_reports_dir.mkdir(parents=True, exist_ok=True)

        # Timeline and Markdown report subcomponents
        self.timeline_reconstructor = TimelineReconstructor(
            db_manager=db_manager,
            default_window_seconds=timeline_window_seconds,
        )
        self.report_generator = (
            MarkdownReportGenerator(output_dir=self.markdown_reports_dir)
            if self.markdown_reports_dir
            else None
        )

    def dispatch(
        self,
        alert: Alert,
        candidate_events: list[ProcessEvent] | None = None,
    ) -> dict[str, Any]:
        """Process, enrich with timeline, and dispatch an alert to all configured channels.

        Args:
            alert: The triggered Alert object.
            candidate_events: Optional list of in-memory events to supplement database events.

        Returns:
            Dictionary containing dispatch metadata and paths to generated artifacts.
        """
        # 1. Reconstruct historical and concurrent event timeline (± 5–10 minutes)
        timeline_entries = self.timeline_reconstructor.reconstruct_timeline(
            alert=alert,
            candidate_events=candidate_events,
        )

        # 2. Build ASCII process lineage tree
        process_tree = self.timeline_reconstructor.build_ascii_process_tree(
            trigger_event=alert.event,
            timeline_entries=timeline_entries,
        )

        # 3. Console Output
        if self.console_alerts:
            self._print_console_alert(alert, timeline_entries, process_tree)

        # 4. JSON Outputs (JSONL aggregate + individual incident JSON)
        json_file_path = None
        if self.json_log_path:
            json_file_path = self._write_json_alert(alert, timeline_entries)

        # 5. Markdown Report Output
        report_file_path = None
        if self.report_generator is not None:
            report_file_path = self.report_generator.write_report_file(
                alert=alert,
                timeline_entries=timeline_entries,
                process_tree=process_tree,
            )

        return {
            "alert_id": alert.alert_id,
            "timeline_count": len(timeline_entries),
            "json_log_path": str(self.json_log_path) if self.json_log_path else None,
            "individual_json": str(json_file_path) if json_file_path else None,
            "markdown_report": str(report_file_path) if report_file_path else None,
        }

    def _print_console_alert(
        self,
        alert: Alert,
        timeline_entries: list[TimelineEntry],
        process_tree: str,
    ) -> None:
        """Format and print an alert banner with contextual timeline to standard output."""
        color = self._SEVERITY_COLORS.get(alert.severity, "")
        reset = self._RESET_COLOR if color else ""
        mitre_str = ", ".join(alert.mitre_attack) if alert.mitre_attack else "N/A"
        indicators_str = ", ".join(alert.matched_indicators)

        lines = [
            f"\n{color}══════════════════════════════════════════════════════════════════════════════{reset}",
            f"{color} [ALERT: {alert.severity.upper()}] {alert.rule_id} - {alert.rule_name}{reset}",
            f"{color}══════════════════════════════════════════════════════════════════════════════{reset}",
            f"  Alert ID        : {alert.alert_id}",
            f"  Timestamp (UTC) : {alert.timestamp}",
            f"  MITRE ATT&CK    : {mitre_str}",
            f"  Trigger Process : {alert.event.image} (PID: {alert.event.pid}, PPID: {alert.event.ppid})",
            f"  Parent Process  : {alert.event.parent_image}",
            f"  Command Line    : {alert.event.command_line}",
            f"  Security User   : {alert.event.user} ({alert.event.integrity_level} integrity)",
            f"  Indicators      : {indicators_str}",
            f"  Description     : {alert.description}",
        ]

        # Multi-event sequence info if present
        if alert.context.get("is_sequential"):
            duration = alert.context.get("duration_seconds", "N/A")
            corr_key = alert.context.get("correlation_key", "N/A")
            lines.append(f"  Sequence Chain  : Correlated in {duration}s (Key: {corr_key})")

        # Reconstructed Process Tree
        if process_tree:
            lines.append("  Process Lineage :")
            for t_line in process_tree.splitlines():
                lines.append(f"    {t_line}")

        # Reconstructed Timeline Table
        if timeline_entries:
            lines.append(f"  Timeline (± 5-10m Window: {len(timeline_entries)} correlated events):")
            for entry in timeline_entries:
                rel_tag = f"[{entry.relationship}]"
                marker = ">>>" if entry.relationship == "TRIGGER" else "   "
                short_cmd = entry.command_line
                if len(short_cmd) > 65:
                    short_cmd = short_cmd[:62] + "..."
                lines.append(
                    f"    {marker} {entry.delta_display:<10} | {rel_tag:<11} | PID {entry.pid:<5} | {entry.image:<15} | {short_cmd}"
                )

        lines.append(f"{color}──────────────────────────────────────────────────────────────────────────────{reset}\n")
        print("\n".join(lines), flush=True)

    def _write_json_alert(
        self,
        alert: Alert,
        timeline_entries: list[TimelineEntry],
    ) -> Path | None:
        """Write structured alert payload with full timeline to JSONL and individual JSON."""
        if not self.json_log_path:
            return None

        # Build comprehensive incident data payload
        payload = alert.to_dict()
        payload["timeline_reconstruction"] = {
            "window_seconds": self.timeline_reconstructor.default_window_seconds,
            "total_correlated_events": len(timeline_entries),
            "events": [entry.to_dict() for entry in timeline_entries],
        }

        # 1. Append to aggregate JSONL log
        try:
            with self.json_log_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(payload) + "\n")
        except OSError as exc:
            logger.error("Failed to append alert to JSONL %s: %s", self.json_log_path, exc)

        # 2. Write dedicated incident JSON file
        json_dir = self.json_log_path.parent / "incidents"
        json_dir.mkdir(parents=True, exist_ok=True)
        incident_file = json_dir / f"incident_{alert.rule_id}_{alert.alert_id[:8]}.json"

        try:
            incident_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write individual JSON %s: %s", incident_file, exc)

        return incident_file
