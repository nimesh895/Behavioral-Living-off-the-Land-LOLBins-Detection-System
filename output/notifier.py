"""Console and JSONL file output handlers for LOLBins detection alerts."""

import json
import logging
from pathlib import Path

from utils.models import Alert, Severity

logger = logging.getLogger("lolbins-detector.output")


class AlertDispatcher:
    """Dispatches triggered alerts to the console and/or a structured JSONL file."""

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
    ) -> None:
        """Initialize the alert dispatcher.

        Args:
            console_alerts: Whether to print formatted alerts to standard output.
            json_log_path: Optional file path to append JSON-formatted alerts.
        """
        self.console_alerts = console_alerts
        self.json_log_path = Path(json_log_path) if json_log_path else None

        if self.json_log_path:
            self.json_log_path.parent.mkdir(parents=True, exist_ok=True)

    def dispatch(self, alert: Alert) -> None:
        """Send an alert to all configured output channels.

        Args:
            alert: The triggered Alert object.
        """
        if self.console_alerts:
            self._print_console_alert(alert)

        if self.json_log_path:
            self._write_json_alert(alert)

    def _print_console_alert(self, alert: Alert) -> None:
        """Format and print an alert banner to the console."""
        color = self._SEVERITY_COLORS.get(alert.severity, "")
        reset = self._RESET_COLOR if color else ""
        mitre_str = ", ".join(alert.mitre_attack) if alert.mitre_attack else "N/A"
        indicators_str = ", ".join(alert.matched_indicators)

        banner = (
            f"\n{color}[ALERT: {alert.severity.upper()}] {alert.rule_id} - {alert.rule_name}{reset}\n"
            f"  Timestamp       : {alert.timestamp}\n"
            f"  MITRE ATT&CK    : {mitre_str}\n"
            f"  Process (PID)   : {alert.event.image} (PID: {alert.event.pid}, PPID: {alert.event.ppid})\n"
            f"  Parent Process  : {alert.event.parent_image}\n"
            f"  Command Line    : {alert.event.command_line}\n"
            f"  User / Integrity: {alert.event.user} ({alert.event.integrity_level})\n"
            f"  Indicators      : {indicators_str}\n"
            f"  Description     : {alert.description}\n"
        )
        print(banner, flush=True)

    def _write_json_alert(self, alert: Alert) -> None:
        """Append the alert as a single JSON line to the configured log file."""
        if not self.json_log_path:
            return
        try:
            with self.json_log_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(alert.to_dict()) + "\n")
        except OSError as exc:
            logger.error("Failed to write alert to %s: %s", self.json_log_path, exc)
