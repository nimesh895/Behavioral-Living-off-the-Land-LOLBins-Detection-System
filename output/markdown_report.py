"""Markdown Incident Report Generator for SOC Analysts."""

from datetime import datetime, timezone
import logging
from pathlib import Path

from output.timeline import TimelineEntry
from utils.models import Alert

logger = logging.getLogger("lolbins-detector.output.markdown")


class MarkdownReportGenerator:
    """Generates standardized, professional Markdown incident reports for SOC analysts."""

    def __init__(self, output_dir: str | Path = "reports") -> None:
        """Initialize the report generator.

        Args:
            output_dir: Directory where markdown report files will be saved.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        alert: Alert,
        timeline_entries: list[TimelineEntry],
        process_tree: str,
    ) -> str:
        """Compile a comprehensive Markdown incident report.

        Args:
            alert: The triggered security Alert.
            timeline_entries: Chronologically reconstructed events around the alert.
            process_tree: Formatted process lineage hierarchy tree.

        Returns:
            Rendered Markdown text.
        """
        mitre_list = ", ".join(alert.mitre_attack) if alert.mitre_attack else "Unassigned"
        indicators_list = "\n".join([f"- `{ind}`" for ind in alert.matched_indicators]) or "- None"

        # Severity badges
        severity_badges = {
            "critical": "🔴 **CRITICAL**",
            "high": "🟠 **HIGH**",
            "medium": "🟡 **MEDIUM**",
            "low": "🔵 **LOW**",
        }
        badge = severity_badges.get(str(alert.severity).lower(), f"**{alert.severity.upper()}**")

        # Format timeline table rows
        timeline_rows: list[str] = []
        for entry in timeline_entries:
            # Escape pipes in command line to prevent Markdown table formatting breaks
            sanitized_cmd = entry.command_line.replace("|", "\\|")
            if len(sanitized_cmd) > 90:
                sanitized_cmd = sanitized_cmd[:87] + "..."

            rel_badge = f"`{entry.relationship}`"
            if entry.relationship == "TRIGGER":
                rel_badge = "**`TRIGGER`**"

            row = (
                f"| {entry.delta_display} "
                f"| {entry.timestamp} "
                f"| {rel_badge} "
                f"| {entry.image} (PID: {entry.pid}) "
                f"| `{sanitized_cmd}` |"
            )
            timeline_rows.append(row)

        timeline_table = "\n".join(timeline_rows) if timeline_rows else "| - | - | - | - | - |"

        # Markdown Document Assembly
        report = f"""# Security Incident Report: {alert.rule_name}

---

## 1. Incident Overview & Triage Summary

| Attribute | Details |
| :--- | :--- |
| **Alert ID** | `{alert.alert_id}` |
| **Detection Rule ID** | `{alert.rule_id}` |
| **Severity Level** | {badge} |
| **Trigger Timestamp** | `{alert.timestamp}` |
| **Triage Status** | 🚨 New / Pending SOC Analysis |
| **MITRE ATT&CK** | {mitre_list} |

> **Rule Description**:  
> {alert.description}

---

## 2. Process Execution Context

| Field | Value |
| :--- | :--- |
| **Target Binary** | `{alert.event.image}` |
| **Process ID (PID)** | `{alert.event.pid}` |
| **Parent Process ID (PPID)** | `{alert.event.ppid}` |
| **Parent Executable** | `{alert.event.parent_image}` |
| **Security Account / User** | `{alert.event.user}` |
| **Integrity Level** | `{alert.event.integrity_level}` |
| **Process Creation Time** | `{alert.event.creation_time}` |

### Command Line Invocation
```powershell
{alert.event.command_line}
```

---

## 3. Matched Behavioral Indicators

The detection engine identified the following suspicious indicators and signature matches:

{indicators_list}

---

## 4. Process Lineage & Ancestry Tree

Reconstructed execution tree leading to the triggered binary:

```text
{process_tree}
```

---

## 5. Correlated Event Timeline (± 5–10 Minutes)

Chronological reconstruction of related process telemetry within the surrounding observation window:

| Delta | Timestamp (UTC) | Relationship | Process (PID) | Command Line |
| :--- | :--- | :--- | :--- | :--- |
{timeline_table}

---

## 6. Recommended SOC Analyst Response Playbook

1. **Process Containment**:
   - Terminate offending process (PID: `{alert.event.pid}`) and any spawned child processes.
   - If interactive remote command execution is suspected, isolate the affected endpoint from the local network segment.
2. **Forensic Artifact Preservation**:
   - Capture memory dump if suspicious script injection or unmanaged code execution occurred.
   - Inspect local staging paths (`%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%`, `C:\\Users\\Public\\`) for dropped payloads.
3. **Network Triage**:
   - Inspect proxy, firewall, and DNS logs for outbound network connections initiated around `{alert.timestamp}`.
4. **Credential & Persistence Auditing**:
   - Check for scheduled tasks, registry Run keys (`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`), or WMI event subscriptions created by `{alert.event.user}`.

---
*Report generated automatically by lolbins-detector on {datetime.now(timezone.utc).isoformat()}*
"""
        return report

    def write_report_file(
        self,
        alert: Alert,
        timeline_entries: list[TimelineEntry],
        process_tree: str,
    ) -> Path:
        """Render and write the report to a Markdown file on disk.

        Args:
            alert: The triggered security Alert.
            timeline_entries: Reconstructed timeline entries.
            process_tree: Formatted process lineage hierarchy tree.

        Returns:
            Path to the written report file.
        """
        report_content = self.generate_report(alert, timeline_entries, process_tree)
        safe_rule_id = alert.rule_id.replace(" ", "_")
        filename = f"incident_{safe_rule_id}_{alert.alert_id[:8]}.md"
        report_path = self.output_dir / filename

        try:
            report_path.write_text(report_content, encoding="utf-8")
            logger.info("Generated SOC incident report: %s", report_path)
        except OSError as exc:
            logger.error("Failed to write report file %s: %s", report_path, exc)

        return report_path
