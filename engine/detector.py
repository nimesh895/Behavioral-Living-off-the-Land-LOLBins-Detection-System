"""Modular detection engine orchestrating single-event, sequential, and masquerading rules with suppression."""

from collections.abc import Sequence
import logging
from pathlib import Path
import re
from typing import Any

from engine.base import BaseRule
from engine.state import CorrelationState
from engine.suppression import SuppressionEngine
from utils.models import Alert, ProcessEvent, Severity

logger = logging.getLogger("lolbins-detector.engine")


class DetectionEngine:
    """Modular behavioral detection engine.

    Orchestrates single-event detection rules, sequential (multi-event) correlation
    rules, binary masquerading checks, PPID anomaly analysis, and false positive suppression.
    """

    # Generic LOLBin obfuscation patterns observed in living-off-the-land attacks
    _OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("Excessive caret (^) escaping", re.compile(r"(\^[^\s]){4,}")),
        ("Excessive backtick (`) escaping", re.compile(r"(`[^\s]){4,}")),
        (
            "Base64-like long payload string",
            re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
        ),
        (
            "Environment variable string slicing",
            re.compile(r"%[A-Za-z0-9_]+:~[0-9,-]+%"),
        ),
    ]

    _MONITORED_LOLBINS: set[str] = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "certutil.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "wscript.exe",
        "cscript.exe",
        "msiexec.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "msbuild.exe",
        "forfiles.exe",
        "pcalua.exe",
    }

    _CRITICAL_SYSTEM_PROCESSES: set[str] = {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "lsass.exe",
        "services.exe",
    }

    def __init__(
        self,
        rules: Sequence[BaseRule] | None = None,
        enable_heuristics: bool = True,
        min_severity: str = "low",
        window_seconds: float = 600.0,
        suppression_engine: SuppressionEngine | None = None,
    ) -> None:
        """Initialize the detection engine.

        Args:
            rules: Sequence of BaseRule instances (single-event or sequential).
            enable_heuristics: Whether to run generic command-line obfuscation checks.
            min_severity: Minimum alert severity threshold (low, medium, high, critical).
            window_seconds: Short-term correlation state duration in seconds (default: 600s / 10 min).
            suppression_engine: Optional SuppressionEngine instance for whitelisting and de-duplication.
        """
        self.rules: list[BaseRule] = list(rules or [])
        self.enable_heuristics = enable_heuristics
        self.min_severity_weight = Severity.weight(min_severity)

        # Correlation state maintaining 5-10 minute sliding window
        self.state = CorrelationState(window_seconds=window_seconds)
        self.suppression_engine = suppression_engine or SuppressionEngine()

        logger.info(
            "Initialized DetectionEngine with %d rules (correlation window: %.0fs, min severity: %s)",
            len(self.rules),
            window_seconds,
            min_severity,
        )

    def register_rule(self, rule: BaseRule) -> None:
        """Add a detection rule to the engine dynamically.

        Args:
            rule: A BaseRule instance (single-event or sequential).
        """
        self.rules.append(rule)
        logger.debug("Registered rule '%s' (%s)", rule.rule_id, rule.name)

    def evaluate(self, event: ProcessEvent) -> list[Alert]:
        """Evaluate an incoming process creation event against all rules, heuristics, and anomaly models.

        Args:
            event: The incoming ProcessEvent.

        Returns:
            List of triggered Alert objects meeting the severity threshold and passing suppression.
        """
        # 1. Update correlation state with the incoming event
        self.state.add_event(event)

        raw_alerts: list[Alert] = []

        # 2. Binary Masquerading / Renamed LOLBin Detection (PE OriginalFileName vs Executable Name)
        masq_alert = self._evaluate_masquerading(event)
        if masq_alert:
            raw_alerts.append(masq_alert)

        # 3. Parent PID (PPID) Spoofing & Lineage Anomaly Detection
        ppid_alert = self._evaluate_ppid_anomalies(event)
        if ppid_alert:
            raw_alerts.append(ppid_alert)

        # 4. Evaluate registered rules (single-event & sequential)
        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                alert = rule.evaluate(event, self.state)
                if alert and Severity.weight(alert.severity) >= self.min_severity_weight:
                    raw_alerts.append(alert)
            except Exception as exc:
                logger.error("Error evaluating rule '%s': %s", rule.rule_id, exc)

        # 5. Evaluate generic obfuscation heuristics if enabled
        if self.enable_heuristics:
            heuristic_alert = self._evaluate_heuristics(event)
            if (
                heuristic_alert
                and Severity.weight(heuristic_alert.severity) >= self.min_severity_weight
            ):
                raw_alerts.append(heuristic_alert)

        # 6. Apply false positive suppression and de-duplication
        filtered_alerts: list[Alert] = []
        for alert in raw_alerts:
            # Check explicit suppression rules
            suppressed, reason = self.suppression_engine.is_suppressed(alert)
            if suppressed:
                logger.debug("Alert '%s' suppressed: %s", alert.rule_id, reason)
                continue

            # Check alert de-duplication cooldown
            is_dup, count = self.suppression_engine.check_deduplication(alert)
            if is_dup:
                logger.debug(
                    "Alert '%s' de-duplicated (count: %d within cooldown window)",
                    alert.rule_id,
                    count,
                )
                continue

            alert.context["alert_hit_count"] = count
            filtered_alerts.append(alert)

        return filtered_alerts

    def _evaluate_masquerading(self, event: ProcessEvent) -> Alert | None:
        """Detect when a native Windows LOLBin has been renamed or copied to disguise its identity."""
        if not event.original_file_name:
            return None

        orig_clean = event.original_file_name.strip().lower()
        if not orig_clean.endswith(".exe"):
            orig_clean += ".exe"

        current_name = event.image_name

        # If original file name is a known monitored LOLBin, but current file name is different
        if orig_clean in self._MONITORED_LOLBINS and orig_clean != current_name:
            indicators = [
                f"original_file_name={orig_clean}",
                f"executing_image={current_name}",
            ]
            if event.hashes:
                indicators.append(f"sha256={event.hashes.get('SHA256', 'N/A')}")

            return Alert(
                rule_id="MASQ-001",
                rule_name="Masquerading: Renamed LOLBin Executable Invocation",
                severity=Severity.CRITICAL,
                description=(
                    f"A native Windows utility ({orig_clean}) was executed under a renamed or disguised "
                    f"binary path ({current_name}), indicating deliberate defense evasion."
                ),
                mitre_attack=["T1036.003", "T1218"],
                event=event,
                matched_indicators=indicators,
                context={
                    "detection_type": "masquerading",
                    "original_pe_name": orig_clean,
                    "disguised_image": current_name,
                },
            )

        return None

    def _evaluate_ppid_anomalies(self, event: ProcessEvent) -> Alert | None:
        """Detect indicators of Parent Process ID (PPID) spoofing and process tree tampering."""
        parent_lower = event.parent_image_name

        # Indicator 1: User-level process claiming critical core system service parent
        if parent_lower in self._CRITICAL_SYSTEM_PROCESSES:
            # System services run as SYSTEM; if child is standard user or medium integrity, likely spoofed
            is_user_context = "SYSTEM" not in event.user.upper() and "SERVICE" not in event.user.upper()
            is_low_integrity = event.integrity_level.lower() in ("medium", "low", "untrusted")

            if is_user_context and is_low_integrity:
                return Alert(
                    rule_id="PPID-ANOMALY-001",
                    rule_name="Suspicious Parent Process Spoofing Anomaly",
                    severity=Severity.HIGH,
                    description=(
                        f"Process {event.image_name} claims critical system parent ({parent_lower}), "
                        f"but executes with non-system user credentials ({event.user}) and {event.integrity_level} integrity."
                    ),
                    mitre_attack=["T1134.004", "T1059"],
                    event=event,
                    matched_indicators=[
                        f"claimed_parent={parent_lower}",
                        f"user_mismatch={event.user}",
                        f"integrity={event.integrity_level}",
                    ],
                    context={
                        "detection_type": "ppid_spoofing",
                        "anomaly": "system_parent_user_credentials",
                    },
                )

        return None

    def _evaluate_heuristics(self, event: ProcessEvent) -> Alert | None:
        """Analyze LOLBin command lines for obfuscation and evasion patterns."""
        if event.image_name not in self._MONITORED_LOLBINS:
            return None

        matched_heuristics: list[str] = []
        for label, pattern in self._OBFUSCATION_PATTERNS:
            if pattern.search(event.command_line):
                matched_heuristics.append(label)

        if not matched_heuristics:
            return None

        severity = Severity.HIGH if len(matched_heuristics) > 1 else Severity.MEDIUM
        return Alert(
            rule_id="HEURISTIC-OBF-001",
            rule_name="Suspicious Command-Line Obfuscation on LOLBin",
            severity=severity,
            description=(
                "Heuristic analysis detected potential command-line obfuscation "
                "or encoded payload execution on a monitored Windows binary."
            ),
            mitre_attack=["T1027", "T1059"],
            event=event,
            matched_indicators=matched_heuristics,
            context={
                "detection_type": "heuristic",
                "matched_heuristic_patterns": matched_heuristics,
            },
        )


# Alias for backward compatibility
BehavioralEngine = DetectionEngine
