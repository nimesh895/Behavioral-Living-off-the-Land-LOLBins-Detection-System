"""Modular detection engine orchestrating single-event and sequential correlation rules."""

from collections.abc import Sequence
import logging
import re
from typing import Any

from engine.base import BaseRule
from engine.state import CorrelationState
from utils.models import Alert, ProcessEvent, Severity

logger = logging.getLogger("lolbins-detector.engine")


class DetectionEngine:
    """Modular behavioral detection engine.

    Orchestrates single-event detection rules, sequential (multi-event) correlation
    rules, and command-line obfuscation heuristics over a short-term sliding window.
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

    def __init__(
        self,
        rules: Sequence[BaseRule] | None = None,
        enable_heuristics: bool = True,
        min_severity: str = "low",
        window_seconds: float = 600.0,
    ) -> None:
        """Initialize the detection engine.

        Args:
            rules: Sequence of BaseRule instances (single-event or sequential).
            enable_heuristics: Whether to run generic command-line obfuscation checks.
            min_severity: Minimum alert severity threshold (low, medium, high, critical).
            window_seconds: Short-term correlation state duration in seconds (default: 600s / 10 min).
        """
        self.rules: list[BaseRule] = list(rules or [])
        self.enable_heuristics = enable_heuristics
        self.min_severity_weight = Severity.weight(min_severity)

        # Correlation state maintaining 5-10 minute sliding window
        self.state = CorrelationState(window_seconds=window_seconds)

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
        """Evaluate an incoming process creation event against all rules and heuristics.

        Args:
            event: The incoming ProcessEvent.

        Returns:
            List of triggered Alert objects meeting the severity threshold.
        """
        # 1. Update correlation state with the incoming event
        self.state.add_event(event)

        alerts: list[Alert] = []

        # 2. Evaluate all registered rules (single-event & sequential)
        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                alert = rule.evaluate(event, self.state)
                if alert and Severity.weight(alert.severity) >= self.min_severity_weight:
                    alerts.append(alert)
            except Exception as exc:
                logger.error("Error evaluating rule '%s': %s", rule.rule_id, exc)

        # 3. Evaluate generic obfuscation heuristics if enabled
        if self.enable_heuristics:
            heuristic_alert = self._evaluate_heuristics(event)
            if (
                heuristic_alert
                and Severity.weight(heuristic_alert.severity) >= self.min_severity_weight
            ):
                alerts.append(heuristic_alert)

        return alerts

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
