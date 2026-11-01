"""Behavioral detection engine evaluating process events against rules and heuristics."""

import logging
import re

from rules.loader import DetectionRule
from utils.models import Alert, ProcessEvent, Severity

logger = logging.getLogger("lolbins-detector.engine")


class BehavioralEngine:
    """Evaluates Windows process creation events against LOLBin rules and heuristics."""

    # Common obfuscation patterns observed in Living-off-the-Land command lines
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
        rules: list[DetectionRule],
        enable_heuristics: bool = True,
        min_severity: str = "low",
    ) -> None:
        """Initialize the behavioral detection engine.

        Args:
            rules: List of loaded DetectionRule objects.
            enable_heuristics: Whether to run command-line obfuscation heuristics.
            min_severity: Minimum severity threshold for emitting alerts.
        """
        self.rules = rules
        self.enable_heuristics = enable_heuristics
        self.min_severity_weight = Severity.weight(min_severity)

    def evaluate(self, event: ProcessEvent) -> list[Alert]:
        """Evaluate a single process creation event and return any triggered alerts.

        Args:
            event: The ProcessEvent to analyze.

        Returns:
            List of triggered Alert objects meeting the severity threshold.
        """
        alerts: list[Alert] = []

        for rule in self.rules:
            matched, indicators = self._matches_rule(event, rule)
            if matched and Severity.weight(rule.severity) >= self.min_severity_weight:
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        mitre_attack=rule.mitre_attack,
                        event=event,
                        matched_indicators=indicators,
                    )
                )

        if self.enable_heuristics:
            heuristic_alert = self._evaluate_heuristics(event)
            if (
                heuristic_alert
                and Severity.weight(heuristic_alert.severity) >= self.min_severity_weight
            ):
                alerts.append(heuristic_alert)

        return alerts

    def _matches_rule(
        self, event: ProcessEvent, rule: DetectionRule
    ) -> tuple[bool, list[str]]:
        """Check whether an event satisfies all defined criteria of a rule."""
        indicators: list[str] = []
        image_name = event.image_name
        parent_name = event.parent_image_name
        cmd_lower = event.command_line.lower()
        integrity_lower = event.integrity_level.lower()

        # 1. Target image check
        if rule.target_images:
            if image_name not in rule.target_images:
                return False, []
            indicators.append(f"image={image_name}")

        # 2. Suspicious parent check
        if rule.suspicious_parents:
            if parent_name not in rule.suspicious_parents:
                return False, []
            indicators.append(f"parent_image={parent_name}")

        # 3. Required integrity level check
        if rule.required_integrity_levels:
            if integrity_lower not in rule.required_integrity_levels:
                return False, []
            indicators.append(f"integrity_level={event.integrity_level}")

        # 4. Command line 'contains_all' check
        if rule.command_line_contains_all:
            for token in rule.command_line_contains_all:
                if token not in cmd_lower:
                    return False, []
                indicators.append(f"cmdline_all:{token}")

        # 5. Command line 'contains_any' and 'regex' checks
        has_cmd_constraints = bool(
            rule.command_line_contains_any or rule.command_line_regex
        )
        if has_cmd_constraints:
            cmd_matched = False
            for token in rule.command_line_contains_any:
                if token in cmd_lower:
                    cmd_matched = True
                    indicators.append(f"cmdline_token:{token}")

            for pattern in rule.command_line_regex:
                if pattern.search(event.command_line):
                    cmd_matched = True
                    indicators.append(f"cmdline_regex:{pattern.pattern}")

            if not cmd_matched:
                return False, []

        return bool(indicators), indicators

    def _evaluate_heuristics(self, event: ProcessEvent) -> Alert | None:
        """Analyze LOLBin command lines for generic obfuscation and evasion patterns."""
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
        )
