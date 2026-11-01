"""Single-event behavioral detection rule implementation."""

from collections.abc import Sequence
import re
from typing import Any

from engine.base import BaseRule
from engine.state import CorrelationState
from utils.models import Alert, ProcessEvent, Severity


class SingleEventRule(BaseRule):
    """Rule base evaluating a single process creation event against defined criteria.

    Can be instantiated directly with declarative pattern criteria (e.g. from YAML),
    or subclassed in Python by overriding the matches() method.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity | str,
        mitre_attack: list[str] | None = None,
        target_images: Sequence[str] | None = None,
        suspicious_parents: Sequence[str] | None = None,
        command_line_contains_any: Sequence[str] | None = None,
        command_line_contains_all: Sequence[str] | None = None,
        command_line_regex: Sequence[re.Pattern[str] | str] | None = None,
        required_integrity_levels: Sequence[str] | None = None,
        enabled: bool = True,
    ) -> None:
        """Initialize single-event detection rule.

        Args:
            rule_id: Unique rule identifier.
            name: Human-readable name.
            description: Technical description.
            severity: Severity level.
            mitre_attack: List of MITRE ATT&CK technique IDs.
            target_images: List of lowercased executable names (e.g. ['certutil.exe']).
            suspicious_parents: List of suspicious parent process names.
            command_line_contains_any: Tokens where any matching satisfies command line condition.
            command_line_contains_all: Tokens where all must be present.
            command_line_regex: Regex patterns to test against the command line.
            required_integrity_levels: Allowed process integrity levels.
            enabled: Whether this rule is active.
        """
        super().__init__(
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            mitre_attack=mitre_attack or [],
            enabled=enabled,
        )
        self.target_images: list[str] = [img.lower() for img in (target_images or [])]
        self.suspicious_parents: list[str] = [
            p.lower() for p in (suspicious_parents or [])
        ]
        self.command_line_contains_any: list[str] = [
            t.lower() for t in (command_line_contains_any or [])
        ]
        self.command_line_contains_all: list[str] = [
            t.lower() for t in (command_line_contains_all or [])
        ]

        compiled_regexes: list[re.Pattern[str]] = []
        for r in command_line_regex or []:
            if isinstance(r, str):
                compiled_regexes.append(re.compile(r, re.IGNORECASE))
            else:
                compiled_regexes.append(r)
        self.command_line_regex = compiled_regexes

        self.required_integrity_levels: list[str] = [
            lvl.lower() for lvl in (required_integrity_levels or [])
        ]

    def matches(
        self, event: ProcessEvent, state: CorrelationState
    ) -> tuple[bool, list[str]]:
        """Evaluate event against the rule's criteria.

        Subclasses may override this method for custom detection algorithms.

        Args:
            event: The incoming ProcessEvent.
            state: CorrelationState containing recent events for context.

        Returns:
            Tuple of (is_match, matched_indicators).
        """
        indicators: list[str] = []
        image_name = event.image_name
        parent_name = event.parent_image_name
        cmd_lower = event.command_line.lower()
        integrity_lower = event.integrity_level.lower()

        # 1. Target image check
        if self.target_images:
            if image_name not in self.target_images:
                return False, []
            indicators.append(f"image={image_name}")

        # 2. Suspicious parent check
        if self.suspicious_parents:
            if parent_name not in self.suspicious_parents:
                return False, []
            indicators.append(f"parent_image={parent_name}")

        # 3. Required integrity level check
        if self.required_integrity_levels:
            if integrity_lower not in self.required_integrity_levels:
                return False, []
            indicators.append(f"integrity_level={event.integrity_level}")

        # 4. Command line 'contains_all' check
        if self.command_line_contains_all:
            for token in self.command_line_contains_all:
                if token not in cmd_lower:
                    return False, []
                indicators.append(f"cmdline_all:{token}")

        # 5. Command line 'contains_any' or 'regex' checks
        has_cmd_constraints = bool(
            self.command_line_contains_any or self.command_line_regex
        )
        if has_cmd_constraints:
            cmd_matched = False
            for token in self.command_line_contains_any:
                if token in cmd_lower:
                    cmd_matched = True
                    indicators.append(f"cmdline_token:{token}")

            for pattern in self.command_line_regex:
                if pattern.search(event.command_line):
                    cmd_matched = True
                    indicators.append(f"cmdline_regex:{pattern.pattern}")

            if not cmd_matched:
                return False, []

        return bool(indicators), indicators

    def evaluate(
        self, event: ProcessEvent, state: CorrelationState
    ) -> Alert | None:
        """Evaluate event and return an Alert if matched."""
        if not self.enabled:
            return None

        is_match, indicators = self.matches(event, state)
        if not is_match:
            return None

        return self.create_alert(
            trigger_event=event,
            matched_indicators=indicators,
            matched_events=[event],
            additional_context={"detection_type": "single_event"},
        )
