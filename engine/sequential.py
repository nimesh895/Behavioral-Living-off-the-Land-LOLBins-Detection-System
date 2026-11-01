"""Sequential (multi-event) correlation detection rule implementation."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import logging
import re
import time
from typing import Any

from engine.base import BaseRule
from engine.state import CorrelationState, SequenceTrack
from utils.models import Alert, ProcessEvent, Severity

logger = logging.getLogger("lolbins-detector.engine.sequential")


@dataclass(slots=True)
class SequenceStage:
    """Represents a single step within an ordered multi-event detection sequence."""

    name: str
    target_images: list[str] = field(default_factory=list)
    suspicious_parents: list[str] = field(default_factory=list)
    command_line_contains_any: list[str] = field(default_factory=list)
    command_line_contains_all: list[str] = field(default_factory=list)
    command_line_regex: list[re.Pattern[str]] = field(default_factory=list)
    predicate: Callable[[ProcessEvent], bool] | None = None

    def matches(self, event: ProcessEvent) -> tuple[bool, list[str]]:
        """Evaluate if a process event fulfills this sequence stage."""
        indicators: list[str] = []
        image_name = event.image_name
        parent_name = event.parent_image_name
        cmd_lower = event.command_line.lower()

        if self.target_images:
            if image_name not in [img.lower() for img in self.target_images]:
                return False, []
            indicators.append(f"stage='{self.name}' image={image_name}")

        if self.suspicious_parents:
            if parent_name not in [p.lower() for p in self.suspicious_parents]:
                return False, []
            indicators.append(f"parent_image={parent_name}")

        if self.command_line_contains_all:
            for token in self.command_line_contains_all:
                if token.lower() not in cmd_lower:
                    return False, []
                indicators.append(f"cmdline_all:{token}")

        has_cmd_constraints = bool(
            self.command_line_contains_any or self.command_line_regex
        )
        if has_cmd_constraints:
            matched_cmd = False
            for token in self.command_line_contains_any:
                if token.lower() in cmd_lower:
                    matched_cmd = True
                    indicators.append(f"cmdline_token:{token}")

            for pattern in self.command_line_regex:
                if pattern.search(event.command_line):
                    matched_cmd = True
                    indicators.append(f"cmdline_regex:{pattern.pattern}")

            if not matched_cmd:
                return False, []

        if self.predicate is not None:
            try:
                if not self.predicate(event):
                    return False, []
                indicators.append(f"stage_predicate_passed:{self.name}")
            except Exception as exc:
                logger.debug("Stage predicate exception: %s", exc)
                return False, []

        return bool(indicators), indicators


class SequentialRule(BaseRule):
    """Detects ordered sequences of correlated events occurring within a time window.

    Maintains short-term progression state across multiple events, correlating them
    by user account, process tree lineage, or host-wide context.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity | str,
        stages: Sequence[SequenceStage],
        mitre_attack: list[str] | None = None,
        correlation_key_type: str = "user",
        within_seconds: float = 300.0,
        enabled: bool = True,
    ) -> None:
        """Initialize sequential rule.

        Args:
            rule_id: Unique rule identifier.
            name: Human-readable name.
            description: Technical description.
            severity: Severity level.
            stages: Ordered sequence of SequenceStage objects (minimum 2 stages).
            mitre_attack: List of MITRE ATT&CK technique IDs.
            correlation_key_type: Method to correlate events ('user', 'process_tree', 'parent_child', or 'global').
            within_seconds: Maximum time window for the entire sequence to complete.
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
        if len(stages) < 2:
            raise ValueError(f"SequentialRule '{rule_id}' must define at least 2 stages.")

        self.stages = list(stages)
        self.correlation_key_type = correlation_key_type.lower()
        self.within_seconds = max(10.0, within_seconds)

    def resolve_correlation_key(self, event: ProcessEvent) -> str:
        """Derive the correlation partition key for an event."""
        if self.correlation_key_type in ("process_tree", "parent_child"):
            return f"tree:{event.pid}"
        elif self.correlation_key_type == "user":
            return f"user:{event.user.upper()}"
        return "global:system"

    def evaluate(
        self, event: ProcessEvent, state: CorrelationState
    ) -> Alert | None:
        """Evaluate event against the multi-event sequence state machine."""
        if not self.enabled:
            return None

        now = time.time()
        is_tree_corr = self.correlation_key_type in ("process_tree", "parent_child")

        # 1. Locate active track
        active_track: SequenceTrack | None = None
        if is_tree_corr:
            ancestors = state.get_process_ancestors(event.pid)
            ancestor_pids = {a.pid for a in ancestors}
            active_track = state.find_process_tree_track(
                self.rule_id, event.ppid, ancestor_pids
            )
        else:
            correlation_key = self.resolve_correlation_key(event)
            active_track = state.get_sequence_track(self.rule_id, correlation_key)

        # 2. Case: No active sequence in-flight
        if active_track is None:
            first_stage = self.stages[0]
            matched, indicators = first_stage.matches(event)
            if matched:
                key = (
                    f"tree:{event.pid}"
                    if is_tree_corr
                    else self.resolve_correlation_key(event)
                )
                logger.debug(
                    "[%s] Stage 1/%d ('%s') matched for %s",
                    self.rule_id,
                    len(self.stages),
                    first_stage.name,
                    key,
                )
                new_track = SequenceTrack(
                    rule_id=self.rule_id,
                    correlation_key=key,
                    matched_events=[event],
                    associated_pids={event.pid},
                    current_stage_index=0,
                    started_at=now,
                    expires_at=now + self.within_seconds,
                )
                state.set_sequence_track(new_track)
            return None

        # 3. Case: Sequence in-flight - evaluate next expected stage
        next_stage_index = active_track.current_stage_index + 1
        expected_stage = self.stages[next_stage_index]
        matched, stage_indicators = expected_stage.matches(event)

        if matched:
            active_track.matched_events.append(event)
            active_track.associated_pids.add(event.pid)
            active_track.current_stage_index = next_stage_index

            logger.debug(
                "[%s] Advanced to Stage %d/%d ('%s') for %s",
                self.rule_id,
                next_stage_index + 1,
                len(self.stages),
                expected_stage.name,
                active_track.correlation_key,
            )

            # Check if all stages are completed
            if next_stage_index == len(self.stages) - 1:
                state.clear_sequence_track(self.rule_id, active_track.correlation_key)
                duration = round(now - active_track.started_at, 2)

                all_matched_events = list(active_track.matched_events)
                summary_indicators = [
                    f"stage_{idx + 1}:{stage.name}"
                    for idx, stage in enumerate(self.stages)
                ]

                context = {
                    "detection_type": "sequential",
                    "correlation_key": active_track.correlation_key,
                    "correlation_type": self.correlation_key_type,
                    "duration_seconds": duration,
                    "within_window_seconds": self.within_seconds,
                    "stages_completed": [stage.name for stage in self.stages],
                }

                logger.info(
                    "[%s] Multi-event sequence matched: '%s' across %d events in %.2fs",
                    self.rule_id,
                    self.name,
                    len(all_matched_events),
                    duration,
                )

                return self.create_alert(
                    trigger_event=event,
                    matched_indicators=summary_indicators,
                    matched_events=all_matched_events,
                    additional_context=context,
                )

            # Not yet complete, save updated track
            state.set_sequence_track(active_track)
            return None

        # If incoming event matches Stage 0 again, refresh/restart track
        first_stage = self.stages[0]
        matched_restart, _ = first_stage.matches(event)
        if matched_restart:
            active_track.matched_events = [event]
            active_track.associated_pids = {event.pid}
            active_track.current_stage_index = 0
            active_track.started_at = now
            active_track.expires_at = now + self.within_seconds
            state.set_sequence_track(active_track)

        return None
