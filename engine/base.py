"""Base rule definitions and detection results for lolbins-detector."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from utils.models import Alert, ProcessEvent, Severity

if TYPE_CHECKING:
    from engine.state import CorrelationState


@dataclass(slots=True)
class DetectionResult:
    """Encapsulates the outcome of a rule evaluation."""

    matched: bool
    matched_indicators: list[str] = field(default_factory=list)
    matched_events: list[ProcessEvent] = field(default_factory=list)
    context_details: dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for all behavioral detection rules.

    Each rule must provide identification, classification metadata,
    and an evaluation implementation that inspects the current event
    and the correlation state.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity | str,
        mitre_attack: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        """Initialize base rule metadata.

        Args:
            rule_id: Unique rule identifier (e.g. 'LOLBIN-001', 'SEQ-001').
            name: Human-readable rule title.
            description: Detailed description of the threat or technique.
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL).
            mitre_attack: List of MITRE ATT&CK technique IDs (e.g. ['T1105']).
            enabled: Whether the rule should be evaluated by the engine.
        """
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = Severity(str(severity).lower())
        self.mitre_attack = mitre_attack or []
        self.enabled = enabled

    @abstractmethod
    def evaluate(
        self, event: ProcessEvent, state: "CorrelationState"
    ) -> Alert | None:
        """Evaluate an incoming process event against this rule.

        Args:
            event: The incoming process creation event.
            state: The correlation state containing short-term historical context.

        Returns:
            An Alert object if the rule triggers, or None.
        """
        raise NotImplementedError

    def create_alert(
        self,
        trigger_event: ProcessEvent,
        matched_indicators: list[str],
        matched_events: list[ProcessEvent] | None = None,
        additional_context: dict[str, Any] | None = None,
    ) -> Alert:
        """Construct a structured Alert with contextual metadata.

        Args:
            trigger_event: The event that triggered or completed the detection.
            matched_indicators: List of specific behavioral indicators matched.
            matched_events: All events involved in the detection (single or multi-event).
            additional_context: Optional dictionary of correlation context.

        Returns:
            Populated Alert instance.
        """
        all_events = matched_events or [trigger_event]

        # Generate a chronological timeline context for correlated events
        timeline = [
            {
                "event_id": ev.event_id,
                "timestamp": ev.timestamp,
                "pid": ev.pid,
                "image": ev.image_name,
                "command_line": ev.command_line,
                "user": ev.user,
            }
            for ev in all_events
        ]

        context: dict[str, Any] = {
            "is_sequential": len(all_events) > 1,
            "event_count": len(all_events),
            "timeline": timeline,
            **(additional_context or {}),
        }

        return Alert(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=trigger_event,
            matched_indicators=matched_indicators,
            timestamp=datetime.now(timezone.utc).isoformat(),
            context=context,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.rule_id!r} name={self.name!r} severity={self.severity}>"
