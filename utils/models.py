"""Data models for process creation events and detection alerts."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
import uuid


class Severity(StrEnum):
    """Alert severity levels ordered from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def weight(cls, severity: "Severity | str") -> int:
        """Return numeric weight for severity comparison."""
        mapping = {
            cls.LOW: 1,
            cls.MEDIUM: 2,
            cls.HIGH: 3,
            cls.CRITICAL: 4,
        }
        return mapping.get(Severity(severity.lower()), 0)


@dataclass(slots=True)
class ProcessEvent:
    """Represents a Windows process creation event."""

    pid: int
    ppid: int
    image: str
    command_line: str
    user: str = "UNKNOWN"
    parent_image: str = "UNKNOWN"
    integrity_level: str = "Medium"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def image_name(self) -> str:
        """Extract the executable filename in lowercase (e.g., 'certutil.exe')."""
        normalized = self.image.replace("/", "\\")
        return normalized.rsplit("\\", maxsplit=1)[-1].lower()

    @property
    def parent_image_name(self) -> str:
        """Extract the parent executable filename in lowercase."""
        normalized = self.parent_image.replace("/", "\\")
        return normalized.rsplit("\\", maxsplit=1)[-1].lower()

    def to_dict(self) -> dict[str, Any]:
        """Convert the process event into a serializable dictionary."""
        return asdict(self)


@dataclass(slots=True)
class Alert:
    """Represents a security alert triggered by a detection rule."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    mitre_attack: list[str]
    event: ProcessEvent
    matched_indicators: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Convert the alert and its nested event into a dictionary."""
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data
