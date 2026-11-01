"""Timeline reconstruction and contextual event correlation around alerts."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import logging
from typing import Any

from storage.database import DatabaseManager
from utils.models import Alert, ProcessEvent

logger = logging.getLogger("lolbins-detector.output.timeline")


@dataclass(slots=True)
class TimelineEntry:
    """Represents a single contextual event within an alert timeline."""

    event_id: str
    timestamp: str
    delta_seconds: float
    delta_display: str
    relationship: str
    pid: int
    ppid: int
    image: str
    parent_image: str
    command_line: str
    user: str
    integrity_level: str

    def to_dict(self) -> dict[str, Any]:
        """Convert entry into serializable dictionary."""
        return asdict(self)


class TimelineReconstructor:
    """Reconstructs historical and concurrent process execution timelines surrounding an alert."""

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        default_window_seconds: float = 300.0,
    ) -> None:
        """Initialize the timeline reconstructor.

        Args:
            db_manager: Optional DatabaseManager to fetch historical events from SQLite.
            default_window_seconds: Lookback/lookahead window in seconds (default: 300s / 5 min, up to 600s / 10 min).
        """
        self.db_manager = db_manager
        self.default_window_seconds = max(60.0, default_window_seconds)

    def reconstruct_timeline(
        self,
        alert: Alert,
        window_seconds: float | None = None,
        candidate_events: list[ProcessEvent] | None = None,
    ) -> list[TimelineEntry]:
        """Reconstruct chronological timeline around an alert within ± window_seconds.

        Args:
            alert: The triggered security Alert.
            window_seconds: Optional window override in seconds (e.g. 300s to 600s).
            candidate_events: Optional list of in-memory events to supplement database events.

        Returns:
            Chronologically sorted list of TimelineEntry objects.
        """
        window = window_seconds or self.default_window_seconds
        trigger_epoch = self._parse_epoch(alert.event.timestamp)

        # 1. Collect candidate events
        event_map: dict[str, ProcessEvent] = {}

        # Add trigger event explicitly
        event_map[alert.event.event_id] = alert.event

        # Query database if available
        if self.db_manager is not None:
            db_events = self.db_manager.get_events_around_timestamp(
                target_timestamp=alert.event.timestamp,
                window_seconds=window,
            )
            for ev in db_events:
                event_map[ev.event_id] = ev

        # Add any in-memory candidates (e.g. from sequence matched_events)
        for ev in candidate_events or []:
            event_map[ev.event_id] = ev

        if "timeline" in alert.context:
            for item in alert.context.get("timeline", []):
                ev_id = item.get("event_id")
                if ev_id and ev_id not in event_map:
                    # Construct ProcessEvent stub if missing
                    event_map[ev_id] = ProcessEvent(
                        event_id=ev_id,
                        timestamp=item.get("timestamp", alert.timestamp),
                        pid=item.get("pid", 0),
                        ppid=0,
                        image=item.get("image", "UNKNOWN"),
                        command_line=item.get("command_line", ""),
                        user=item.get("user", alert.event.user),
                    )

        # 2. Build process tree lookup map for relationship categorization
        pid_to_event = {ev.pid: ev for ev in event_map.values()}

        # 3. Categorize and build timeline entries
        entries: list[TimelineEntry] = []
        for ev in event_map.values():
            ev_epoch = self._parse_epoch(ev.timestamp)
            delta_sec = round(ev_epoch - trigger_epoch, 2)
            delta_disp = self._format_delta(delta_sec, ev.event_id == alert.event.event_id)
            rel = self._classify_relationship(ev, alert.event, pid_to_event)

            entry = TimelineEntry(
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                delta_seconds=delta_sec,
                delta_display=delta_disp,
                relationship=rel,
                pid=ev.pid,
                ppid=ev.ppid,
                image=ev.image_name,
                parent_image=ev.parent_image_name,
                command_line=ev.command_line,
                user=ev.user,
                integrity_level=ev.integrity_level,
            )
            entries.append(entry)

        # 4. Sort chronologically by timestamp and delta
        entries.sort(key=lambda x: (x.delta_seconds, x.timestamp))
        return entries

    def build_ascii_process_tree(
        self,
        trigger_event: ProcessEvent,
        timeline_entries: list[TimelineEntry],
    ) -> str:
        """Render a clean text-based process lineage tree for reports and console.

        Args:
            trigger_event: The process creation event that caused the alert.
            timeline_entries: The reconstructed timeline entries.

        Returns:
            ASCII tree diagram string.
        """
        pid_map = {entry.pid: entry for entry in timeline_entries}

        # Build lineage chain upwards from trigger event
        lineage: list[str] = [
            f"{trigger_event.image_name} (PID: {trigger_event.pid}) [TRIGGER]"
        ]
        curr_ppid = trigger_event.ppid

        depth = 0
        while curr_ppid > 0 and depth < 6:
            depth += 1
            parent = pid_map.get(curr_ppid)
            if parent:
                lineage.append(f"{parent.image} (PID: {parent.pid})")
                curr_ppid = parent.ppid
            else:
                lineage.append(f"{trigger_event.parent_image_name} (PID: {curr_ppid})")
                break

        # Reverse so root ancestor is at the top
        lineage.reverse()

        tree_lines = []
        for idx, node in enumerate(lineage):
            prefix = "    " * idx + ("└── " if idx > 0 else "")
            tree_lines.append(f"{prefix}{node}")

        return "\n".join(tree_lines)

    @staticmethod
    def _classify_relationship(
        ev: ProcessEvent, trigger: ProcessEvent, pid_to_event: dict[int, ProcessEvent]
    ) -> str:
        """Classify relationship of an event relative to the trigger process."""
        if ev.event_id == trigger.event_id or ev.pid == trigger.pid:
            return "TRIGGER"
        if ev.pid == trigger.ppid:
            return "PARENT"
        if ev.ppid == trigger.pid:
            return "CHILD"
        if ev.ppid == trigger.ppid and ev.ppid > 0:
            return "SIBLING"

        # Check if ancestor
        curr = trigger.ppid
        for _ in range(5):
            if curr <= 0:
                break
            if ev.pid == curr:
                return "ANCESTOR"
            parent = pid_to_event.get(curr)
            curr = parent.ppid if parent else 0

        if ev.user.upper() == trigger.user.upper():
            return "SAME_USER"

        return "PROXIMITY"

    @staticmethod
    def _format_delta(delta_sec: float, is_trigger: bool) -> str:
        """Format numeric delta seconds into readable human string."""
        if is_trigger or abs(delta_sec) < 0.05:
            return "TRIGGER"

        sign = "+" if delta_sec > 0 else "-"
        abs_sec = int(abs(delta_sec))
        minutes = abs_sec // 60
        seconds = abs_sec % 60
        return f"{sign}{minutes:02d}m {seconds:02d}s"

    @staticmethod
    def _parse_epoch(timestamp_str: str) -> float:
        """Parse ISO timestamp to epoch float."""
        try:
            clean = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return dt.timestamp()
        except Exception:
            return datetime.now(timezone.utc).timestamp()
