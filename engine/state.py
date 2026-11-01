"""Short-term correlation state and sliding window manager for LOLBins detection."""

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import time

from utils.models import ProcessEvent

logger = logging.getLogger("lolbins-detector.engine.state")


@dataclass(slots=True)
class SequenceTrack:
    """Tracks the state of an in-flight multi-event detection sequence."""

    rule_id: str
    correlation_key: str
    matched_events: list[ProcessEvent] = field(default_factory=list)
    current_stage_index: int = 0
    started_at: float = field(default_factory=time.time)
    expires_at: float = 0.0

    @property
    def is_expired(self) -> bool:
        """Check whether this sequence track has exceeded its time window."""
        return time.time() > self.expires_at


class CorrelationState:
    """Maintains a sliding window of recent process creation events and active sequence tracks."""

    def __init__(self, window_seconds: float = 600.0) -> None:
        """Initialize correlation state with a short-term sliding window.

        Args:
            window_seconds: Duration in seconds to retain historical events (default: 600s / 10 min).
        """
        self.window_seconds = max(60.0, window_seconds)

        # Chronological queue: (epoch_timestamp, event)
        self._history: deque[tuple[float, ProcessEvent]] = deque()

        # Fast lookup indexes
        self._user_index: dict[str, list[ProcessEvent]] = defaultdict(list)
        self._pid_index: dict[int, ProcessEvent] = {}
        self._image_index: dict[str, list[ProcessEvent]] = defaultdict(list)

        # In-flight sequence tracking for multi-event rules: (rule_id, correlation_key) -> SequenceTrack
        self._sequence_tracks: dict[tuple[str, str], SequenceTrack] = {}

    def add_event(self, event: ProcessEvent) -> None:
        """Record an incoming process event into the sliding window and indexes.

        Args:
            event: The ProcessEvent to record.
        """
        epoch = self._parse_event_epoch(event)
        self._history.append((epoch, event))

        # Update indexes
        self._user_index[event.user.upper()].append(event)
        self._pid_index[event.pid] = event
        self._image_index[event.image_name].append(event)

        # Prune expired items
        self.evict_expired(epoch)

    def get_recent_events_by_user(
        self, user: str, within_seconds: float | None = None
    ) -> list[ProcessEvent]:
        """Retrieve recent events associated with a specific user account.

        Args:
            user: Username string.
            within_seconds: Lookback limit in seconds. Defaults to correlation window.

        Returns:
            List of matching ProcessEvent instances within the timeframe.
        """
        max_age = within_seconds or self.window_seconds
        now = time.time()
        events = self._user_index.get(user.upper(), [])
        return [
            ev
            for ev in events
            if (now - self._parse_event_epoch(ev)) <= max_age
        ]

    def get_process_ancestors(
        self, pid: int, max_depth: int = 5
    ) -> list[ProcessEvent]:
        """Trace known process lineage ancestors within the current sliding window.

        Args:
            pid: Child process ID.
            max_depth: Maximum hierarchy levels to traverse.

        Returns:
            List of ancestor ProcessEvent instances, starting from immediate parent upwards.
        """
        ancestors: list[ProcessEvent] = []
        curr_pid = pid
        visited: set[int] = {pid}

        for _ in range(max_depth):
            current_event = self._pid_index.get(curr_pid)
            if not current_event or current_event.ppid <= 0:
                break

            parent_pid = current_event.ppid
            if parent_pid in visited:
                break  # Cycle detection

            parent_event = self._pid_index.get(parent_pid)
            if not parent_event:
                break

            ancestors.append(parent_event)
            visited.add(parent_pid)
            curr_pid = parent_pid

        return ancestors

    def find_recent_events(
        self,
        image_name: str | None = None,
        within_seconds: float | None = None,
        predicate: Callable[[ProcessEvent], bool] | None = None,
    ) -> list[ProcessEvent]:
        """Search the sliding window for events matching an image name or predicate.

        Args:
            image_name: Optional lowercased executable name (e.g. 'certutil.exe').
            within_seconds: Optional lookback duration.
            predicate: Optional filter callable returning bool.

        Returns:
            List of matching ProcessEvent instances.
        """
        max_age = within_seconds or self.window_seconds
        now = time.time()

        candidates: list[ProcessEvent]
        if image_name:
            candidates = self._image_index.get(image_name.lower(), [])
        else:
            candidates = [ev for _, ev in self._history]

        results: list[ProcessEvent] = []
        for ev in candidates:
            if (now - self._parse_event_epoch(ev)) <= max_age:
                if predicate is None or predicate(ev):
                    results.append(ev)
        return results

    def get_sequence_track(
        self, rule_id: str, correlation_key: str
    ) -> SequenceTrack | None:
        """Retrieve an active sequence tracking state for a given rule and correlation key."""
        track = self._sequence_tracks.get((rule_id, correlation_key))
        if track and track.is_expired:
            del self._sequence_tracks[(rule_id, correlation_key)]
            return None
        return track

    def set_sequence_track(self, track: SequenceTrack) -> None:
        """Store or update an active sequence tracking state."""
        self._sequence_tracks[(track.rule_id, track.correlation_key)] = track

    def clear_sequence_track(self, rule_id: str, correlation_key: str) -> None:
        """Remove a completed or discarded sequence tracking state."""
        self._sequence_tracks.pop((rule_id, correlation_key), None)

    def evict_expired(self, current_epoch: float | None = None) -> None:
        """Evict events and sequence tracks older than the correlation window."""
        now = current_epoch or time.time()
        cutoff = now - self.window_seconds

        # Evict from chronological deque
        while self._history and self._history[0][0] < cutoff:
            _, old_event = self._history.popleft()

            # Clean indexes
            user_list = self._user_index.get(old_event.user.upper())
            if user_list and old_event in user_list:
                user_list.remove(old_event)

            img_list = self._image_index.get(old_event.image_name)
            if img_list and old_event in img_list:
                img_list.remove(old_event)

            if self._pid_index.get(old_event.pid) == old_event:
                del self._pid_index[old_event.pid]

        # Evict expired sequence tracks
        expired_track_keys = [
            k for k, track in self._sequence_tracks.items() if track.is_expired
        ]
        for key in expired_track_keys:
            del self._sequence_tracks[key]

    @staticmethod
    def _parse_event_epoch(event: ProcessEvent) -> float:
        """Convert ISO 8601 event timestamp or creation time into a Unix epoch float."""
        raw = event.creation_time or event.timestamp
        try:
            # Handle standard ISO formats (including trailing 'Z')
            clean = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return dt.timestamp()
        except Exception:
            return time.time()
