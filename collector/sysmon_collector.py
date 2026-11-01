"""Sysmon Event ID 1 (Process Creation) collector for Windows Event Log."""

from collections.abc import Iterator
from datetime import datetime, timezone
import logging
import platform
from typing import Any
import xml.etree.ElementTree as ET

from utils.models import ProcessEvent

logger = logging.getLogger("lolbins-detector.collector.sysmon")

# Detect pywin32 availability
HAS_WIN32_EVENT_LOG = False
if platform.system() == "Windows":
    try:
        import pywintypes
        import win32api
        import win32con
        import win32event
        import win32evtlog

        HAS_WIN32_EVENT_LOG = True
    except ImportError:
        HAS_WIN32_EVENT_LOG = False


class SysmonCollector:
    """Collects real-time process creation events from Sysmon Event ID 1."""

    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
    EVENT_ID_PROCESS_CREATE = 1

    def __init__(
        self,
        channel: str = SYSMON_CHANNEL,
        poll_interval: float = 1.0,
        ignore_images: set[str] | None = None,
    ) -> None:
        """Initialize Sysmon collector.

        Args:
            channel: Windows Event Log channel path for Sysmon.
            poll_interval: Timeout in seconds for signal wait intervals.
            ignore_images: Set of lowercased executable filenames to ignore.
        """
        self.channel = channel
        self.poll_interval = poll_interval
        self.ignore_images = ignore_images or set()
        self._running = False
        self._signal_event: Any = None

    @classmethod
    def is_available(cls, channel: str = SYSMON_CHANNEL) -> tuple[bool, str]:
        """Verify whether Sysmon is installed, operational, and accessible.

        Returns:
            Tuple of (is_available, status_or_error_message).
        """
        if platform.system() != "Windows":
            return False, f"Unsupported operating system '{platform.system()}'; Sysmon requires Windows."

        if not HAS_WIN32_EVENT_LOG:
            return False, "pywin32 (win32evtlog) is not installed in the current environment."

        try:
            flags = (
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryReverseDirection
            )
            # Test query for Event ID 1 to verify channel registration and read permissions
            handle = win32evtlog.EvtQuery(
                channel,
                flags,
                f"*[System[(EventID={cls.EVENT_ID_PROCESS_CREATE})]]",
                None,
            )
            if handle:
                try:
                    win32api.CloseHandle(handle)
                except Exception:
                    pass
                return True, f"Sysmon channel '{channel}' is operational and accessible."
            return False, f"Failed to acquire query handle for channel '{channel}'."

        except pywintypes.error as exc:
            win_err = exc.winerror if hasattr(exc, "winerror") else exc.args[0]
            err_msg = exc.strerror if hasattr(exc, "strerror") else str(exc)

            if win_err == 15007:  # ERROR_EVT_CHANNEL_NOT_FOUND
                return (
                    False,
                    f"Sysmon channel '{channel}' was not found. "
                    "Sysmon is either not installed or disabled.",
                )
            elif win_err == 5:  # ERROR_ACCESS_DENIED
                return (
                    False,
                    f"Access denied reading Sysmon channel '{channel}'. "
                    "Elevated Administrator privileges or 'Event Log Readers' group membership required.",
                )
            return False, f"WinEventLog error querying '{channel}': {err_msg} (Error Code {win_err})"

        except Exception as exc:
            return False, f"Unexpected error checking Sysmon availability: {exc}"

    def stop(self) -> None:
        """Signal the Sysmon event subscription loop to stop."""
        self._running = False
        if HAS_WIN32_EVENT_LOG and self._signal_event is not None:
            try:
                win32event.SetEvent(self._signal_event)
            except Exception:
                pass

    def stream_events(self) -> Iterator[ProcessEvent]:
        """Stream real-time process creation events by subscribing to Sysmon Event ID 1."""
        if not HAS_WIN32_EVENT_LOG:
            logger.error("pywin32 is not available; cannot start Sysmon subscription.")
            return

        available, reason = self.is_available(self.channel)
        if not available:
            logger.warning("Sysmon is unavailable: %s", reason)
            return

        query_xpath = f"*[System[(EventID={self.EVENT_ID_PROCESS_CREATE})]]"
        sub_handle = None
        self._running = True

        try:
            self._signal_event = win32event.CreateEvent(None, False, False, None)
            sub_handle = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=self._signal_event,
                Query=query_xpath,
            )
            logger.info("Subscribed to Sysmon Event ID 1 on '%s'", self.channel)

            wait_timeout_ms = max(500, int(self.poll_interval * 1000))

            while self._running:
                wait_result = win32event.WaitForSingleObject(
                    self._signal_event, wait_timeout_ms
                )
                if not self._running:
                    break

                if wait_result == win32event.WAIT_OBJECT_0:
                    yield from self._drain_events(sub_handle)
                elif wait_result == win32event.WAIT_TIMEOUT:
                    continue
                else:
                    logger.debug("Sysmon signal wait returned: %s", wait_result)

        except pywintypes.error as exc:
            win_err = exc.winerror if hasattr(exc, "winerror") else exc.args[0]
            err_msg = exc.strerror if hasattr(exc, "strerror") else str(exc)
            logger.error(
                "Sysmon subscription error (%d): %s. Stopping Sysmon stream.",
                win_err,
                err_msg,
            )
        except Exception as exc:
            logger.exception("Unexpected error in Sysmon event stream: %s", exc)
        finally:
            self._running = False
            if sub_handle is not None:
                try:
                    win32api.CloseHandle(sub_handle)
                except Exception:
                    pass
            if self._signal_event is not None:
                try:
                    win32api.CloseHandle(self._signal_event)
                except Exception:
                    pass
                self._signal_event = None
            logger.info("Sysmon event collector stopped.")

    def _drain_events(self, sub_handle: Any) -> Iterator[ProcessEvent]:
        """Fetch and parse all pending events from the subscription handle."""
        batch_size = 32
        while self._running:
            try:
                events = win32evtlog.EvtNext(sub_handle, batch_size, 0, 0)
            except pywintypes.error as exc:
                win_err = exc.winerror if hasattr(exc, "winerror") else exc.args[0]
                if win_err == 259:  # ERROR_NO_MORE_ITEMS
                    break
                logger.warning("Error reading Sysmon event batch: %s", exc)
                break
            except Exception as exc:
                logger.warning("Unexpected error during EvtNext: %s", exc)
                break

            if not events:
                break

            for event_handle in events:
                try:
                    xml_str = win32evtlog.EvtRender(
                        event_handle, win32evtlog.EvtRenderEventXml
                    )
                    parsed_event = self.parse_sysmon_event_xml(xml_str)
                    if (
                        parsed_event
                        and parsed_event.image_name not in self.ignore_images
                    ):
                        yield parsed_event
                except Exception as exc:
                    logger.debug("Failed to render or parse Sysmon event XML: %s", exc)
                finally:
                    try:
                        win32api.CloseHandle(event_handle)
                    except Exception:
                        pass

    @classmethod
    def parse_sysmon_event_xml(cls, xml_content: str) -> ProcessEvent | None:
        """Parse Sysmon Event ID 1 XML into a structured ProcessEvent.

        Args:
            xml_content: Raw XML string of the event.

        Returns:
            Populated ProcessEvent instance, or None if parsing fails.
        """
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            logger.debug("XML parse error: %s", exc)
            return None

        time_created: str | None = None
        data_fields: dict[str, str] = {}

        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "TimeCreated":
                time_created = elem.get("SystemTime")
            elif tag == "Data":
                name = elem.get("Name")
                if name:
                    data_fields[name] = elem.text or ""

        # Require minimum process identification data
        pid_raw = data_fields.get("ProcessId")
        image = data_fields.get("Image")
        if not pid_raw or not image:
            return None

        try:
            pid = int(pid_raw)
        except ValueError:
            pid = 0

        try:
            ppid = int(data_fields.get("ParentProcessId", 0) or 0)
        except ValueError:
            ppid = 0

        command_line = data_fields.get("CommandLine", "") or image
        user = data_fields.get("User", "UNKNOWN")
        parent_image = data_fields.get("ParentImage", "UNKNOWN")
        integrity_level = data_fields.get("IntegrityLevel", "Medium")

        # Normalize timestamp format
        creation_time_raw = data_fields.get("UtcTime") or time_created
        if creation_time_raw:
            creation_time = creation_time_raw.replace(" ", "T")
            if not creation_time.endswith("Z") and "+" not in creation_time:
                creation_time += "Z"
        else:
            creation_time = datetime.now(timezone.utc).isoformat()

        return ProcessEvent(
            pid=pid,
            ppid=ppid,
            image=image,
            command_line=command_line,
            user=user,
            parent_image=parent_image,
            integrity_level=integrity_level,
            creation_time=creation_time,
            timestamp=creation_time,
        )
