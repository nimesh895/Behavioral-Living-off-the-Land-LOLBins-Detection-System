"""Polling-based process creation collector using psutil and Windows API."""

from collections.abc import Iterator
from datetime import datetime, timezone
import logging
import platform
import time

import psutil

from utils.models import ProcessEvent

logger = logging.getLogger("lolbins-detector.collector.psutil")

# Detect pywin32 security API for exact token integrity level queries
HAS_WIN32_SECURITY = False
if platform.system() == "Windows":
    try:
        import win32api
        import win32con
        import win32security

        HAS_WIN32_SECURITY = True
    except ImportError:
        HAS_WIN32_SECURITY = False


class PsutilCollector:
    """Fallback collector that monitors new process creations via polling."""

    def __init__(
        self,
        poll_interval: float = 1.0,
        ignore_images: set[str] | None = None,
    ) -> None:
        """Initialize the psutil process collector.

        Args:
            poll_interval: Seconds between successive process table scans.
            ignore_images: Set of lowercased executable names to ignore.
        """
        self.poll_interval = max(0.1, poll_interval)
        self.ignore_images = ignore_images or set()
        self._running = False

    def stop(self) -> None:
        """Signal the polling loop to stop."""
        self._running = False

    def stream_events(self) -> Iterator[ProcessEvent]:
        """Continuously poll process table and yield ProcessEvents for newly created processes."""
        self._running = True

        # Establish baseline of currently active PIDs so existing processes are not re-alerted
        seen_pids: set[int] = set()
        for p in psutil.process_iter(["pid"]):
            try:
                seen_pids.add(p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        logger.info(
            "Initialized psutil process collector (baseline: %d active processes, poll interval: %.1fs)",
            len(seen_pids),
            self.poll_interval,
        )

        while self._running:
            current_pids: set[int] = set()
            new_events: list[ProcessEvent] = []

            for proc in psutil.process_iter(
                ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
            ):
                if not self._running:
                    break

                try:
                    pid = proc.pid
                    current_pids.add(pid)

                    if pid in seen_pids:
                        continue

                    event = self._extract_process_event(proc)
                    if event and event.image_name not in self.ignore_images:
                        new_events.append(event)

                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except psutil.AccessDenied as exc:
                    logger.debug("Access denied reading process %s: %s", getattr(proc, "pid", "unknown"), exc)
                    continue
                except Exception as exc:
                    logger.debug("Error inspecting process: %s", exc)
                    continue

            # Update active PIDs set
            seen_pids = current_pids

            for event in new_events:
                yield event

            if not self._running:
                break

            time.sleep(self.poll_interval)

        logger.info("psutil process collector stopped.")

    def _extract_process_event(self, proc: psutil.Process) -> ProcessEvent | None:
        """Safely extract all available telemetry fields from a psutil.Process instance."""
        try:
            pid = proc.pid
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

        # Resolve executable image path
        image = "UNKNOWN"
        try:
            image = proc.exe() or proc.name() or "UNKNOWN"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            try:
                image = proc.name() or "UNKNOWN"
            except Exception:
                image = f"Process_{pid}"

        # Resolve command line
        command_line = image
        try:
            cmdline_parts = proc.cmdline()
            if cmdline_parts:
                command_line = " ".join(cmdline_parts)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            command_line = image

        # Resolve PPID
        ppid = 0
        try:
            ppid = proc.ppid()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            ppid = 0

        # Resolve username
        user = "UNKNOWN"
        try:
            user = proc.username() or "UNKNOWN"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            user = "UNKNOWN"

        # Resolve process creation time
        creation_time_str = datetime.now(timezone.utc).isoformat()
        try:
            create_time_epoch = proc.create_time()
            if create_time_epoch > 0:
                creation_dt = datetime.fromtimestamp(create_time_epoch, tz=timezone.utc)
                creation_time_str = creation_dt.isoformat()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        # Resolve parent image
        parent_image = self._resolve_parent_image(ppid)

        # Resolve process integrity level
        integrity_level = self._resolve_integrity_level(pid, user)

        # Resolve PE metadata (OriginalFilename) for binary masquerading detection
        original_file_name = self._resolve_pe_original_filename(image)

        return ProcessEvent(
            pid=pid,
            ppid=ppid,
            image=image,
            command_line=command_line,
            user=user,
            parent_image=parent_image,
            integrity_level=integrity_level,
            creation_time=creation_time_str,
            timestamp=creation_time_str,
            original_file_name=original_file_name,
        )

    @staticmethod
    def _resolve_pe_original_filename(image_path: str) -> str:
        """Attempt to extract PE OriginalFilename metadata using Windows API."""
        if not HAS_WIN32_SECURITY or not image_path or image_path == "UNKNOWN":
            return ""
        try:
            import win32api
            trans = win32api.GetFileVersionInfo(image_path, "\\VarFileInfo\\Translation")
            if trans:
                lang, codepage = trans[0]
                key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\OriginalFilename"
                orig_name = win32api.GetFileVersionInfo(image_path, key)
                return str(orig_name).strip() if orig_name else ""
        except Exception:
            pass
        return ""

    @staticmethod
    def _resolve_parent_image(ppid: int) -> str:
        """Attempt to resolve parent process executable path or name from its PID."""
        if ppid <= 0:
            return "System"
        try:
            parent = psutil.Process(ppid)
            return parent.exe() or parent.name() or f"PID_{ppid}"
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return f"PID_{ppid}"
        except Exception:
            return "UNKNOWN"

    @classmethod
    def _resolve_integrity_level(cls, pid: int, user: str) -> str:
        """Determine process integrity level via Windows Token API or heuristic account inference."""
        if HAS_WIN32_SECURITY and pid > 0:
            token_level = cls._query_win32_token_integrity(pid)
            if token_level != "Unknown":
                return token_level

        # Fallback heuristic inference from account context
        return cls._infer_integrity_level_from_user(user)

    @staticmethod
    def _query_win32_token_integrity(pid: int) -> str:
        """Query process token integrity level using the Windows Security API."""
        try:
            # Request PROCESS_QUERY_LIMITED_INFORMATION to maximize success without debug privileges
            h_process = win32api.OpenProcess(
                win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            try:
                h_token = win32security.OpenProcessToken(
                    h_process, win32con.TOKEN_QUERY
                )
                try:
                    sid, _ = win32security.GetTokenInformation(
                        h_token, win32security.TokenIntegrityLevel
                    )
                    count = win32security.GetSubAuthorityCount(sid)
                    rid = win32security.GetSubAuthority(sid, count - 1)

                    if rid >= 0x4000:
                        return "System"
                    elif rid >= 0x3000:
                        return "High"
                    elif rid >= 0x2000:
                        return "Medium"
                    elif rid >= 0x1000:
                        return "Low"
                    return "Untrusted"
                finally:
                    win32api.CloseHandle(h_token)
            finally:
                win32api.CloseHandle(h_process)
        except Exception:
            return "Unknown"

    @staticmethod
    def _infer_integrity_level_from_user(username: str) -> str:
        """Infer estimated integrity level based on username string."""
        upper_user = username.upper()
        if (
            "SYSTEM" in upper_user
            or "LOCAL SERVICE" in upper_user
            or "NETWORK SERVICE" in upper_user
        ):
            return "System"
        if "ADMIN" in upper_user:
            return "High"
        return "Medium"
