"""Example Python implementation of a custom single-event rule with correlation state lookup.

Demonstrates inspecting process ancestry from the short-term correlation state.
"""

from engine.base import BaseRule
from engine.state import CorrelationState
from utils.models import Alert, ProcessEvent, Severity


class SuspiciousBrowserSpawnRule(BaseRule):
    """Detects web browsers spawning LOLBins or command line shells.

    Utilizes the correlation state's process lineage tracking to detect deep
    descendant executions even when intermediate helper binaries are invoked.
    """

    _BROWSER_IMAGES: set[str] = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
    }
    _TARGET_LOLBINS: set[str] = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
    }

    def __init__(self) -> None:
        super().__init__(
            rule_id="PY-LIN-001",
            name="Browser Spawning Interactive Shell or LOLBin",
            description=(
                "Detects a web browser process (or descendant) spawning a command shell "
                "or LOLBin scripting utility, indicating potential remote code execution."
            ),
            severity=Severity.HIGH,
            mitre_attack=["T1204.001", "T1059"],
            enabled=True,
        )

    def evaluate(
        self, event: ProcessEvent, state: CorrelationState
    ) -> Alert | None:
        """Evaluate if the event or any of its recorded ancestors originate from a web browser."""
        if event.image_name not in self._TARGET_LOLBINS:
            return None

        # Check immediate parent
        if event.parent_image_name in self._BROWSER_IMAGES:
            return self.create_alert(
                trigger_event=event,
                matched_indicators=[
                    f"direct_parent={event.parent_image_name}",
                    f"target_child={event.image_name}",
                ],
                matched_events=[event],
                additional_context={
                    "detection_type": "lineage",
                    "originating_browser": event.parent_image_name,
                },
            )

        # Check ancestors recorded in the short-term correlation state
        ancestors = state.get_process_ancestors(event.pid)
        for ancestor in ancestors:
            if ancestor.image_name in self._BROWSER_IMAGES:
                return self.create_alert(
                    trigger_event=event,
                    matched_indicators=[
                        f"ancestor_browser={ancestor.image_name}",
                        f"target_child={event.image_name}",
                    ],
                    matched_events=[ancestor, event],
                    additional_context={
                        "detection_type": "lineage_deep",
                        "ancestor_pid": ancestor.pid,
                        "originating_browser": ancestor.image_name,
                    },
                )

        return None


RULES = [SuspiciousBrowserSpawnRule()]
