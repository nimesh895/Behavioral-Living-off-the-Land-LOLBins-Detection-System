"""Python implementations of multi-stage sequential attack chain detection rules."""

import re

from engine.sequential import SequenceStage, SequentialRule
from utils.models import ProcessEvent, Severity


class DownloadThenExecuteChainRule(SequentialRule):
    """Detects a download cradle (certutil, bitsadmin, or PowerShell) followed by payload execution."""

    def __init__(self) -> None:
        stages = [
            SequenceStage(
                name="Stage 1: Remote Payload Download",
                target_images=["certutil.exe", "bitsadmin.exe", "powershell.exe", "pwsh.exe"],
                command_line_contains_any=[
                    "-urlcache",
                    "/urlcache",
                    "/transfer",
                    "-transfer",
                    "/addfile",
                    "-addfile",
                    "downloadstring",
                    "downloadfile",
                    "invoke-webrequest",
                    "iwr ",
                    "net.webclient",
                ],
                command_line_regex=[re.compile(r"(?i)https?://")],
            ),
            SequenceStage(
                name="Stage 2: Staged Payload or Proxy Execution",
                target_images=[
                    "mshta.exe",
                    "regsvr32.exe",
                    "rundll32.exe",
                    "cscript.exe",
                    "wscript.exe",
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "wmic.exe",
                ],
                command_line_regex=[
                    re.compile(
                        r"(?i)(appdata|temp|programdata|users\\public|downloads).*"
                        r"(payload|update|stage|script|backdoor|setup|drop|\.exe|\.dll|\.bat|\.ps1|\.vbs|\.js|\.hta|\.sct)"
                    ),
                    re.compile(r"(?i)(javascript|vbscript):"),
                    re.compile(r"(?i)[-/]i:https?://"),
                    re.compile(r"(?i)scrobj\.dll"),
                ],
            ),
        ]

        super().__init__(
            rule_id="PY-CHAIN-001",
            name="Python Chain: LOLBin Download Cradle Followed by Payload Execution",
            description=(
                "Correlates network ingress transfers via certutil, bitsadmin, or PowerShell "
                "with subsequent payload execution by the same user within 5 minutes."
            ),
            severity=Severity.CRITICAL,
            stages=stages,
            mitre_attack=["T1105", "T1204.002", "T1218"],
            correlation_key_type="user",
            within_seconds=300.0,
            enabled=True,
        )


class EncodedPowerShellAfterLOLBinRule(SequentialRule):
    """Detects native LOLBin execution followed by encoded PowerShell within 3 minutes."""

    def __init__(self) -> None:
        stages = [
            SequenceStage(
                name="Stage 1: Initial LOLBin Staging",
                target_images=[
                    "certutil.exe",
                    "bitsadmin.exe",
                    "mshta.exe",
                    "regsvr32.exe",
                    "rundll32.exe",
                    "wmic.exe",
                    "cscript.exe",
                    "wscript.exe",
                    "msiexec.exe",
                    "installutil.exe",
                    "forfiles.exe",
                    "pcalua.exe",
                ],
            ),
            SequenceStage(
                name="Stage 2: Encoded PowerShell Invocation",
                target_images=["powershell.exe", "pwsh.exe"],
                command_line_contains_any=["-enc", "-encodedcommand", "frombase64string"],
                command_line_regex=[
                    re.compile(r"(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{8,}"),
                ],
            ),
        ]

        super().__init__(
            rule_id="PY-CHAIN-002",
            name="Python Chain: Encoded PowerShell Invocation Following LOLBin",
            description=(
                "Detects a LOLBin staging step followed by an obfuscated, encoded "
                "PowerShell execution under the same user session within 3 minutes."
            ),
            severity=Severity.CRITICAL,
            stages=stages,
            mitre_attack=["T1059.001", "T1027", "T1218"],
            correlation_key_type="user",
            within_seconds=180.0,
            enabled=True,
        )


class CascadingShellLOLBinChainRule(SequentialRule):
    """Detects process tree cascade: cmd.exe -> powershell.exe -> LOLBin."""

    def __init__(self) -> None:
        stages = [
            SequenceStage(
                name="Stage 1: Command Interpreter (cmd.exe)",
                target_images=["cmd.exe"],
            ),
            SequenceStage(
                name="Stage 2: Intermediate Shell (powershell.exe)",
                target_images=["powershell.exe", "pwsh.exe"],
                suspicious_parents=["cmd.exe"],
            ),
            SequenceStage(
                name="Stage 3: Downstream LOLBin Invocation",
                target_images=[
                    "mshta.exe",
                    "regsvr32.exe",
                    "rundll32.exe",
                    "certutil.exe",
                    "bitsadmin.exe",
                    "wmic.exe",
                    "cscript.exe",
                    "wscript.exe",
                    "msiexec.exe",
                ],
                suspicious_parents=["powershell.exe", "pwsh.exe"],
            ),
        ]

        super().__init__(
            rule_id="PY-CHAIN-003",
            name="Python Chain: Cascading Process Tree (cmd.exe -> powershell.exe -> LOLBin)",
            description=(
                "Detects multi-hop process tree progression where cmd.exe spawns powershell.exe, "
                "which in turn spawns another native LOLBin within 3 minutes along the same lineage."
            ),
            severity=Severity.HIGH,
            stages=stages,
            mitre_attack=["T1059.003", "T1059.001", "T1218"],
            correlation_key_type="process_tree",
            within_seconds=180.0,
            enabled=True,
        )


# Export rule instances for automated dynamic discovery
RULES = [
    DownloadThenExecuteChainRule(),
    EncodedPowerShellAfterLOLBinRule(),
    CascadingShellLOLBinChainRule(),
]
