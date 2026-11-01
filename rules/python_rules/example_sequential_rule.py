"""Example Python implementation of a sequential (multi-event) correlation rule.

Demonstrates how to write modular, testable Python detection rules by subclassing
SequentialRule or BaseRule and leveraging the engine's short-term correlation state.
"""

from engine.sequential import SequenceStage, SequentialRule
from utils.models import ProcessEvent, Severity


class CertutilToRegsvr32PipelineRule(SequentialRule):
    """Detects certutil downloading a remote resource followed by regsvr32 loading a COM scriptlet."""

    def __init__(self) -> None:
        stages = [
            SequenceStage(
                name="Stage 1: Ingress Download Cradle",
                target_images=["certutil.exe"],
                command_line_contains_any=["-urlcache", "/urlcache", "-split"],
            ),
            SequenceStage(
                name="Stage 2: Squiblydoo Proxy Execution",
                target_images=["regsvr32.exe"],
                command_line_contains_any=["scrobj.dll", "/i:http", "-i:http"],
            ),
        ]

        super().__init__(
            rule_id="PY-SEQ-001",
            name="Certutil Download Followed by Regsvr32 Squiblydoo Execution",
            description=(
                "Detects a sequence where certutil.exe is used to fetch a remote file, "
                "followed by regsvr32.exe loading a COM scriptlet under the same user session."
            ),
            severity=Severity.CRITICAL,
            stages=stages,
            mitre_attack=["T1105", "T1218.010"],
            correlation_key_type="user",
            within_seconds=300.0,
            enabled=True,
        )


# Export the rule so the loader can register it directly
RULES = [CertutilToRegsvr32PipelineRule()]
