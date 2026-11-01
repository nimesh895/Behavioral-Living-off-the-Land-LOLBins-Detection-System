# lolbins-detector

A modular Windows Behavioral Living-off-the-Land (LOLBins) Detection System built for Python 3.12+.

## Key Features

- **Telemetry Collector**:
  - Prefers **Sysmon Event ID 1** (Process Creation) via Windows Event Log API (`Microsoft-Windows-Sysmon/Operational`).
  - Automatically checks Sysmon availability and channel permissions; falls back gracefully to polling via `psutil`.
  - Captures: `PID`, `PPID`, `Image`, `CommandLine`, `User`, `ParentImage`, `CreationTime`, and `IntegrityLevel` (via Win32 Security Token API or heuristic account context).
  - Handles permissions (`AccessDenied`, missing debug privileges) on a per-process level without crashing.
  - Automatically persists all process events directly into SQLite.
  - Continuous execution until interrupted or signaled to stop.
- **Sequential Attack Chain Correlation**:
  - Correlates multi-stage behavioral patterns over a **2–5 minute sliding window**.
  - **Download then Execute Chain**: Correlates ingress transfer via `certutil`, `bitsadmin`, or `powershell` with immediate payload or LOLBin execution.
  - **Encoded PowerShell after LOLBin**: Detects staging via native utilities followed by obfuscated/encoded PowerShell payloads.
  - **Cascading Shell Chain**: Identifies process tree cascades (`cmd.exe` -> `powershell.exe` -> downstream LOLBin).
  - Partitioning across **user accounts** or **process tree lineage**.
- **Single-Event Behavioral Rules**:
  - Office applications spawning native LOLBins (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`).
  - Suspicious `certutil` usage (`-urlcache`, `-decode`, HTTP/HTTPS URLs).
  - Suspicious `bitsadmin` remote transfers (`/transfer`, `/addfile`, external URLs).
  - `mshta` inline script execution (`javascript:`, `vbscript:`, remote `.hta`).
  - `regsvr32` proxy execution patterns (Squiblydoo, `scrobj.dll`, `/i:http:`).
- **Dual Rule Formats**:
  - Declarative **YAML** definitions (`rules/definitions/*.yaml`).
  - Extensible **Python** rule classes (`rules/python_rules/*.py`).
- **Structured Alerts & Storage**:
  - Emits rich alerts with full context: trigger process, matched indicators, correlated multi-event timeline, sequence duration, and MITRE ATT&CK technique IDs.
  - SQLite backend with WAL mode and foreign key constraints.
  - Formatted color console alert banners and JSONL alert file output.

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
├── storage/
│   ├── __init__.py
│   ├── database.py             # SQLite database manager
│   └── schema.sql              # SQLite schema for process_events and alerts
├── output/
│   ├── __init__.py
│   └── notifier.py             # Console alert banners and JSONL alert logging
├── utils/
│   ├── __init__.py
│   ├── config.py               # Typed configuration loader
│   ├── logger.py               # Structured logging setup
│   └── models.py               # Dataclasses for ProcessEvent, Alert, and Severity
├── config.yaml                 # Application configuration
├── requirements.txt            # Python dependencies
└── main.py                     # Application entry point
```

## Usage

```bash
# Run detection pipeline
python main.py

# Test with simulated single-event and sequential attack chains
python main.py --mode mock

# Inspect database event and alert statistics
python main.py --stats
```
