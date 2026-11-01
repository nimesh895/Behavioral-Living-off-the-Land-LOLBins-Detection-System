# lolbins-detector

A modular Windows Behavioral Living-off-the-Land (LOLBins) Detection System built for Python 3.12+.

## Features

- **Telemetry Collector**:
  - Prefers **Sysmon Event ID 1** (Process Creation) via Windows Event Log API (`Microsoft-Windows-Sysmon/Operational`).
  - Automatically detects Sysmon availability and channel permissions; falls back gracefully to polling via `psutil`.
  - Captures: `PID`, `PPID`, `Image`, `CommandLine`, `User`, `ParentImage`, `CreationTime`, and `IntegrityLevel` (via Win32 Security Token API or heuristic account context).
  - Handles permissions (`AccessDenied`, missing debug privileges) on a per-process level without crashing.
  - Automatically persists all process events directly into SQLite.
  - Continuous execution until interrupted or signaled to stop.
- **Behavioral Detection Engine**:
  - Rules mapped to MITRE ATT&CK techniques (T1105, T1140, T1059, T1218, T1197, T1047, etc.).
  - Obfuscation heuristics for command lines (excessive carets/backticks, encoded Base64 strings, environment variable slicing).
- **Storage & Reporting**:
  - SQLite backend with WAL mode and foreign key constraints.
  - Formatted console alert banners and JSONL alert file output.

## Project Structure

```text
lolbins-detector/
├── collector/
│   ├── __init__.py             # Collector exports
│   ├── process_collector.py    # High-level orchestrator (auto Sysmon + psutil fallback)
│   ├── sysmon_collector.py     # Sysmon Event ID 1 subscriber and XML parser
│   └── psutil_collector.py     # psutil polling with Win32 Token Integrity inspection
├── engine/
│   ├── __init__.py
│   └── detector.py             # Behavioral rule matching & command-line obfuscation heuristics
├── rules/
│   ├── __init__.py
│   ├── loader.py               # YAML rule parser and validator
│   └── definitions/
│       └── core_lolbins.yaml   # Behavioral detection rules mapped to MITRE ATT&CK
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

## Requirements & Installation

Requires **Python 3.12+**.

```bash
pip install -r requirements.txt
```

## Usage

### Run with Automatic Collector Selection (Sysmon -> psutil fallback)
```bash
python main.py
```

### Force a Specific Collector Mode
```bash
# Force Sysmon Event ID 1 collection
python main.py --mode sysmon

# Force psutil polling collection
python main.py --mode psutil_polling

# Run simulated mock events for test verification
python main.py --mode mock
```

### View Database Event and Alert Counts
```bash
python main.py --stats
```
