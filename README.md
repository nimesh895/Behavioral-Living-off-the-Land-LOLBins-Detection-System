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
- **Modular Detection Engine**:
  - **Single-Event Rules**: Fast pattern evaluation (images, command lines, regexes, parent images, integrity levels).
  - **Sequential (Multi-Event) Rules**: Detects ordered sequences of correlated actions (e.g. download cradle -> LOLBin execution, recon -> privilege escalation) within a sliding time window.
  - **Short-Term Correlation State**: Maintains a 5–10 minute in-memory sliding window indexed by `user`, `pid` (process lineage/ancestors), and `image`, with automated TTL eviction.
  - **Dual Rule Formats**: Add rules effortlessly via declarative **YAML** files or extensible **Python** rule classes (`BaseRule`, `SingleEventRule`, `SequentialRule`).
  - **Obfuscation Heuristics**: Analyzes command lines for generic living-off-the-land evasion (excessive caret/backtick escaping, encoded payloads, variable slicing).
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
│   ├── state.py                # CorrelationState (short-term 5-10 min sliding window & indexes)
│   ├── single_event.py         # SingleEventRule implementation
│   ├── sequential.py           # SequentialRule & SequenceStage multi-event state machine
│   └── detector.py             # DetectionEngine orchestrating rules & heuristics
├── rules/
│   ├── __init__.py
│   ├── loader.py               # Unified loader for YAML & Python rule files
│   ├── definitions/
│   │   ├── core_lolbins.yaml   # Single-event YAML rules mapped to MITRE ATT&CK
│   │   └── sequential_lolbins.yaml # Multi-event correlation YAML rules
│   └── python_rules/
│       ├── example_sequential_rule.py # Concrete Python SequentialRule implementation
│       └── example_single_rule.py     # Concrete Python BaseRule with lineage inspection
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

## Adding Rules

### 1. YAML Rules
Place `.yaml` files in `rules/`:

**Single-Event Rule:**
```yaml
rules:
  - id: "LOLBIN-001"
    name: "Certutil Remote Payload Download"
    description: "Detects certutil downloading files."
    severity: "high"
    mitre_attack: ["T1105"]
    detection:
      target_images: ["certutil.exe"]
      command_line_contains_any: ["-urlcache", "/urlcache"]
```

**Sequential Multi-Event Rule:**
```yaml
rules:
  - id: "SEQ-001"
    type: "sequential"
    name: "Certutil Download Followed by Mshta Execution"
    description: "Detects download cradle followed by script execution within 5 minutes."
    severity: "critical"
    mitre_attack: ["T1105", "T1218.005"]
    correlation:
      key: "user"
      within_seconds: 300
      stages:
        - name: "Download Cradle"
          target_images: ["certutil.exe"]
          command_line_contains_any: ["-urlcache"]
        - name: "Execution"
          target_images: ["mshta.exe"]
```

### 2. Python Rules
Create a `.py` file under `rules/` subclassing `BaseRule`, `SingleEventRule`, or `SequentialRule`:

```python
from engine.sequential import SequenceStage, SequentialRule
from utils.models import Severity

class CustomSequenceRule(SequentialRule):
    def __init__(self):
        super().__init__(
            rule_id="PY-SEQ-EXAMPLE",
            name="Download to Execution Chain",
            description="Custom Python correlation rule",
            severity=Severity.HIGH,
            stages=[
                SequenceStage(name="Stage 1", target_images=["certutil.exe"]),
                SequenceStage(name="Stage 2", target_images=["regsvr32.exe"]),
            ],
            correlation_key_type="user",
            within_seconds=300.0,
        )

RULES = [CustomSequenceRule()]
```

## Usage

```bash
# Run detection pipeline
python main.py

# Test with simulated single and multi-event telemetry
python main.py --mode mock

# Inspect database statistics
python main.py --stats
```
