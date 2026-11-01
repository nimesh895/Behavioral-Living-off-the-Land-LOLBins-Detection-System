# lolbins-detector

A modular Windows Behavioral Living-off-the-Land (LOLBins) Detection System built for Python 3.12+.

## Project Structure

```text
lolbins-detector/
├── collector/
│   ├── __init__.py
│   └── process_collector.py    # Real-time WMI, psutil polling, and mock event collectors
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

Run with default configuration (`config.yaml`):
```bash
python main.py
```

Run in simulated `mock` mode to verify rules, alerting, and SQLite persistence:
```bash
python main.py --mode mock
```

View stored event and alert statistics from the SQLite database:
```bash
python main.py --stats
```
