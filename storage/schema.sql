-- SQLite Schema for lolbins-detector
-- Stores process creation telemetry and behavioral LOLBin alerts.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    creation_time TEXT,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    image TEXT NOT NULL,
    command_line TEXT NOT NULL,
    user TEXT NOT NULL,
    parent_image TEXT NOT NULL,
    integrity_level TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_process_events_timestamp ON process_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_process_events_pid ON process_events(pid);
CREATE INDEX IF NOT EXISTS idx_process_events_image ON process_events(image);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    mitre_attack TEXT NOT NULL,        -- JSON array of MITRE technique IDs
    matched_indicators TEXT NOT NULL,  -- JSON array of matched behavioral indicators
    context TEXT DEFAULT '{}',         -- JSON object containing correlation & multi-event context
    event_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    image TEXT NOT NULL,
    command_line TEXT NOT NULL,
    user TEXT NOT NULL,
    parent_image TEXT NOT NULL,
    integrity_level TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES process_events(event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
