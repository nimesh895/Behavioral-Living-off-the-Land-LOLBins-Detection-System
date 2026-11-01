"""SQLite database manager for persisting process events and alerts."""

import json
import logging
from pathlib import Path
import sqlite3
from typing import Any

from utils.models import Alert, ProcessEvent

logger = logging.getLogger("lolbins-detector.storage")


class DatabaseManager:
    """Manages SQLite connections, schema initialization, and event/alert storage."""

    def __init__(self, db_path: str | Path, schema_path: str | Path | None = None) -> None:
        """Initialize the database manager and ensure schema exists.

        Args:
            db_path: Path to the SQLite database file.
            schema_path: Optional path to the SQL schema file. Defaults to storage/schema.sql.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        if schema_path is None:
            self.schema_path = Path(__file__).parent / "schema.sql"
        else:
            self.schema_path = Path(schema_path)

        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a configured SQLite database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _initialize_database(self) -> None:
        """Execute the SQL schema script to initialize tables and indexes."""
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Database schema file not found: {self.schema_path}")

        schema_sql = self.schema_path.read_text(encoding="utf-8")
        with self._get_connection() as conn:
            conn.executescript(schema_sql)
            # Ensure backward compatibility if an existing database lacks creation_time
            try:
                conn.execute("ALTER TABLE process_events ADD COLUMN creation_time TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists
        logger.debug("Database initialized at %s", self.db_path)

    def insert_process_event(self, event: ProcessEvent) -> None:
        """Store a process creation event in the database.

        Args:
            event: The ProcessEvent instance to store.
        """
        query = """
            INSERT OR IGNORE INTO process_events (
                event_id, timestamp, creation_time, pid, ppid, image,
                command_line, user, parent_image, integrity_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            event.event_id,
            event.timestamp,
            event.creation_time or event.timestamp,
            event.pid,
            event.ppid,
            event.image,
            event.command_line,
            event.user,
            event.parent_image,
            event.integrity_level,
        )
        try:
            with self._get_connection() as conn:
                conn.execute(query, params)
        except sqlite3.Error as exc:
            logger.error("Failed to insert process event (PID: %d): %s", event.pid, exc)

    def insert_alert(self, alert: Alert) -> None:
        """Store a detection alert in the database.

        Ensures the associated process event is stored first to satisfy foreign key constraints.

        Args:
            alert: The Alert instance to store.
        """
        self.insert_process_event(alert.event)

        query = """
            INSERT OR IGNORE INTO alerts (
                alert_id, timestamp, rule_id, rule_name, severity,
                description, mitre_attack, matched_indicators, event_id,
                pid, ppid, image, command_line, user, parent_image, integrity_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert.alert_id,
            alert.timestamp,
            alert.rule_id,
            alert.rule_name,
            str(alert.severity),
            alert.description,
            json.dumps(alert.mitre_attack),
            json.dumps(alert.matched_indicators),
            alert.event.event_id,
            alert.event.pid,
            alert.event.ppid,
            alert.event.image,
            alert.event.command_line,
            alert.event.user,
            alert.event.parent_image,
            alert.event.integrity_level,
        )
        try:
            with self._get_connection() as conn:
                conn.execute(query, params)
        except sqlite3.Error as exc:
            logger.error("Failed to insert alert %s: %s", alert.alert_id, exc)

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve the most recent alerts from the database.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of alert dictionaries.
        """
        query = """
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """
        with self._get_connection() as conn:
            cursor = conn.execute(query, (limit,))
            rows = cursor.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["mitre_attack"] = json.loads(item.get("mitre_attack", "[]"))
            item["matched_indicators"] = json.loads(item.get("matched_indicators", "[]"))
            results.append(item)
        return results

    def get_statistics(self) -> dict[str, int]:
        """Return total counts of stored process events and alerts."""
        with self._get_connection() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {
            "total_events": int(event_count),
            "total_alerts": int(alert_count),
        }
