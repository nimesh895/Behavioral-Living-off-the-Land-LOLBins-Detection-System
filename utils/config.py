"""Configuration loader and validator for lolbins-detector."""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any
import yaml

from engine.suppression import SuppressionRule


@dataclass(slots=True)
class AppConfig:
    """General application settings."""

    name: str = "lolbins-detector"
    version: str = "1.0.0"
    log_level: str = "INFO"


@dataclass(slots=True)
class CollectorConfig:
    """Process event collection settings."""

    mode: str = "auto"
    poll_interval_seconds: float = 1.0
    ignore_images: list[str] = field(default_factory=list)


@dataclass(slots=True)
class StorageConfig:
    """SQLite database storage settings."""

    database_path: str = "data/lolbins_events.db"
    store_all_events: bool = True
    retention_days: int = 30


@dataclass(slots=True)
class EngineConfig:
    """Behavioral detection engine settings."""

    rules_directory: str = "rules"
    enable_heuristic_scoring: bool = True
    alert_threshold_severity: str = "low"
    window_seconds: float = 600.0


@dataclass(slots=True)
class SuppressionConfig:
    """False positive suppression and de-duplication settings."""

    enabled: bool = True
    cooldown_seconds: float = 300.0
    enable_deduplication: bool = True
    rules: list[dict[str, Any]] = field(default_factory=list)

    def parse_rules(self) -> list[SuppressionRule]:
        """Convert raw dictionary rules into SuppressionRule instances."""
        parsed: list[SuppressionRule] = []
        for r in self.rules:
            cmd_regex = (
                re.compile(r["command_line_regex"], re.IGNORECASE)
                if "command_line_regex" in r
                else None
            )
            img_regex = (
                re.compile(r["image_regex"], re.IGNORECASE)
                if "image_regex" in r
                else None
            )
            parsed.append(
                SuppressionRule(
                    rule_id=r.get("rule_id"),
                    user=r.get("user"),
                    image_regex=img_regex,
                    command_line_regex=cmd_regex,
                    parent_image=r.get("parent_image"),
                    reason=r.get("reason", "Configured administrative whitelisting"),
                )
            )
        return parsed


@dataclass(slots=True)
class WebhookConfig:
    """External SIEM or incident chat webhook forwarding settings."""

    enabled: bool = False
    url: str | None = None
    type: str = "generic"
    timeout_seconds: float = 5.0


@dataclass(slots=True)
class OutputConfig:
    """Alert output, timeline, and reporting settings."""

    console_alerts: bool = True
    json_log_path: str = "data/alerts.jsonl"
    markdown_reports_dir: str = "reports"
    timeline_window_seconds: float = 300.0
    webhook: WebhookConfig = field(default_factory=WebhookConfig)


@dataclass(slots=True)
class Config:
    """Root configuration container."""

    app: AppConfig = field(default_factory=AppConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    suppression: SuppressionConfig = field(default_factory=SuppressionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(config_path: str | Path = "config.yaml") -> Config:
    """Load and parse the YAML configuration file into typed dataclasses.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Populated Config instance.
    """
    path = Path(config_path)
    if not path.exists():
        return Config()

    with path.open("r", encoding="utf-8") as file:
        raw_data: dict[str, Any] = yaml.safe_load(file) or {}

    out_raw = raw_data.get("output", {})
    webhook_raw = out_raw.get("webhook", {})

    return Config(
        app=AppConfig(**raw_data.get("app", {})),
        collector=CollectorConfig(**raw_data.get("collector", {})),
        storage=StorageConfig(**raw_data.get("storage", {})),
        engine=EngineConfig(**raw_data.get("engine", {})),
        suppression=SuppressionConfig(**raw_data.get("suppression", {})),
        output=OutputConfig(
            console_alerts=out_raw.get("console_alerts", True),
            json_log_path=out_raw.get("json_log_path", "data/alerts.jsonl"),
            markdown_reports_dir=out_raw.get("markdown_reports_dir", "reports"),
            timeline_window_seconds=out_raw.get("timeline_window_seconds", 300.0),
            webhook=WebhookConfig(**webhook_raw),
        ),
    )
