"""Configuration loader and validator for lolbins-detector."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml


@dataclass(slots=True)
class AppConfig:
    """General application settings."""

    name: str = "lolbins-detector"
    version: str = "1.0.0"
    log_level: str = "INFO"


@dataclass(slots=True)
class CollectorConfig:
    """Process event collection settings."""

    mode: str = "psutil_polling"
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

    rules_directory: str = "rules/definitions"
    enable_heuristic_scoring: bool = True
    alert_threshold_severity: str = "low"


@dataclass(slots=True)
class OutputConfig:
    """Alert output and reporting settings."""

    console_alerts: bool = True
    json_log_path: str = "data/alerts.jsonl"


@dataclass(slots=True)
class Config:
    """Root configuration container."""

    app: AppConfig = field(default_factory=AppConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
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

    return Config(
        app=AppConfig(**raw_data.get("app", {})),
        collector=CollectorConfig(**raw_data.get("collector", {})),
        storage=StorageConfig(**raw_data.get("storage", {})),
        engine=EngineConfig(**raw_data.get("engine", {})),
        output=OutputConfig(**raw_data.get("output", {})),
    )
