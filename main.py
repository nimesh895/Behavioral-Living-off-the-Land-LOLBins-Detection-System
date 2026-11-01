"""Main entry point for the Windows Behavioral LOLBins Detection System."""

import argparse
from pathlib import Path
import signal
import sys
from types import FrameType

from collector.process_collector import ProcessCollector
from engine.detector import BehavioralEngine
from output.notifier import AlertDispatcher
from rules.loader import RuleLoader
from storage.database import DatabaseManager
from utils.config import load_config
from utils.logger import setup_logger


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for lolbins-detector."""
    parser = argparse.ArgumentParser(
        prog="lolbins-detector",
        description="Windows Behavioral Living-off-the-Land (LOLBins) Detection System",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["psutil_polling", "wmi", "mock"],
        default=None,
        help="Override the collector mode defined in config.yaml",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display database event and alert statistics and exit",
    )
    return parser.parse_args()


def main() -> int:
    """Initialize components and run the behavioral detection pipeline."""
    args = parse_arguments()
    config = load_config(args.config)

    if args.mode:
        config.collector.mode = args.mode

    logger = setup_logger(name=config.app.name, level=config.app.log_level)
    logger.info("Starting %s v%s", config.app.name, config.app.version)

    # Initialize SQLite Storage
    db = DatabaseManager(db_path=config.storage.database_path)

    if args.stats:
        stats = db.get_statistics()
        logger.info(
            "Database Statistics | Total Events: %d | Total Alerts: %d",
            stats["total_events"],
            stats["total_alerts"],
        )
        return 0

    # Load Behavioral Rules & Initialize Engine
    rules = RuleLoader.load_rules_from_directory(config.engine.rules_directory)
    engine = BehavioralEngine(
        rules=rules,
        enable_heuristics=config.engine.enable_heuristic_scoring,
        min_severity=config.engine.alert_threshold_severity,
    )

    # Initialize Output Dispatcher & Process Collector
    dispatcher = AlertDispatcher(
        console_alerts=config.output.console_alerts,
        json_log_path=config.output.json_log_path,
    )
    collector = ProcessCollector(
        mode=config.collector.mode,
        poll_interval=config.collector.poll_interval_seconds,
        ignore_images=config.collector.ignore_images,
    )

    # Register graceful shutdown handler
    def handle_shutdown(signum: int, _frame: FrameType | None) -> None:
        logger.info("Received signal %d, stopping collector...", signum)
        collector.stop()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    processed_events = 0
    triggered_alerts = 0

    try:
        for event in collector.stream_events():
            processed_events += 1
            if config.storage.store_all_events:
                db.insert_process_event(event)

            alerts = engine.evaluate(event)
            for alert in alerts:
                triggered_alerts += 1
                db.insert_alert(alert)
                dispatcher.dispatch(alert)

    except KeyboardInterrupt:
        logger.info("Interrupted by user, shutting down...")
    finally:
        logger.info(
            "Shutdown complete. Processed %d events and generated %d alerts.",
            processed_events,
            triggered_alerts,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
