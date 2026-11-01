"""Rule schema and YAML loader for behavioral LOLBins detection rules."""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import Any
import yaml

from utils.models import Severity

logger = logging.getLogger("lolbins-detector.rules")


@dataclass(slots=True)
class DetectionRule:
    """Represents a behavioral detection rule for a Living-off-the-Land binary."""

    id: str
    name: str
    description: str
    severity: Severity
    mitre_attack: list[str]
    target_images: list[str] = field(default_factory=list)
    suspicious_parents: list[str] = field(default_factory=list)
    command_line_contains_any: list[str] = field(default_factory=list)
    command_line_contains_all: list[str] = field(default_factory=list)
    command_line_regex: list[re.Pattern[str]] = field(default_factory=list)
    required_integrity_levels: list[str] = field(default_factory=list)


class RuleLoader:
    """Loads and validates YAML detection rules from a directory."""

    @staticmethod
    def load_rules_from_directory(directory: str | Path) -> list[DetectionRule]:
        """Load all YAML rule files from the specified directory.

        Args:
            directory: Path to the directory containing .yaml/.yml rule files.

        Returns:
            List of parsed DetectionRule objects.
        """
        rules_dir = Path(directory)
        if not rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", rules_dir)
            return []

        rules: list[DetectionRule] = []
        rule_files = sorted(
            list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml"))
        )

        for file_path in rule_files:
            try:
                loaded = RuleLoader._parse_rule_file(file_path)
                rules.extend(loaded)
            except Exception as exc:
                logger.error("Failed to load rule file %s: %s", file_path, exc)

        logger.info("Loaded %d behavioral detection rules from %s", len(rules), rules_dir)
        return rules

    @staticmethod
    def _parse_rule_file(file_path: Path) -> list[DetectionRule]:
        """Parse a single YAML file containing one or more rule definitions."""
        with file_path.open("r", encoding="utf-8") as file:
            raw_content: Any = yaml.safe_load(file)

        if not raw_content:
            return []

        rule_dicts: list[dict[str, Any]]
        if isinstance(raw_content, dict) and "rules" in raw_content:
            rule_dicts = raw_content["rules"]
        elif isinstance(raw_content, list):
            rule_dicts = raw_content
        elif isinstance(raw_content, dict):
            rule_dicts = [raw_content]
        else:
            return []

        parsed_rules: list[DetectionRule] = []
        for item in rule_dicts:
            detection = item.get("detection", {})
            compiled_regexes = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in detection.get("command_line_regex", [])
            ]

            rule = DetectionRule(
                id=str(item["id"]),
                name=str(item["name"]),
                description=str(item.get("description", "")),
                severity=Severity(str(item.get("severity", "medium")).lower()),
                mitre_attack=[str(tag) for tag in item.get("mitre_attack", [])],
                target_images=[
                    img.lower() for img in detection.get("target_images", [])
                ],
                suspicious_parents=[
                    parent.lower() for parent in detection.get("suspicious_parents", [])
                ],
                command_line_contains_any=[
                    token.lower()
                    for token in detection.get("command_line_contains_any", [])
                ],
                command_line_contains_all=[
                    token.lower()
                    for token in detection.get("command_line_contains_all", [])
                ],
                command_line_regex=compiled_regexes,
                required_integrity_levels=[
                    lvl.lower()
                    for lvl in detection.get("required_integrity_levels", [])
                ],
            )
            parsed_rules.append(rule)

        return parsed_rules
