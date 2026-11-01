"""Unified rule loader for YAML definitions and Python detection rule modules."""

from collections.abc import Sequence
import importlib.util
import inspect
import logging
from pathlib import Path
import re
from typing import Any
import yaml

from engine.base import BaseRule
from engine.sequential import SequenceStage, SequentialRule
from engine.single_event import SingleEventRule
from utils.models import Severity

logger = logging.getLogger("lolbins-detector.rules")

# Alias for backward compatibility
DetectionRule = SingleEventRule


class RuleLoader:
    """Loads detection rules from YAML files and Python rule scripts."""

    @classmethod
    def load_rules_from_directory(cls, directory: str | Path) -> list[BaseRule]:
        """Load all YAML and Python rule files located in a directory (and subdirectories).

        Args:
            directory: Path to the rules directory.

        Returns:
            List of instantiated BaseRule objects.
        """
        rules_dir = Path(directory)
        if not rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", rules_dir)
            return []

        rules: list[BaseRule] = []

        # 1. Discover and load all YAML rules
        yaml_files = sorted(
            list(rules_dir.glob("**/*.yaml")) + list(rules_dir.glob("**/*.yml"))
        )
        for yml_file in yaml_files:
            try:
                loaded_yaml_rules = cls._parse_yaml_file(yml_file)
                rules.extend(loaded_yaml_rules)
            except Exception as exc:
                logger.error("Failed to parse YAML rule file '%s': %s", yml_file, exc)

        # 2. Discover and load all Python rules (excluding __init__.py)
        py_files = sorted(
            [
                p
                for p in rules_dir.glob("**/*.py")
                if not p.name.startswith("__")
            ]
        )
        for py_file in py_files:
            try:
                loaded_py_rules = cls.load_python_rule_file(py_file)
                rules.extend(loaded_py_rules)
            except Exception as exc:
                logger.error("Failed to load Python rule file '%s': %s", py_file, exc)

        logger.info("Loaded %d detection rules from '%s'", len(rules), rules_dir)
        return rules

    @classmethod
    def load_python_rule_file(cls, file_path: str | Path) -> list[BaseRule]:
        """Dynamically import a Python file and instantiate any BaseRule subclasses or lists.

        Args:
            file_path: Path to the .py rule file.

        Returns:
            List of BaseRule instances found in the module.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            logger.warning("Python rule file not found: %s", path)
            return []

        module_name = f"lolbins_rule_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            logger.warning("Cannot load spec for %s", path)
            return []

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        discovered_rules: list[BaseRule] = []

        # Check for module-level RULES collection
        if hasattr(module, "RULES") and isinstance(module.RULES, (list, tuple)):
            for r in module.RULES:
                if isinstance(r, BaseRule):
                    discovered_rules.append(r)

        # Inspect classes defined in the module that inherit from BaseRule
        base_classes = {BaseRule, SingleEventRule, SequentialRule}
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseRule) and obj not in base_classes:
                # Instantiate default rule class if not already in RULES
                try:
                    instance = obj()
                    if not any(r.rule_id == instance.rule_id for r in discovered_rules):
                        discovered_rules.append(instance)
                except Exception as exc:
                    logger.debug("Could not auto-instantiate rule class %s: %s", obj, exc)

        logger.debug("Loaded %d rules from Python file %s", len(discovered_rules), path.name)
        return discovered_rules

    @classmethod
    def _parse_yaml_file(cls, file_path: Path) -> list[BaseRule]:
        """Parse a YAML rule file containing single-event or sequential rule definitions."""
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

        parsed_rules: list[BaseRule] = []
        for item in rule_dicts:
            rule_type = str(item.get("type", "single")).lower()

            if rule_type == "sequential" or "stages" in item or "correlation" in item:
                rule = cls._parse_sequential_yaml_rule(item)
            else:
                rule = cls._parse_single_yaml_rule(item)

            if rule:
                parsed_rules.append(rule)

        return parsed_rules

    @staticmethod
    def _parse_single_yaml_rule(item: dict[str, Any]) -> SingleEventRule:
        """Parse a single-event rule dictionary from YAML."""
        detection = item.get("detection", {})
        compiled_regexes = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in detection.get("command_line_regex", [])
        ]

        return SingleEventRule(
            rule_id=str(item["id"]),
            name=str(item["name"]),
            description=str(item.get("description", "")),
            severity=Severity(str(item.get("severity", "medium")).lower()),
            mitre_attack=[str(tag) for tag in item.get("mitre_attack", [])],
            target_images=detection.get("target_images", []),
            suspicious_parents=detection.get("suspicious_parents", []),
            command_line_contains_any=detection.get("command_line_contains_any", []),
            command_line_contains_all=detection.get("command_line_contains_all", []),
            command_line_regex=compiled_regexes,
            required_integrity_levels=detection.get("required_integrity_levels", []),
            enabled=bool(item.get("enabled", True)),
        )

    @staticmethod
    def _parse_sequential_yaml_rule(item: dict[str, Any]) -> SequentialRule | None:
        """Parse a sequential (multi-event) correlation rule from YAML."""
        correlation = item.get("correlation", {})
        raw_stages = correlation.get("stages") or item.get("stages", [])

        if len(raw_stages) < 2:
            logger.warning(
                "Sequential rule '%s' requires at least 2 stages, found %d",
                item.get("id"),
                len(raw_stages),
            )
            return None

        parsed_stages: list[SequenceStage] = []
        for idx, stage_dict in enumerate(raw_stages):
            stage_regexes = [
                re.compile(p, re.IGNORECASE)
                for p in stage_dict.get("command_line_regex", [])
            ]
            stage = SequenceStage(
                name=stage_dict.get("name", f"Stage_{idx + 1}"),
                target_images=stage_dict.get("target_images", []),
                suspicious_parents=stage_dict.get("suspicious_parents", []),
                command_line_contains_any=stage_dict.get("command_line_contains_any", []),
                command_line_contains_all=stage_dict.get("command_line_contains_all", []),
                command_line_regex=stage_regexes,
            )
            parsed_stages.append(stage)

        return SequentialRule(
            rule_id=str(item["id"]),
            name=str(item["name"]),
            description=str(item.get("description", "")),
            severity=Severity(str(item.get("severity", "high")).lower()),
            stages=parsed_stages,
            mitre_attack=[str(tag) for tag in item.get("mitre_attack", [])],
            correlation_key_type=str(correlation.get("key", "user")),
            within_seconds=float(correlation.get("within_seconds", 300.0)),
            enabled=bool(item.get("enabled", True)),
        )
