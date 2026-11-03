"""False positive suppression and alert de-duplication engine."""

from dataclasses import dataclass, field
import logging
import re
import time
from typing import Any

from utils.models import Alert

logger = logging.getLogger("lolbins-detector.engine.suppression")


@dataclass(slots=True)
class SuppressionRule:
    """Defines criteria to suppress false positive alerts."""

    rule_id: str | None = None
    user: str | None = None
    image_regex: re.Pattern[str] | None = None
    command_line_regex: re.Pattern[str] | None = None
    parent_image: str | None = None
    reason: str = "Administrative false positive"


class SuppressionEngine:
    """Evaluates alerts against configured suppression rules and manages alert de-duplication."""

    def __init__(
        self,
        suppression_rules: list[SuppressionRule] | None = None,
        cooldown_seconds: float = 300.0,
        enable_deduplication: bool = True,
    ) -> None:
        """Initialize suppression engine.

        Args:
            suppression_rules: List of SuppressionRule instances.
            cooldown_seconds: Window in seconds to de-duplicate identical alerts.
            enable_deduplication: Whether to suppress repeated identical alerts within cooldown.
        """
        self.suppression_rules = suppression_rules or []
        self.cooldown_seconds = max(10.0, cooldown_seconds)
        self.enable_deduplication = enable_deduplication

        # De-duplication tracker: (rule_id, user, command_line_hash_or_prefix) -> (last_alert_time, hit_count)
        self._alert_history: dict[tuple[str, str, str], tuple[float, int]] = {}

    def is_suppressed(self, alert: Alert) -> tuple[bool, str]:
        """Check if an alert matches any suppression rule.

        Returns:
            Tuple of (is_suppressed, reason_message).
        """
        user_upper = alert.event.user.upper()
        image_lower = alert.event.image_name
        parent_lower = alert.event.parent_image_name
        cmd = alert.event.command_line

        for rule in self.suppression_rules:
            # Rule ID check
            if rule.rule_id and rule.rule_id != alert.rule_id:
                continue

            # User check
            if rule.user and rule.user.upper() != user_upper:
                continue

            # Parent image check
            if rule.parent_image and rule.parent_image.lower() != parent_lower:
                continue

            # Image regex check
            if rule.image_regex and not rule.image_regex.search(image_lower):
                continue

            # Command line regex check
            if rule.command_line_regex and not rule.command_line_regex.search(cmd):
                continue

            logger.info(
                "Suppressed alert '%s' (%s) due to suppression rule: %s",
                alert.rule_id,
                alert.rule_name,
                rule.reason,
            )
            return True, rule.reason

        return False, ""

    def check_deduplication(self, alert: Alert) -> tuple[bool, int]:
        """Check if an identical alert triggered recently within the cooldown window.

        Returns:
            Tuple of (is_duplicate, previous_occurrences_count).
        """
        if not self.enable_deduplication:
            return False, 1

        now = time.time()
        # Create a signature key combining rule ID, user, and normalized command line
        norm_cmd = alert.event.command_line.strip()[:150]
        sig_key = (alert.rule_id, alert.event.user.upper(), norm_cmd)

        # Evict old de-duplication entries
        expired_keys = [
            k for k, (t, _) in self._alert_history.items() if now - t > self.cooldown_seconds
        ]
        for k in expired_keys:
            del self._alert_history[k]

        if sig_key in self._alert_history:
            last_time, count = self._alert_history[sig_key]
            if now - last_time <= self.cooldown_seconds:
                new_count = count + 1
                self._alert_history[sig_key] = (now, new_count)
                logger.debug(
                    "De-duplicated alert '%s' (occurrence #%d in %.1fs cooldown)",
                    alert.rule_id,
                    new_count,
                    self.cooldown_seconds,
                )
                return True, new_count

        self._alert_history[sig_key] = (now, 1)
        return False, 1
