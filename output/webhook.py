"""SIEM and Incident Chat Webhook Dispatcher (Generic HTTP, Slack, Discord)."""

from datetime import datetime, timezone
import json
import logging
from typing import Any
import urllib.error
import urllib.request

from utils.models import Alert, Severity

logger = logging.getLogger("lolbins-detector.output.webhook")


class WebhookDispatcher:
    """Dispatches formatted alert notifications to external SIEM or webhook endpoints."""

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_type: str = "generic",
        timeout: float = 5.0,
        enabled: bool = True,
    ) -> None:
        """Initialize the webhook dispatcher.

        Args:
            webhook_url: Target HTTP/HTTPS endpoint.
            webhook_type: One of 'generic', 'slack', or 'discord'.
            timeout: Network request timeout in seconds.
            enabled: Whether webhook forwarding is active.
        """
        self.webhook_url = webhook_url
        self.webhook_type = webhook_type.lower()
        self.timeout = max(1.0, timeout)
        self.enabled = bool(enabled and webhook_url)

    def dispatch(self, alert: Alert, timeline_count: int = 0) -> bool:
        """Send alert to the configured webhook destination.

        Args:
            alert: The security Alert to forward.
            timeline_count: Number of correlated timeline events.

        Returns:
            True if delivered successfully, False otherwise.
        """
        if not self.enabled or not self.webhook_url:
            return False

        try:
            payload = self._build_payload(alert, timeline_count)
            data = json.dumps(payload).encode("utf-8")

            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "lolbins-detector/1.0",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = response.getcode()
                if 200 <= status_code < 300:
                    logger.debug("Successfully forwarded alert %s to webhook", alert.alert_id)
                    return True
                logger.warning("Webhook returned unexpected status code: %d", status_code)
                return False

        except urllib.error.URLError as exc:
            logger.error("Failed to deliver webhook alert %s: %s", alert.alert_id, exc)
            return False
        except Exception as exc:
            logger.error("Unexpected error in webhook delivery: %s", exc)
            return False

    def _build_payload(self, alert: Alert, timeline_count: int) -> dict[str, Any]:
        """Format the alert payload according to the destination webhook protocol."""
        if self.webhook_type == "slack":
            return self._build_slack_payload(alert, timeline_count)
        elif self.webhook_type == "discord":
            return self._build_discord_payload(alert, timeline_count)
        return self._build_generic_payload(alert, timeline_count)

    @staticmethod
    def _build_generic_payload(alert: Alert, timeline_count: int) -> dict[str, Any]:
        """Generic SIEM JSON schema."""
        return {
            "source": "lolbins-detector",
            "version": "1.0",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "alert": alert.to_dict(),
            "timeline_events_count": timeline_count,
        }

    @staticmethod
    def _build_slack_payload(alert: Alert, timeline_count: int) -> dict[str, Any]:
        """Slack Block Kit format with colored attachment."""
        color_map = {
            Severity.LOW: "#36a64f",
            Severity.MEDIUM: "#ecb22e",
            Severity.HIGH: "#e01e5a",
            Severity.CRITICAL: "#a30200",
        }
        mitre_str = ", ".join(alert.mitre_attack) if alert.mitre_attack else "N/A"

        return {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, "#439fe0"),
                    "title": f":rotating_light: [{alert.severity.upper()}] {alert.rule_name}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Rule ID", "value": alert.rule_id, "short": True},
                        {"title": "MITRE ATT&CK", "value": mitre_str, "short": True},
                        {"title": "Target Image", "value": f"`{alert.event.image}`", "short": True},
                        {"title": "PID / PPID", "value": f"{alert.event.pid} / {alert.event.ppid}", "short": True},
                        {"title": "Security Account", "value": alert.event.user, "short": True},
                        {"title": "Correlated Timeline", "value": f"{timeline_count} events", "short": True},
                        {"title": "Command Line", "value": f"```{alert.event.command_line}```", "short": False},
                    ],
                    "footer": "lolbins-detector",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

    @staticmethod
    def _build_discord_payload(alert: Alert, timeline_count: int) -> dict[str, Any]:
        """Discord webhook embed schema."""
        color_map = {
            Severity.LOW: 3581519,
            Severity.MEDIUM: 15512110,
            Severity.HIGH: 14687834,
            Severity.CRITICAL: 10682880,
        }
        mitre_str = ", ".join(alert.mitre_attack) if alert.mitre_attack else "N/A"

        return {
            "embeds": [
                {
                    "title": f"🚨 [{alert.severity.upper()}] {alert.rule_name}",
                    "description": alert.description,
                    "color": color_map.get(alert.severity, 0x3498DB),
                    "fields": [
                        {"name": "Rule ID", "value": alert.rule_id, "inline": True},
                        {"name": "MITRE ATT&CK", "value": mitre_str, "inline": True},
                        {"name": "Process", "value": f"`{alert.event.image_name}` (PID: {alert.event.pid})", "inline": True},
                        {"name": "User", "value": alert.event.user, "inline": True},
                        {"name": "Correlated Events", "value": f"{timeline_count} events", "inline": True},
                        {"name": "Command Line", "value": f"```{alert.event.command_line[:500]}```", "inline": False},
                    ],
                    "footer": {"text": f"Alert ID: {alert.alert_id}"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }
