from __future__ import annotations

try:
    import httpx
except ImportError:  # pragma: no cover - only required for real Slack mode
    httpx = None

from playbooks.base import ActionResult, PlaybookAction, now_utc


class SlackAlertPlaybook(PlaybookAction):
    def __init__(self, config):
        self.config = config

    def validate(self, alert: dict, decision: dict) -> bool:
        return bool(alert.get("source_ip") and decision.get("reasoning"))

    async def run(self, alert: dict, decision: dict) -> ActionResult:
        text = (
            f"Linz detected {decision['threat_type']} from {alert['source_ip']} "
            f"with confidence {decision['confidence']:.2f}. Action: {decision['recommended_action']}."
        )
        if not self.config.slack_webhook_url:
            return ActionResult(
                success=True,
                action_type="slack_alert",
                target="#demo-security",
                timestamp=now_utc(),
                details={"provider": "demo_slack", "message": text},
            )
        if httpx is None:
            raise RuntimeError("httpx is not installed. Run `pip install -r requirements.txt`.")

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(self.config.slack_webhook_url, json={"text": text})
            response.raise_for_status()
        return ActionResult(
            success=True,
            action_type="slack_alert",
            target="slack_webhook",
            timestamp=now_utc(),
            details={"provider": "slack", "message": text},
        )
