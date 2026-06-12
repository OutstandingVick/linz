from __future__ import annotations

import base64

try:
    import httpx
except ImportError:  # pragma: no cover - only required for real Jira mode
    httpx = None

from playbooks.base import ActionResult, PlaybookAction, now_utc


class CreateTicketPlaybook(PlaybookAction):
    def __init__(self, config):
        self.config = config

    def validate(self, alert: dict, decision: dict) -> bool:
        return bool(alert.get("id") and decision.get("threat_type"))

    async def run(self, alert: dict, decision: dict) -> ActionResult:
        if not all([self.config.jira_base_url, self.config.jira_email, self.config.jira_api_token]):
            key = f"{self.config.jira_project_key}-DEMO-{alert['id'][-5:]}"
            return ActionResult(
                success=True,
                action_type="create_ticket",
                target=key,
                timestamp=now_utc(),
                details={"provider": "demo_jira", "summary": self._summary(alert, decision)},
            )
        if httpx is None:
            raise RuntimeError("httpx is not installed. Run `pip install -r requirements.txt`.")

        auth = base64.b64encode(
            f"{self.config.jira_email}:{self.config.jira_api_token}".encode()
        ).decode()
        payload = {
            "fields": {
                "project": {"key": self.config.jira_project_key},
                "summary": self._summary(alert, decision),
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": decision["reasoning"]}],
                        }
                    ],
                },
                "issuetype": {"name": "Task"},
            }
        }
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.config.jira_base_url.rstrip('/')}/rest/api/3/issue",
                headers={
                    "Authorization": f"Basic {auth}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        return ActionResult(
            success=True,
            action_type="create_ticket",
            target=data["key"],
            timestamp=now_utc(),
            details={"provider": "jira", "issue_url": f"{self.config.jira_base_url}/browse/{data['key']}"},
        )

    def _summary(self, alert: dict, decision: dict) -> str:
        return f"Linz: {decision['threat_type']} from {alert['source_ip']}"
