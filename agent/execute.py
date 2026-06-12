from __future__ import annotations

from playbooks.base import ActionResult
from playbooks.block_ip import BlockIPPlaybook
from playbooks.create_ticket import CreateTicketPlaybook
from playbooks.isolate_endpoint import IsolateEndpointPlaybook
from playbooks.slack_alert import SlackAlertPlaybook


class ActionExecutor:
    def __init__(self, config):
        self.playbooks = {
            "block_ip": BlockIPPlaybook(),
            "isolate_endpoint": IsolateEndpointPlaybook(),
            "create_ticket": CreateTicketPlaybook(config),
            "slack_alert": SlackAlertPlaybook(config),
        }

    async def execute(self, alert: dict, decision: dict) -> ActionResult | None:
        action_key = decision["recommended_action"]
        if action_key == "monitor_only":
            return None

        playbook = self.playbooks.get(action_key)
        if not playbook:
            raise ValueError(f"Unknown action: {action_key}")
        if not playbook.validate(alert, decision):
            raise ValueError(f"Validation failed for {action_key}")
        return await playbook.run(alert, decision)
