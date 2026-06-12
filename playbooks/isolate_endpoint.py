from __future__ import annotations

from playbooks.base import ActionResult, PlaybookAction, now_utc


class IsolateEndpointPlaybook(PlaybookAction):
    def validate(self, alert: dict, decision: dict) -> bool:
        return bool(alert.get("dest_ip"))

    async def run(self, alert: dict, decision: dict) -> ActionResult:
        target = alert["dest_ip"]
        return ActionResult(
            success=True,
            action_type="isolate_endpoint",
            target=target,
            timestamp=now_utc(),
            details={
                "provider": "demo_edr",
                "isolation_id": f"edr-isolate-{target.replace('.', '-')}",
            },
        )
