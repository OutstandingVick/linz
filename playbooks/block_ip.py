from __future__ import annotations

from ipaddress import ip_address, ip_network

from playbooks.base import ActionResult, PlaybookAction, now_utc


class BlockIPPlaybook(PlaybookAction):
    def validate(self, alert: dict, decision: dict) -> bool:
        source_ip = alert.get("source_ip")
        if not source_ip:
            return False
        try:
            parsed = ip_address(source_ip)
        except ValueError:
            return False
        private_ranges = (
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
        )
        return not any(parsed in network for network in private_ranges)

    async def run(self, alert: dict, decision: dict) -> ActionResult:
        source_ip = alert["source_ip"]
        return ActionResult(
            success=True,
            action_type="block_ip",
            target=source_ip,
            timestamp=now_utc(),
            details={
                "provider": "demo_firewall",
                "rule_id": f"fw-block-{source_ip.replace('.', '-')}",
                "reason": decision["reasoning"],
            },
        )
