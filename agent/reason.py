from __future__ import annotations

import json
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

try:
    import anthropic
except ImportError:  # pragma: no cover - optional until real AI mode is enabled
    anthropic = None


class AlertTriager:
    def __init__(
        self,
        api_key: str | None,
        model: str,
        use_mock_ai: bool,
        splunk_ai=None,
        require_splunk_ai: bool = False,
        prompt_path: Path = Path("prompts/triage_system.txt"),
    ):
        self.api_key = api_key
        self.model = model
        self.use_mock_ai = use_mock_ai or not api_key
        self.splunk_ai = splunk_ai
        self.require_splunk_ai = require_splunk_ai
        self.prompt_path = prompt_path

    async def triage(self, alert: dict[str, Any]) -> dict[str, Any]:
        splunk_ai_result = await self._run_splunk_ai(alert)
        if self.use_mock_ai:
            decision = mock_triage(alert)
            decision["model"] = "deterministic_demo_triage"
            decision["splunk_ai"] = splunk_ai_result
            return decision
        if anthropic is None:
            raise RuntimeError("anthropic is not installed. Run `pip install -r requirements.txt`.")
        enriched_alert = {**alert, "splunk_ai": splunk_ai_result}
        decision = self._triage_with_claude(enriched_alert)
        decision["model"] = self.model
        decision["splunk_ai"] = splunk_ai_result
        return decision

    async def _run_splunk_ai(self, alert: dict[str, Any]) -> dict[str, Any]:
        if self.splunk_ai is None:
            if self.require_splunk_ai:
                raise RuntimeError("Splunk AI is required but LINZ_USE_SPLUNK_AI is not enabled.")
            return {"enabled": False, "provider": None}
        try:
            return await self.splunk_ai.analyze_alert(alert)
        except Exception as exc:
            if self.require_splunk_ai:
                raise
            return {"enabled": True, "provider": "splunk_ai_spl", "error": str(exc)}

    def _triage_with_claude(self, alert: dict[str, Any]) -> dict[str, Any]:
        client = anthropic.Anthropic(api_key=self.api_key)
        system_prompt = self.prompt_path.read_text(encoding="utf-8")
        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Triage this alert:\n\n{json.dumps(alert, indent=2)}",
                }
            ],
        )
        return _parse_json_response(response.content[0].text)


def mock_triage(alert: dict[str, Any]) -> dict[str, Any]:
    source_ip = alert.get("source_ip", "")
    metadata = alert.get("metadata", {})
    event_count = metadata.get("event_count") or 0
    unique_usernames = metadata.get("unique_usernames") or 0
    ports_scanned = metadata.get("ports_scanned") or []
    alert_type = alert.get("alert_type", "other")
    internal_source = _is_internal_ip(source_ip)

    if unique_usernames >= 100:
        action = "create_ticket" if internal_source else "block_ip"
        return {
            "is_real_threat": True,
            "threat_type": "credential stuffing",
            "confidence": 0.94,
            "blast_radius": "environment",
            "recommended_action": action,
            "reasoning": f"{event_count} failed logins across {unique_usernames} usernames indicates automated credential stuffing. The source is {'internal' if internal_source else 'external'}, so Linz selected {action}.",
            "mitre_attack_id": "T1110.004",
        }

    if alert_type == "authentication_failure" and event_count >= 50:
        action = "create_ticket" if internal_source else "block_ip"
        return {
            "is_real_threat": True,
            "threat_type": "SSH brute force",
            "confidence": 0.91,
            "blast_radius": "single_host",
            "recommended_action": action,
            "reasoning": f"{event_count} failed authentication attempts from {source_ip} in a short window match automated brute forcing. The source IP is {'internal' if internal_source else 'external'}, so Linz selected {action}.",
            "mitre_attack_id": "T1110.001",
        }

    if alert_type == "network_scan" or len(ports_scanned) >= 5:
        return {
            "is_real_threat": True,
            "threat_type": "port scan",
            "confidence": 0.72,
            "blast_radius": "network_segment",
            "recommended_action": "create_ticket",
            "reasoning": f"{source_ip} touched multiple sensitive ports in seconds, which is consistent with reconnaissance. Confidence is moderate, so Linz escalated through a ticket instead of blocking immediately.",
            "mitre_attack_id": "T1046",
        }

    return {
        "is_real_threat": False,
        "threat_type": "other",
        "confidence": 0.35,
        "blast_radius": "single_host",
        "recommended_action": "monitor_only",
        "reasoning": "The alert lacks enough corroborating signals for automated response. Linz will monitor and preserve the event for human review.",
        "mitre_attack_id": None,
    }


def _parse_json_response(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _is_internal_ip(value: str) -> bool:
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    private_ranges = (
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
    )
    return any(parsed in network for network in private_ranges)
