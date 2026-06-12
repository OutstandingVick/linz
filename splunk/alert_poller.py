from __future__ import annotations

from pathlib import Path

from splunk.mcp_client import SplunkMCPClient


class AlertPoller:
    def __init__(self, client: SplunkMCPClient, security_index: str, cache_path: Path):
        self.client = client
        self.security_index = security_index
        self.cache_path = cache_path
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.seen_ids = self._load_seen_ids()

    async def poll_new_alerts(self) -> list[dict]:
        raw_alerts = await self.client.search_alerts(
            self.security_index,
            "severity>=medium earliest=-15m",
        )
        new_alerts = []
        for alert in raw_alerts:
            alert_id = str(alert.get("id") or alert.get("splunk_alert_id"))
            if alert_id and alert_id not in self.seen_ids:
                self.seen_ids.add(alert_id)
                new_alerts.append(alert)
        self._save_seen_ids()
        return new_alerts

    def _load_seen_ids(self) -> set[str]:
        if not self.cache_path.exists():
            return set()
        return {line.strip() for line in self.cache_path.read_text().splitlines() if line.strip()}

    def _save_seen_ids(self) -> None:
        self.cache_path.write_text("\n".join(sorted(self.seen_ids)) + "\n", encoding="utf-8")
