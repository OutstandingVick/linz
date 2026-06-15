from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover - only required for real MCP HTTP mode
    httpx = None


class SplunkMCPClient:
    """Small MCP boundary used by Linz for Splunk reads and writes.

    In demo mode, events are read from local JSONL files. With a token present,
    the same public methods can call a Splunk MCP HTTP endpoint.
    """

    def __init__(self, base_url: str, token: str | None, demo_dir: Path):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.demo_dir = demo_dir
        self.demo_dir.mkdir(parents=True, exist_ok=True)
        self.alert_queue = self.demo_dir / "security_alerts.jsonl"
        self.report_log = self.demo_dir / "linz_reports.jsonl"

    async def search_alerts(self, index: str, query: str) -> list[dict[str, Any]]:
        if not self.token:
            return self._read_demo_alerts()
        if httpx is None:
            raise RuntimeError("httpx is not installed. Run `pip install -r requirements.txt`.")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.base_url}/search",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"index": index, "query": query},
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("results", payload if isinstance(payload, list) else [])

    async def run_spl_search(self, search: str) -> list[dict[str, Any]]:
        """Run an arbitrary SPL search through the configured Splunk MCP endpoint."""
        if not self.token:
            raise RuntimeError("SPLUNK_TOKEN is required for live Splunk SPL searches.")
        if httpx is None:
            raise RuntimeError("httpx is not installed. Run `pip install -r requirements.txt`.")

        async with httpx.AsyncClient(timeout=45) as client:
            response = await client.post(
                f"{self.base_url}/search",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"query": search},
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("results", payload if isinstance(payload, list) else [])

    async def write_event(self, index: str, event: dict[str, Any]) -> None:
        if not self.token:
            with self.report_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"index": index, "event": event}) + "\n")
            return
        if httpx is None:
            raise RuntimeError("httpx is not installed. Run `pip install -r requirements.txt`.")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.base_url}/events",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"index": index, "event": event},
            )
            response.raise_for_status()

    def append_demo_alert(self, alert: dict[str, Any]) -> None:
        with self.alert_queue.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert) + "\n")

    def _read_demo_alerts(self) -> list[dict[str, Any]]:
        if not self.alert_queue.exists():
            return []
        alerts: list[dict[str, Any]] = []
        with self.alert_queue.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    alerts.append(json.loads(line))
        return alerts
