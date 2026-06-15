from __future__ import annotations

import json
from typing import Any

from splunk.mcp_client import SplunkMCPClient


class SplunkAIRuntime:
    """Calls Splunk AI capabilities at runtime through Splunk SPL.

    The default command uses Splunk's anomaly detection search capability. Teams
    running Splunk MLTK or another Splunk AI app can swap the command with
    SPLUNK_AI_SEARCH_COMMAND without changing Linz's agent loop.
    """

    def __init__(self, client: SplunkMCPClient, command: str = "anomalydetection"):
        self.client = client
        self.command = command

    async def analyze_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        search = self._build_search(alert)
        results = await self.client.run_spl_search(search)
        top = results[0] if results else {}
        return {
            "enabled": True,
            "provider": "splunk_ai_spl",
            "command": self.command,
            "search": search,
            "results": results[:3],
            "score": _as_float(top.get("anomaly_score") or top.get("score") or top.get("probability"), 0.0),
            "is_anomaly": _as_bool(top.get("isOutlier") or top.get("is_anomaly") or top.get("anomaly"), bool(results)),
        }

    def _build_search(self, alert: dict[str, Any]) -> str:
        metadata = alert.get("metadata", {})
        event_count = metadata.get("event_count") or 0
        time_window = metadata.get("time_window_seconds") or 60
        ports = metadata.get("ports_scanned") or []
        unique_users = metadata.get("unique_usernames") or 0
        payload = json.dumps(alert, sort_keys=True).replace("\\", "\\\\").replace('"', '\\"')
        return (
            "| makeresults "
            f'| eval raw_alert="{payload}" '
            f'| eval event_count={int(event_count)}, time_window_seconds={int(time_window)}, '
            f'unique_usernames={int(unique_users)}, ports_scanned={len(ports)} '
            "| eval events_per_second=round(event_count / max(time_window_seconds, 1), 4) "
            "| eval linz_signal=event_count + (unique_usernames * 2) + (ports_scanned * 10) "
            f"| {self.command} linz_signal action=annotate "
            "| table raw_alert event_count time_window_seconds unique_usernames ports_scanned "
            "events_per_second linz_signal isOutlier anomaly_score"
        )


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "outlier"}
