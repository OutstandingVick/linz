from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4


def normalize_alert(raw: dict) -> dict:
    raw_logs = raw.get("raw_logs") or raw.get("context_window") or []
    timestamp = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    alert_id = raw.get("id") or raw.get("splunk_alert_id") or f"SA-{uuid4().hex[:12]}"

    return {
        "id": alert_id,
        "timestamp": timestamp,
        "source_ip": raw.get("source_ip", "unknown"),
        "dest_ip": raw.get("dest_ip") or raw.get("target_host", "unknown"),
        "alert_type": raw.get("alert_type", "other"),
        "severity": raw.get("severity", "medium"),
        "raw_log": raw.get("raw_log") or (raw_logs[0] if raw_logs else ""),
        "context_window": raw_logs[:5],
        "metadata": {
            "source_index": raw.get("source_index", "security"),
            "splunk_alert_id": alert_id,
            "event_count": raw.get("event_count"),
            "time_window_seconds": raw.get("time_window_seconds"),
            "ports_scanned": raw.get("ports_scanned"),
            "unique_usernames": raw.get("unique_usernames"),
            "expected_action": raw.get("expected_action"),
        },
    }
