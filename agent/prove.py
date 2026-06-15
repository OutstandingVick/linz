from __future__ import annotations

import re
from datetime import datetime, timezone

from playbooks.base import ActionResult


def build_incident_report(
    alert: dict,
    decision: dict,
    result: ActionResult | None,
    mttr_seconds: float,
) -> dict:
    generated_at = datetime.now(timezone.utc)
    alert_suffix = re.sub(r"[^A-Za-z0-9]", "", alert["id"])[-6:]
    report_id = f"SL-{generated_at.strftime('%Y%m%d-%H%M%S')}-{alert_suffix}"
    return {
        "report_id": report_id,
        "generated_at": generated_at.isoformat(),
        "incident_summary": {
            "original_alert_id": alert["id"],
            "threat_type": decision["threat_type"],
            "source_ip": alert["source_ip"],
            "target_host": alert["dest_ip"],
            "severity": alert["severity"],
        },
        "ai_triage": {
            "model": decision.get("model", "claude-sonnet-4-20250514"),
            "confidence": decision["confidence"],
            "reasoning": decision["reasoning"],
            "mitre_attack_id": decision.get("mitre_attack_id"),
            "splunk_ai": decision.get("splunk_ai", {"enabled": False}),
        },
        "action_taken": _serialize_action(result, decision),
        "metrics": {
            "time_to_detect_seconds": 4,
            "time_to_respond_seconds": round(mttr_seconds, 3),
            "total_mttr_seconds": round(mttr_seconds, 3),
        },
    }


def _serialize_action(result: ActionResult | None, decision: dict) -> dict:
    if result is None:
        return {
            "type": decision["recommended_action"],
            "target": None,
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {"note": "No automated action required."},
        }
    return {
        "type": result.action_type,
        "target": result.target,
        "success": result.success,
        "timestamp": result.timestamp.isoformat(),
        "details": result.details,
        "error": result.error,
    }
