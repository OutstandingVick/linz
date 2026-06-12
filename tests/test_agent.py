from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent.perceive import normalize_alert
from agent.prove import build_incident_report
from agent.reason import mock_triage
from playbooks.block_ip import BlockIPPlaybook


FIXTURE_DIR = Path("tests/mock_alerts")


@pytest.mark.parametrize("fixture", sorted(FIXTURE_DIR.glob("*.json")))
def test_mock_triage_matches_expected_action(fixture: Path) -> None:
    raw = json.loads(fixture.read_text(encoding="utf-8"))
    alert = normalize_alert(raw)
    decision = mock_triage(alert)
    assert decision["recommended_action"] == raw["expected_action"]
    assert decision["confidence"] >= raw["expected_confidence_min"]


def test_block_ip_playbook_returns_audit_result() -> None:
    raw = json.loads((FIXTURE_DIR / "ssh_bruteforce.json").read_text(encoding="utf-8"))
    alert = normalize_alert(raw)
    decision = mock_triage(alert)
    result = asyncio.run(BlockIPPlaybook().run(alert, decision))
    assert result.success is True
    assert result.action_type == "block_ip"
    assert result.target == "45.33.32.156"


def test_report_contains_full_loop_trace() -> None:
    raw = json.loads((FIXTURE_DIR / "port_scan.json").read_text(encoding="utf-8"))
    alert = normalize_alert(raw)
    decision = mock_triage(alert)
    report = build_incident_report(alert, decision, None, 0.42)
    assert report["incident_summary"]["original_alert_id"] == raw["id"]
    assert report["ai_triage"]["mitre_attack_id"] == "T1046"
    assert report["metrics"]["total_mttr_seconds"] == 0.42
