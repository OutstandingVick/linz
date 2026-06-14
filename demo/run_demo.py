from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.config import Config
from agent.orchestrator import LinzOrchestrator
from splunk.mcp_client import SplunkMCPClient


SCENARIOS = {
    "ssh_bruteforce": Path("tests/mock_alerts/ssh_bruteforce.json"),
    "port_scan": Path("tests/mock_alerts/port_scan.json"),
    "credential_stuffing": Path("tests/mock_alerts/credential_stuffing.json"),
}


async def run_demo(scenario: str, reset: bool) -> None:
    config = Config.from_env()
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
        force=True,
    )
    if reset:
        reset_demo_dir(config.demo_dir)

    client = SplunkMCPClient(config.splunk_mcp_url, config.splunk_token, config.demo_dir)
    orchestrator = LinzOrchestrator(config)
    scenario_names = list(SCENARIOS) if scenario == "all" else [scenario]

    print("Linz demo starting", flush=True)
    print(
        f"Demo mode: {'local mock Splunk MCP' if not config.splunk_token else 'configured Splunk MCP endpoint'}",
        flush=True,
    )
    print(flush=True)

    for name in scenario_names:
        alert = json.loads(SCENARIOS[name].read_text(encoding="utf-8"))
        suffix = datetime.now(timezone.utc).strftime("%H%M%S%f")
        alert["id"] = f"{alert['id']}-{suffix}"
        client.append_demo_alert(alert)
        print(f"Injected {name}: {alert['id']}", flush=True)
        await orchestrator.run_once()
        print(flush=True)

    report_path = config.demo_dir / "linz_reports.jsonl"
    if report_path.exists():
        reports = [json.loads(line)["event"] for line in report_path.read_text().splitlines() if line.strip()]
        print("Reports written:", flush=True)
        for report in reports[-len(scenario_names) :]:
            action = report["action_taken"]
            summary = report["incident_summary"]
            print(
                f"- {report['report_id']}: {summary['threat_type']} "
                f"from {summary['source_ip']} -> {action['type']} ({'success' if action['success'] else 'failed'})",
                flush=True,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a full Linz demo scenario from injection to report.")
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="ssh_bruteforce")
    parser.add_argument("--no-reset", action="store_true", help="Keep previous local demo queue and reports.")
    args = parser.parse_args()

    asyncio.run(run_demo(args.scenario, reset=not args.no_reset))


def reset_demo_dir(demo_dir: Path) -> None:
    demo_dir.mkdir(parents=True, exist_ok=True)
    for name in ("security_alerts.jsonl", "linz_reports.jsonl", "seen_alerts.txt"):
        path = demo_dir / name
        path.write_text("", encoding="utf-8")


if __name__ == "__main__":
    main()
