from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    def load_dotenv() -> bool:
        return False

from agent.config import Config
from splunk.mcp_client import SplunkMCPClient


SCENARIOS = {
    "ssh_bruteforce": Path("tests/mock_alerts/ssh_bruteforce.json"),
    "port_scan": Path("tests/mock_alerts/port_scan.json"),
    "credential_stuffing": Path("tests/mock_alerts/credential_stuffing.json"),
}


def load_alert(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject demo attack events into Linz's Splunk MCP queue.")
    parser.add_argument("--scenario", choices=[*SCENARIOS.keys(), "all"], required=True)
    args = parser.parse_args()

    load_dotenv()
    config = Config.from_env()
    client = SplunkMCPClient(config.splunk_mcp_url, config.splunk_token, config.demo_dir)
    scenario_names = SCENARIOS.keys() if args.scenario == "all" else [args.scenario]

    for name in scenario_names:
        alert = load_alert(SCENARIOS[name])
        suffix = datetime.now(timezone.utc).strftime("%H%M%S%f")
        alert["id"] = f"{alert['id']}-{suffix}"
        client.append_demo_alert(alert)
        print(f"Injected {name}: {alert['id']} -> {config.security_index}")


if __name__ == "__main__":
    main()
