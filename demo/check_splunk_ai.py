from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.config import Config
from agent.perceive import normalize_alert
from splunk.ai_runtime import SplunkAIRuntime
from splunk.mcp_client import SplunkMCPClient


async def main() -> None:
    config = Config.from_env()
    raw_alert = json.loads(Path("tests/mock_alerts/ssh_bruteforce.json").read_text(encoding="utf-8"))
    alert = normalize_alert(raw_alert)
    client = SplunkMCPClient(config.splunk_mcp_url, config.splunk_token, config.demo_dir)
    result = await SplunkAIRuntime(client, config.splunk_ai_search_command).analyze_alert(alert)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
