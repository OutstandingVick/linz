from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timezone

from agent.config import Config
from agent.execute import ActionExecutor
from agent.perceive import normalize_alert
from agent.prove import build_incident_report
from agent.reason import AlertTriager
from splunk.alert_poller import AlertPoller
from splunk.ai_runtime import SplunkAIRuntime
from splunk.mcp_client import SplunkMCPClient
from splunk.report_writer import ReportWriter

logger = logging.getLogger("linz")


class LinzOrchestrator:
    def __init__(self, config: Config):
        self.config = config
        self.client = SplunkMCPClient(config.splunk_mcp_url, config.splunk_token, config.demo_dir)
        self.poller = AlertPoller(self.client, config.security_index, config.demo_dir / "seen_alerts.txt")
        splunk_ai = SplunkAIRuntime(self.client, config.splunk_ai_search_command) if config.use_splunk_ai else None
        self.triager = AlertTriager(
            config.anthropic_api_key,
            config.anthropic_model,
            config.use_mock_ai,
            splunk_ai=splunk_ai,
            require_splunk_ai=config.require_splunk_ai,
        )
        self.executor = ActionExecutor(config)
        self.reporter = ReportWriter(self.client, config.report_index)

    async def run(self, once: bool = False) -> None:
        logger.info("Linz started. Polling every %ds", self.config.poll_interval_seconds)
        while True:
            await self.run_once()
            if once:
                return
            await asyncio.sleep(self.config.poll_interval_seconds)

    async def run_once(self) -> None:
        raw_alerts = await self.poller.poll_new_alerts()
        if not raw_alerts:
            logger.info("No new Splunk alerts found.")
            return

        for raw_alert in raw_alerts:
            loop_start = datetime.now(timezone.utc)
            alert = normalize_alert(raw_alert)
            logger.info("[PERCEIVE] New alert: %s", alert["id"])

            decision = await self.triager.triage(alert)
            splunk_ai = decision.get("splunk_ai", {})
            if splunk_ai.get("enabled"):
                logger.info(
                    "[SPLUNK_AI] %s | anomaly=%s | score=%.2f",
                    splunk_ai.get("command", "splunk_ai"),
                    splunk_ai.get("is_anomaly"),
                    float(splunk_ai.get("score") or 0.0),
                )
            logger.info(
                "[REASON] %s | confidence=%.2f | action=%s",
                decision["threat_type"],
                decision["confidence"],
                decision["recommended_action"],
            )

            result = await self.executor.execute(alert, decision)
            if result:
                logger.info("[EXECUTE] %s -> %s", result.action_type, "SUCCESS" if result.success else "FAILED")
            else:
                logger.info("[EXECUTE] monitor_only -> no action taken")

            mttr = (datetime.now(timezone.utc) - loop_start).total_seconds()
            report = build_incident_report(alert, decision, result, mttr)
            await self.reporter.write_report(report)
            logger.info("[PROVE] Report %s written to Splunk (MTTR: %.3fs)", report["report_id"], mttr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Linz incident response agent.")
    parser.add_argument("--once", action="store_true", help="Process current alerts once and exit.")
    args = parser.parse_args()

    config = Config.from_env()
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(LinzOrchestrator(config).run(once=args.once))


if __name__ == "__main__":
    main()
