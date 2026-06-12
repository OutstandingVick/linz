from __future__ import annotations

from splunk.mcp_client import SplunkMCPClient


class ReportWriter:
    def __init__(self, client: SplunkMCPClient, report_index: str):
        self.client = client
        self.report_index = report_index

    async def write_report(self, report: dict) -> dict:
        await self.client.write_event(self.report_index, report)
        return report
