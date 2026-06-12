from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    def load_dotenv() -> bool:
        return False


@dataclass(frozen=True)
class Config:
    splunk_mcp_url: str
    splunk_token: str | None
    security_index: str
    report_index: str
    demo_dir: Path
    anthropic_api_key: str | None
    anthropic_model: str
    use_mock_ai: bool
    slack_webhook_url: str | None
    jira_base_url: str | None
    jira_email: str | None
    jira_api_token: str | None
    jira_project_key: str
    poll_interval_seconds: int
    confidence_threshold: float
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        load_dotenv()
        return cls(
            splunk_mcp_url=os.getenv("SPLUNK_MCP_URL", "http://localhost:8089"),
            splunk_token=_clean(os.getenv("SPLUNK_TOKEN")),
            security_index=os.getenv("SPLUNK_SECURITY_INDEX", "security"),
            report_index=os.getenv("SPLUNK_REPORT_INDEX", "linz_reports"),
            demo_dir=Path(os.getenv("LINZ_DEMO_DIR", ".linz_demo")),
            anthropic_api_key=_clean(os.getenv("ANTHROPIC_API_KEY")),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            use_mock_ai=_as_bool(os.getenv("LINZ_USE_MOCK_AI", "true")),
            slack_webhook_url=_clean(os.getenv("SLACK_WEBHOOK_URL")),
            jira_base_url=_clean(os.getenv("JIRA_BASE_URL")),
            jira_email=_clean(os.getenv("JIRA_EMAIL")),
            jira_api_token=_clean(os.getenv("JIRA_API_TOKEN")),
            jira_project_key=os.getenv("JIRA_PROJECT_KEY", "SEC"),
            poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "30")),
            confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.5")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _clean(value: str | None) -> str | None:
    if not value:
        return None
    placeholders = ("your-", "https://hooks.slack.com/services/your")
    if value.startswith(placeholders):
        return None
    return value
