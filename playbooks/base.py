from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ActionResult:
    success: bool
    action_type: str
    target: str
    timestamp: datetime
    details: dict
    error: str | None = None


class PlaybookAction(ABC):
    @abstractmethod
    async def run(self, alert: dict, decision: dict) -> ActionResult:
        """Execute the playbook action and return the result."""

    @abstractmethod
    def validate(self, alert: dict, decision: dict) -> bool:
        """Pre-flight check before execution."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
