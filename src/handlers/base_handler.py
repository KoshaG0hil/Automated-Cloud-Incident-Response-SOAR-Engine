"""
Base Remediation Handler.
Abstract interface with dry-run support, action tracking, and structured audit logs.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger("soar.handler")


@dataclass
class RemediationAction:
    """Individual containment step executed during incident response."""

    action_name: str
    status: str  # SUCCESS, FAILED, SKIPPED, DRY_RUN
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_name": self.action_name,
            "status": self.status,
            "details": self.details,
            "error": self.error,
            "executed_at": self.executed_at,
        }


@dataclass
class ContainmentResult:
    """Consolidated containment operation outcome."""

    resource_type: str
    resource_id: str
    success: bool
    dry_run: bool
    actions_executed: List[RemediationAction] = field(default_factory=list)
    error_message: Optional[str] = None
    quarantine_applied: bool = False
    evidence_collected: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "success": self.success,
            "dry_run": self.dry_run,
            "quarantine_applied": self.quarantine_applied,
            "actions_executed": [a.to_dict() for a in self.actions_executed],
            "error_message": self.error_message,
            "evidence_collected": self.evidence_collected,
        }


class BaseRemediationHandler(ABC):
    """Abstract base class for AWS service incident remediation."""

    def __init__(self, dry_run: bool = False, session: Optional[Any] = None):
        self.dry_run = dry_run
        self.session = session
        self.logger = logging.getLogger(f"soar.{self.__class__.__name__}")

    @abstractmethod
    def execute_containment(self, finding: Any) -> ContainmentResult:
        """Executes active containment steps or simulates them in dry-run mode."""
        pass
