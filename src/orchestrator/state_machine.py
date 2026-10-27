"""
SOAR State Machine Orchestrator.
Coordinates the end-to-end incident lifecycle: Ingestion -> MITRE Mapping -> Triage -> Containment -> Evidence Vault -> Alert.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from ..core.finding_parser import FindingParser, SecurityFinding
from ..core.mitre_mapper import MitreMapper, MitreTactics
from ..core.scoring_engine import (
    IncidentPriority,
    IncidentScoringEngine,
    TriageAssessment,
)
from ..handlers.base_handler import ContainmentResult, RemediationAction
from ..handlers.ec2_handler import Ec2RemediationHandler
from ..handlers.iam_handler import IamRemediationHandler
from ..handlers.s3_handler import S3RemediationHandler
from ..reporters.alert_dispatcher import AlertDispatcher, AlertNotification
from ..reporters.evidence_vault import EvidenceVault, IncidentAuditReport

logger = logging.getLogger("soar.state_machine")


@dataclass
class IncidentResponseResult:
    """End-to-end pipeline execution outcome."""

    finding: SecurityFinding
    mitre: MitreTactics
    triage: TriageAssessment
    containment: ContainmentResult
    evidence_report: IncidentAuditReport
    alert_dispatch_results: Dict[str, Any]
    s3_vault_uri: Optional[str] = None
    local_evidence_path: Optional[str] = None
    execution_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "mitre": self.mitre.to_dict(),
            "triage": self.triage.to_dict(),
            "containment": self.containment.to_dict(),
            "sha256_checksum": self.evidence_report.sha256_checksum,
            "alert_dispatch_results": self.alert_dispatch_results,
            "s3_vault_uri": self.s3_vault_uri,
            "local_evidence_path": self.local_evidence_path,
            "execution_duration_ms": self.execution_duration_ms,
        }


class SoarStateMachine:
    """The central engine coordinating AWS incident response workflows."""

    def __init__(
        self,
        dry_run: bool = False,
        s3_evidence_bucket: Optional[str] = None,
        sns_topic_arn: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        session: Optional[boto3.Session] = None,
        region: str = "us-east-1",
    ):
        self.dry_run = dry_run
        self.session = session
        self.region = region
        self.vault = EvidenceVault(s3_bucket=s3_evidence_bucket, session=session)
        self.dispatcher = AlertDispatcher(
            sns_topic_arn=sns_topic_arn,
            slack_webhook_url=slack_webhook_url,
            session=session,
        )

    def process_event(self, raw_event: Dict[str, Any]) -> List[IncidentResponseResult]:
        """Ingests raw EventBridge / Security Hub / GuardDuty event and executes SOAR pipeline."""
        start_time = datetime.now(timezone.utc)
        findings = FindingParser.parse(raw_event)
        results: List[IncidentResponseResult] = []

        for finding in findings:
            # 1. MITRE ATT&CK Mapping
            mitre_data = MitreMapper.map_finding(finding.finding_type)

            # 2. Risk Scoring & Triage Prioritization
            triage_data = IncidentScoringEngine.evaluate(finding)

            # 3. Containment Execution Route
            containment_result = self._route_containment(finding, triage_data)

            # 4. Forensic Evidence Vault Packaging & SHA-256 Hashing
            evidence_report = self.vault.package_evidence(
                finding=finding,
                mitre=mitre_data,
                triage=triage_data,
                containment=containment_result,
            )

            # Save locally
            local_path = str(self.vault.save_local(evidence_report))

            # Upload to S3 if configured
            s3_uri = self.vault.archive_to_s3(evidence_report)

            # 5. Alert Notification Dispatch
            alert_notification = AlertNotification(
                incident_id=finding.finding_id,
                priority=triage_data.priority.value,
                severity=finding.severity,
                composite_score=triage_data.composite_score,
                finding_type=finding.finding_type,
                resource_type=finding.resource_type,
                resource_id=finding.resource_id,
                containment_status="CONTAINED"
                if containment_result.success
                else "FAILED",
                dry_run=self.dry_run,
                mitre_tactic=mitre_data.tactic,
                mitre_technique=mitre_data.technique,
                actions_count=len(containment_result.actions_executed),
                timestamp=evidence_report.generated_at,
            )
            dispatch_results = self.dispatcher.dispatch(alert_notification)

            duration = (
                datetime.now(timezone.utc) - start_time
            ).total_seconds() * 1000.0

            results.append(
                IncidentResponseResult(
                    finding=finding,
                    mitre=mitre_data,
                    triage=triage_data,
                    containment=containment_result,
                    evidence_report=evidence_report,
                    alert_dispatch_results=dispatch_results,
                    s3_vault_uri=s3_uri,
                    local_evidence_path=local_path,
                    execution_duration_ms=round(duration, 2),
                )
            )

        return results

    def _route_containment(
        self, finding: SecurityFinding, triage: TriageAssessment
    ) -> ContainmentResult:
        """Selects and executes the appropriate service handler based on resource type."""
        # Check if containment should be skipped for low priority findings without auto-remediate
        if (
            not triage.auto_remediate_recommended
            and triage.priority == IncidentPriority.P4_LOW
        ):
            return ContainmentResult(
                resource_type=finding.resource_type,
                resource_id=finding.resource_id,
                success=True,
                dry_run=self.dry_run,
                quarantine_applied=False,
                actions_executed=[
                    RemediationAction(
                        action_name="LowPriorityAuditLogOnly",
                        status="SKIPPED",
                        details={
                            "reason": "P4_LOW priority below auto-containment threshold"
                        },
                    )
                ],
            )

        # Route by resource type
        if finding.resource_type in ["AwsIamUser", "AwsIamRole"]:
            handler = IamRemediationHandler(dry_run=self.dry_run, session=self.session)
            return handler.execute_containment(finding)

        elif finding.resource_type == "AwsEc2Instance":
            handler = Ec2RemediationHandler(
                dry_run=self.dry_run,
                session=self.session,
                region=finding.region or self.region,
            )
            return handler.execute_containment(finding)

        elif finding.resource_type == "AwsS3Bucket":
            handler = S3RemediationHandler(dry_run=self.dry_run, session=self.session)
            return handler.execute_containment(finding)

        else:
            return ContainmentResult(
                resource_type=finding.resource_type,
                resource_id=finding.resource_id,
                success=False,
                dry_run=self.dry_run,
                quarantine_applied=False,
                actions_executed=[],
                error_message=f"Unsupported resource type for automated containment: {finding.resource_type}",
            )
