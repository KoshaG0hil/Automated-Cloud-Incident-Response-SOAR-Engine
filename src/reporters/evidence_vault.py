"""
Forensic Evidence Vault & Chain-of-Custody Packager.
Generates cryptographically hashed (SHA-256) incident audit records and archives them to Amazon S3.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

from ..core.finding_parser import SecurityFinding
from ..core.mitre_mapper import MitreTactics
from ..core.scoring_engine import TriageAssessment
from ..handlers.base_handler import ContainmentResult

logger = logging.getLogger("soar.evidence_vault")


@dataclass
class IncidentAuditReport:
    """Tamper-evident forensic incident record."""

    incident_id: str
    generated_at: str
    finding: Dict[str, Any]
    mitre: Dict[str, str]
    triage: Dict[str, Any]
    containment: Dict[str, Any]
    sha256_checksum: str = ""

    def compute_hash(self) -> str:
        """Computes SHA-256 hash over canonical JSON representation."""
        data_to_hash = {
            "incident_id": self.incident_id,
            "generated_at": self.generated_at,
            "finding": self.finding,
            "mitre": self.mitre,
            "triage": self.triage,
            "containment": self.containment,
        }
        canonical_str = json.dumps(data_to_hash, sort_keys=True, indent=None)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "generated_at": self.generated_at,
            "sha256_checksum": self.sha256_checksum,
            "finding": self.finding,
            "mitre": self.mitre,
            "triage": self.triage,
            "containment": self.containment,
        }


class EvidenceVault:
    """Manages forensic evidence packaging, SHA-256 hashing, and S3 archival."""

    def __init__(
        self,
        s3_bucket: Optional[str] = None,
        session: Optional[boto3.Session] = None,
        local_output_dir: str = "reports",
    ):
        self.s3_bucket = s3_bucket
        self.s3_client = session.client("s3") if session and s3_bucket else None
        self.local_output_dir = Path(local_output_dir)
        self.local_output_dir.mkdir(parents=True, exist_ok=True)

    def package_evidence(
        self,
        finding: SecurityFinding,
        mitre: MitreTactics,
        triage: TriageAssessment,
        containment: ContainmentResult,
    ) -> IncidentAuditReport:
        """Assembles, signs, and packages incident forensic data."""
        now_str = datetime.now(timezone.utc).isoformat()
        report = IncidentAuditReport(
            incident_id=finding.finding_id,
            generated_at=now_str,
            finding=finding.to_dict(),
            mitre=mitre.to_dict(),
            triage=triage.to_dict(),
            containment=containment.to_dict(),
        )
        report.sha256_checksum = report.compute_hash()
        return report

    def save_local(self, report: IncidentAuditReport) -> Path:
        """Saves report to local directory."""
        filename = (
            f"evidence_{report.incident_id.replace(':', '_').replace('/', '_')}.json"
        )
        target_path = self.local_output_dir / filename
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"Forensic evidence saved locally: {target_path}")
        return target_path

    def archive_to_s3(self, report: IncidentAuditReport) -> Optional[str]:
        """Archives evidence JSON to immutable Amazon S3 bucket with metadata."""
        if not self.s3_bucket:
            return None

        key = f"incidents/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{report.incident_id}.json"
        payload_bytes = json.dumps(report.to_dict(), indent=2).encode("utf-8")

        try:
            client = self.s3_client or boto3.client("s3")
            client.put_object(
                Bucket=self.s3_bucket,
                Key=key,
                Body=payload_bytes,
                ContentType="application/json",
                Metadata={
                    "soar-incident-id": report.incident_id,
                    "soar-sha256": report.sha256_checksum,
                    "soar-priority": report.triage.get("priority", "UNKNOWN"),
                },
            )
            s3_uri = f"s3://{self.s3_bucket}/{key}"
            logger.info(f"Forensic evidence archived to S3: {s3_uri}")
            return s3_uri
        except ClientError as e:
            logger.error(f"Failed to archive evidence to S3 ({self.s3_bucket}): {e}")
            return None
