"""
S3 Incident Remediation Handler.
Automated containment for public S3 buckets, object exfiltration, and insecure ACL exposure.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

from ..core.finding_parser import SecurityFinding
from .base_handler import BaseRemediationHandler, ContainmentResult, RemediationAction


class S3RemediationHandler(BaseRemediationHandler):
    """Executes public access block enforcement and ACL lockdown on compromised S3 buckets."""

    def __init__(self, dry_run: bool = False, session: Optional[boto3.Session] = None):
        super().__init__(dry_run=dry_run, session=session)
        self.s3_client = session.client("s3") if session else boto3.client("s3")

    def execute_containment(self, finding: SecurityFinding) -> ContainmentResult:
        bucket_name = finding.resource_id
        actions: List[RemediationAction] = []
        evidence: Dict[str, Any] = {"bucket_name": bucket_name, "account_id": finding.account_id}
        overall_success = True

        self.logger.info(
            f"Initiating S3 lockdown on bucket '{bucket_name}' (Dry-Run: {self.dry_run})"
        )

        # -------------------------------------------------------------
        # Action 1: Enforce S3 Public Access Block
        # -------------------------------------------------------------
        pab_config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="EnforcePublicAccessBlock",
                    status="DRY_RUN",
                    details=pab_config,
                )
            )
        else:
            try:
                self.s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration=pab_config,
                )
                actions.append(
                    RemediationAction(
                        action_name="EnforcePublicAccessBlock",
                        status="SUCCESS",
                        details=pab_config,
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to apply Public Access Block to {bucket_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="EnforcePublicAccessBlock",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        # -------------------------------------------------------------
        # Action 2: Reset Bucket ACL to Private
        # -------------------------------------------------------------
        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="ResetBucketAclToPrivate",
                    status="DRY_RUN",
                    details={"target_acl": "private"},
                )
            )
        else:
            try:
                self.s3_client.put_bucket_acl(
                    Bucket=bucket_name,
                    ACL="private",
                )
                actions.append(
                    RemediationAction(
                        action_name="ResetBucketAclToPrivate",
                        status="SUCCESS",
                        details={"target_acl": "private"},
                    )
                )
            except ClientError as e:
                # Some buckets enforce Object Ownership BucketOwnerEnforced where ACLs are disabled
                if "InvalidBucketAclWithObjectOwnership" in str(e):
                    actions.append(
                        RemediationAction(
                            action_name="ResetBucketAclToPrivate",
                            status="SKIPPED",
                            details={"reason": "BucketOwnerEnforced (ACLs already disabled)"},
                        )
                    )
                else:
                    self.logger.error(f"Failed to reset ACL for {bucket_name}: {e}")
                    actions.append(
                        RemediationAction(
                            action_name="ResetBucketAclToPrivate",
                            status="FAILED",
                            error=str(e),
                        )
                    )
                    overall_success = False

        # -------------------------------------------------------------
        # Action 3: Enforce TLS & Quarantine Bucket Policy
        # -------------------------------------------------------------
        quarantine_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnforceTLSRequestsOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="EnforceTLSQuarantinePolicy",
                    status="DRY_RUN",
                    details={"policy": "EnforceTLSOnly"},
                )
            )
        else:
            try:
                self.s3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(quarantine_policy),
                )
                actions.append(
                    RemediationAction(
                        action_name="EnforceTLSQuarantinePolicy",
                        status="SUCCESS",
                        details={"policy": "EnforceTLSOnly"},
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to put TLS quarantine policy on {bucket_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="EnforceTLSQuarantinePolicy",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        # -------------------------------------------------------------
        # Action 4: Tag Bucket with Remediation Audit Tags
        # -------------------------------------------------------------
        quarantine_tag_set = [
            {"Key": "SOAR_Status", "Value": "Remediated"},
            {"Key": "SOAR_IncidentId", "Value": finding.finding_id},
            {"Key": "SOAR_RemediatedAt", "Value": datetime.now(timezone.utc).isoformat()},
        ]

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="TagRemediatedBucket",
                    status="DRY_RUN",
                    details={"tags": quarantine_tag_set},
                )
            )
        else:
            try:
                self.s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={"TagSet": quarantine_tag_set},
                )
                actions.append(
                    RemediationAction(
                        action_name="TagRemediatedBucket",
                        status="SUCCESS",
                        details={"tags": quarantine_tag_set},
                    )
                )
            except ClientError as e:
                self.logger.warning(f"Could not tag bucket {bucket_name}: {e}")

        return ContainmentResult(
            resource_type="AwsS3Bucket",
            resource_id=bucket_name,
            success=overall_success,
            dry_run=self.dry_run,
            quarantine_applied=overall_success,
            actions_executed=actions,
            evidence_collected=evidence,
        )
