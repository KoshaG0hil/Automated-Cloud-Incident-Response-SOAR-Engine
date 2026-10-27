"""
IAM Incident Remediation Handler.
Automated containment for compromised IAM credentials, active session revocation, and explicit deny-all isolation.
"""

from datetime import datetime, timezone
import json
from typing import List, Optional
import boto3
from botocore.exceptions import ClientError

from ..core.finding_parser import SecurityFinding
from .base_handler import BaseRemediationHandler, ContainmentResult, RemediationAction


class IamRemediationHandler(BaseRemediationHandler):
    """Orchestrates containment for compromised AWS IAM Users and Roles."""

    def __init__(self, dry_run: bool = False, session: Optional[boto3.Session] = None):
        super().__init__(dry_run=dry_run, session=session)
        self.iam_client = session.client("iam") if session else boto3.client("iam")

    def execute_containment(self, finding: SecurityFinding) -> ContainmentResult:
        user_name = finding.resource_id
        actions: List[RemediationAction] = []
        evidence: dict = {"user_name": user_name, "account_id": finding.account_id}
        overall_success = True

        self.logger.info(
            f"Initiating IAM containment on {user_name} (Dry-Run: {self.dry_run})"
        )

        # -------------------------------------------------------------
        # Action 1: Invalidate Active STS Temporary Sessions
        # -------------------------------------------------------------
        revoke_policy_name = "SOAR-RevokeOlderSessions"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        revoke_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["*"],
                    "Resource": ["*"],
                    "Condition": {"DateLessThan": {"aws:CurrentTime": now_iso}},
                }
            ],
        }

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="RevokeActiveSTSSessions",
                    status="DRY_RUN",
                    details={"revocation_timestamp": now_iso, "policy_doc": revoke_policy_doc},
                )
            )
        else:
            try:
                self.iam_client.put_user_policy(
                    UserName=user_name,
                    PolicyName=revoke_policy_name,
                    PolicyDocument=json.dumps(revoke_policy_doc),
                )
                actions.append(
                    RemediationAction(
                        action_name="RevokeActiveSTSSessions",
                        status="SUCCESS",
                        details={"revocation_timestamp": now_iso, "policy": revoke_policy_name},
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to revoke STS sessions for {user_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="RevokeActiveSTSSessions",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        # -------------------------------------------------------------
        # Action 2: Deactivate Active Access Keys
        # -------------------------------------------------------------
        deactivated_keys: List[str] = []
        if self.dry_run:
            target_key = finding.resource_tags.get("AccessKeyId", "AKIA_SIMULATED_KEY_123")
            deactivated_keys.append(target_key)
            actions.append(
                RemediationAction(
                    action_name="DeactivateAccessKeys",
                    status="DRY_RUN",
                    details={"deactivated_keys": deactivated_keys, "count": 1},
                )
            )
        else:
            try:
                keys_resp = self.iam_client.list_access_keys(UserName=user_name)
                for key_metadata in keys_resp.get("AccessKeyMetadata", []):
                    key_id = key_metadata["AccessKeyId"]
                    if key_metadata.get("Status") == "Active":
                        self.iam_client.update_access_key(
                            UserName=user_name,
                            AccessKeyId=key_id,
                            Status="Inactive",
                        )
                        deactivated_keys.append(key_id)

                actions.append(
                    RemediationAction(
                        action_name="DeactivateAccessKeys",
                        status="SUCCESS",
                        details={"deactivated_keys": deactivated_keys, "count": len(deactivated_keys)},
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to deactivate access keys for {user_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="DeactivateAccessKeys",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        evidence["deactivated_keys"] = deactivated_keys

        # -------------------------------------------------------------
        # Action 3: Attach Explicit Deny-All Quarantine Policy
        # -------------------------------------------------------------
        deny_policy_name = "SOAR-CompromisedIdentity-Containment"
        deny_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SOARExplicitDenyAll",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="AttachQuarantineDenyPolicy",
                    status="DRY_RUN",
                    details={"policy_name": deny_policy_name, "mode": "Deny-All"},
                )
            )
        else:
            try:
                self.iam_client.put_user_policy(
                    UserName=user_name,
                    PolicyName=deny_policy_name,
                    PolicyDocument=json.dumps(deny_policy_doc),
                )
                actions.append(
                    RemediationAction(
                        action_name="AttachQuarantineDenyPolicy",
                        status="SUCCESS",
                        details={"policy_name": deny_policy_name, "mode": "Deny-All"},
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to attach quarantine policy to {user_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="AttachQuarantineDenyPolicy",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        # -------------------------------------------------------------
        # Action 4: Tag Resource with Quarantine Metadata
        # -------------------------------------------------------------
        quarantine_tags = [
            {"Key": "SOAR_Status", "Value": "Quarantined"},
            {"Key": "SOAR_IncidentId", "Value": finding.finding_id},
            {"Key": "SOAR_ContainedAt", "Value": datetime.now(timezone.utc).isoformat()},
        ]

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="TagCompromisedPrincipal",
                    status="DRY_RUN",
                    details={"tags": quarantine_tags},
                )
            )
        else:
            try:
                self.iam_client.tag_user(
                    UserName=user_name,
                    Tags=quarantine_tags,
                )
                actions.append(
                    RemediationAction(
                        action_name="TagCompromisedPrincipal",
                        status="SUCCESS",
                        details={"tags": quarantine_tags},
                    )
                )
            except ClientError as e:
                # Non-fatal if tagging fails
                self.logger.warning(f"Could not tag user {user_name}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="TagCompromisedPrincipal",
                        status="SKIPPED",
                        error=str(e),
                    )
                )

        return ContainmentResult(
            resource_type="AwsIamUser",
            resource_id=user_name,
            success=overall_success,
            dry_run=self.dry_run,
            quarantine_applied=overall_success,
            actions_executed=actions,
            evidence_collected=evidence,
        )
