"""Unit tests for IamRemediationHandler with moto."""

import boto3
from src.core.finding_parser import SecurityFinding
from src.handlers.iam_handler import IamRemediationHandler


def test_iam_containment_live_mock(mocked_aws):
    iam = boto3.client("iam", region_name="us-east-1")
    user_name = "test-compromised-developer"
    iam.create_user(UserName=user_name)
    key_resp = iam.create_access_key(UserName=user_name)
    key_id = key_resp["AccessKey"]["AccessKeyId"]

    finding = SecurityFinding(
        finding_id="gd-test-iam",
        source="aws.guardduty",
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        title="Test IAM compromise",
        description="Test",
        severity="HIGH",
        severity_score=80.0,
        resource_type="AwsIamUser",
        resource_id=user_name,
        resource_arn=f"arn:aws:iam::123456789012:user/{user_name}",
        account_id="123456789012",
        region="us-east-1",
    )

    handler = IamRemediationHandler(dry_run=False)
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.quarantine_applied is True
    assert len(result.actions_executed) == 4

    # Verify Access Key was deactivated
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    target_key = [k for k in keys if k["AccessKeyId"] == key_id][0]
    assert target_key["Status"] == "Inactive"

    # Verify Inline Policies attached
    policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    assert "SOAR-RevokeOlderSessions" in policies
    assert "SOAR-CompromisedIdentity-Containment" in policies


def test_iam_containment_dry_run():
    finding = SecurityFinding(
        finding_id="gd-dry-iam",
        source="aws.guardduty",
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        title="Test dry run",
        description="Test",
        severity="HIGH",
        severity_score=80.0,
        resource_type="AwsIamUser",
        resource_id="dry-run-user",
        resource_arn="arn:aws:iam::123:user/dry-run-user",
        account_id="123",
        region="us-east-1",
    )

    handler = IamRemediationHandler(dry_run=True)
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.dry_run is True
    for action in result.actions_executed:
        assert action.status == "DRY_RUN"
