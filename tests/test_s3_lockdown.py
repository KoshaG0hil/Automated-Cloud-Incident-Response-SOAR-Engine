"""Unit tests for S3RemediationHandler with moto."""

import boto3
from src.core.finding_parser import SecurityFinding
from src.handlers.s3_handler import S3RemediationHandler


def test_s3_lockdown_live_mock(mocked_aws):
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "test-exposed-audit-bucket-12345"
    s3.create_bucket(Bucket=bucket_name)

    finding = SecurityFinding(
        finding_id="sechub-test-s3",
        source="aws.securityhub",
        finding_type="Policy:S3/BucketPublicReadWriteGranted",
        title="Public S3 Bucket",
        description="Public access granted",
        severity="HIGH",
        severity_score=85.0,
        resource_type="AwsS3Bucket",
        resource_id=bucket_name,
        resource_arn=f"arn:aws:s3:::{bucket_name}",
        account_id="123456789012",
        region="us-east-1",
    )

    handler = S3RemediationHandler(dry_run=False)
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.quarantine_applied is True

    # Verify Public Access Block was enforced
    pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    assert pab["BlockPublicAcls"] is True
    assert pab["IgnorePublicAcls"] is True
    assert pab["BlockPublicPolicy"] is True
    assert pab["RestrictPublicBuckets"] is True

    # Verify Tagging
    tag_set = s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    tags = {t["Key"]: t["Value"] for t in tag_set}
    assert tags.get("SOAR_Status") == "Remediated"
    assert tags.get("SOAR_IncidentId") == "sechub-test-s3"


def test_s3_lockdown_dry_run():
    finding = SecurityFinding(
        finding_id="sechub-dry-s3",
        source="aws.securityhub",
        finding_type="Policy:S3/BucketPublicReadWriteGranted",
        title="Public S3 Dry Run",
        description="Test",
        severity="HIGH",
        severity_score=85.0,
        resource_type="AwsS3Bucket",
        resource_id="dry-run-bucket",
        resource_arn="arn:aws:s3:::dry-run-bucket",
        account_id="123456789012",
        region="us-east-1",
    )

    handler = S3RemediationHandler(dry_run=True)
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.dry_run is True
    for action in result.actions_executed:
        assert action.status == "DRY_RUN"
