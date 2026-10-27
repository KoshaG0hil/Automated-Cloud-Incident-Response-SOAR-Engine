"""Unit tests for Ec2RemediationHandler with moto."""

import boto3

from src.core.finding_parser import SecurityFinding
from src.handlers.ec2_handler import Ec2RemediationHandler


def test_ec2_quarantine_live_mock(mocked_aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Setup VPC, Subnet, and EC2 instance
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]
    subnet_id = subnet["SubnetId"]

    # Create dummy instance
    instances = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet_id,
    )["Instances"]
    instance_id = instances[0]["InstanceId"]

    finding = SecurityFinding(
        finding_id="gd-test-ec2",
        source="aws.guardduty",
        finding_type="CryptoCurrency:EC2/BitcoinTool.B!DNS",
        title="Crypto Miner Detected",
        description="Bitcoin DNS activity",
        severity="HIGH",
        severity_score=80.0,
        resource_type="AwsEc2Instance",
        resource_id=instance_id,
        resource_arn=f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}",
        account_id="123456789012",
        region="us-east-1",
    )

    handler = Ec2RemediationHandler(dry_run=False, region="us-east-1")
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.quarantine_applied is True

    # Verify instance was moved to isolation security group
    desc = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    assigned_sgs = [g["GroupName"] for g in desc.get("SecurityGroups", [])]
    assert Ec2RemediationHandler.ISOLATION_SG_NAME in assigned_sgs

    # Verify tags applied
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert tags.get("SOAR_Status") == "Quarantined"
    assert tags.get("SOAR_IncidentId") == "gd-test-ec2"


def test_ec2_quarantine_dry_run():
    finding = SecurityFinding(
        finding_id="gd-dry-ec2",
        source="aws.guardduty",
        finding_type="Trojan:EC2/BlackholeTraffic",
        title="Dry Run EC2",
        description="Test",
        severity="HIGH",
        severity_score=80.0,
        resource_type="AwsEc2Instance",
        resource_id="i-0123456789abcdef0",
        resource_arn="arn:aws:ec2:us-east-1:123:instance/i-0123456789abcdef0",
        account_id="123",
        region="us-east-1",
    )

    handler = Ec2RemediationHandler(dry_run=True, region="us-east-1")
    result = handler.execute_containment(finding)

    assert result.success is True
    assert result.dry_run is True
    for action in result.actions_executed:
        assert action.status == "DRY_RUN"
