"""Unit tests for FindingParser."""

from src.core.finding_parser import FindingParser


def test_parse_guardduty_event():
    event = {
        "version": "0",
        "id": "event-12345",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "id": "gd-finding-9988",
            "severity": 8.0,
            "createdAt": "2026-10-26T20:00:00.000Z",
            "title": "Exfiltrated Credentials",
            "description": "Credentials used from malicious IP",
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userName": "secops-bot",
                    "userType": "IAMUser",
                },
            },
            "service": {
                "action": {
                    "awsApiCallAction": {
                        "remoteIpDetails": {
                            "ipAddressV4": "198.51.100.22",
                            "country": {"countryName": "Germany"},
                        }
                    }
                }
            },
        },
    }

    findings = FindingParser.parse(event)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_id == "gd-finding-9988"
    assert f.resource_type == "AwsIamUser"
    assert f.resource_id == "secops-bot"
    assert f.severity == "HIGH"
    assert f.threat_actor_ip == "198.51.100.22"
    assert f.threat_actor_country == "Germany"
    assert f.resource_tags.get("AccessKeyId") == "AKIAIOSFODNN7EXAMPLE"


def test_parse_securityhub_asff_event():
    event = {
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "detail": {
            "findings": [
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/s3-pub-1",
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                    "AwsAccountId": "123456789012",
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "Title": "S3.1 S3 Block Public Access setting should be enabled",
                    "Description": "Bucket is publicly accessible",
                    "Severity": {"Label": "CRITICAL", "Normalized": 90.0},
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": "arn:aws:s3:::critical-finance-lake-prod",
                            "Tags": {"Environment": "Production"},
                        }
                    ],
                }
            ]
        },
    }

    findings = FindingParser.parse(event)
    assert len(findings) == 1
    f = findings[0]
    assert f.resource_type == "AwsS3Bucket"
    assert f.resource_id == "critical-finance-lake-prod"
    assert f.severity == "CRITICAL"
    assert f.is_production is True


def test_parse_simulation_custom():
    custom = {
        "finding_id": "sim-001",
        "resource_type": "AwsEc2Instance",
        "resource_id": "i-1234567890abcdef0",
        "finding_type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": "HIGH",
    }
    findings = FindingParser.parse(custom)
    assert len(findings) == 1
    assert findings[0].resource_id == "i-1234567890abcdef0"
    assert findings[0].severity == "HIGH"
