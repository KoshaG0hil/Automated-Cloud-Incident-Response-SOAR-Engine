"""
Finding Parser Module.
Normalizes AWS GuardDuty and AWS Security Hub (ASFF) events into unified SecurityFinding models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SecurityFinding:
    """Normalized security finding representation across AWS security providers."""

    finding_id: str
    source: str  # e.g., "aws.guardduty", "aws.securityhub", "simulation"
    finding_type: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    severity_score: float  # 0.0 to 100.0 scale
    resource_type: str  # AwsIamUser, AwsEc2Instance, AwsS3Bucket, AwsIamRole
    resource_id: str
    resource_arn: str
    account_id: str
    region: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    threat_actor_ip: Optional[str] = None
    threat_actor_country: Optional[str] = None
    threat_actor_city: Optional[str] = None
    resource_tags: Dict[str, str] = field(default_factory=dict)
    is_production: bool = False
    raw_finding: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "account_id": self.account_id,
            "region": self.region,
            "created_at": self.created_at,
            "threat_actor_ip": self.threat_actor_ip,
            "threat_actor_country": self.threat_actor_country,
            "threat_actor_city": self.threat_actor_city,
            "resource_tags": self.resource_tags,
            "is_production": self.is_production,
        }


class FindingParser:
    """Ingests and parses raw JSON payloads from EventBridge, GuardDuty, and Security Hub."""

    @staticmethod
    def parse(payload: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Parses an incoming payload and returns a list of normalized SecurityFinding instances.
        Supports:
          1. Direct EventBridge GuardDuty events
          2. EventBridge Security Hub findings (ASFF)
          3. Direct Security Hub finding objects
          4. Direct GuardDuty finding objects
          5. Local simulation payloads
        """
        if not isinstance(payload, dict):
            raise ValueError(f"Payload must be a dictionary, got {type(payload)}")

        # Case 1: EventBridge wrapper with detail
        if "detail" in payload and isinstance(payload["detail"], dict):
            detail_type = payload.get("detail-type", "")
            source = payload.get("source", "")
            detail = payload["detail"]

            if "GuardDuty" in detail_type or "aws.guardduty" in source:
                return [
                    FindingParser._parse_guardduty_detail(
                        detail, source or "aws.guardduty"
                    )
                ]

            if "Security Hub" in detail_type or "aws.securityhub" in source:
                findings_list = detail.get("findings", [])
                if findings_list:
                    return [
                        FindingParser._parse_securityhub_finding(
                            f, source or "aws.securityhub"
                        )
                        for f in findings_list
                    ]
                return [
                    FindingParser._parse_securityhub_finding(
                        detail, source or "aws.securityhub"
                    )
                ]

        # Case 2: Security Hub ASFF list under "findings"
        if "findings" in payload and isinstance(payload["findings"], list):
            return [
                FindingParser._parse_securityhub_finding(f, "aws.securityhub")
                for f in payload["findings"]
            ]

        # Case 3: Direct GuardDuty finding
        if "type" in payload and "service" in payload and "schemaVersion" in payload:
            return [FindingParser._parse_guardduty_detail(payload, "aws.guardduty")]

        # Case 4: Direct Security Hub finding
        if "SchemaVersion" in payload and "Id" in payload and "ProductArn" in payload:
            return [
                FindingParser._parse_securityhub_finding(payload, "aws.securityhub")
            ]

        # Case 5: Simulation or custom format
        return [FindingParser._parse_custom_finding(payload)]

    @staticmethod
    def _parse_guardduty_detail(detail: Dict[str, Any], source: str) -> SecurityFinding:
        """Parses native GuardDuty finding JSON schema."""
        finding_id = detail.get("id", detail.get("Id", "unknown-gd-id"))
        finding_type = detail.get("type", detail.get("Type", "Unknown/GuardDuty"))
        title = detail.get("title", detail.get("Title", finding_type))
        description = detail.get("description", detail.get("Description", ""))
        severity_raw = float(detail.get("severity", detail.get("Severity", 5.0)))

        # GuardDuty severity scale is 0.1 to 8.9+
        # 0.1 - 3.9: Low, 4.0 - 6.9: Medium, 7.0 - 8.9: High, 9.0+: Critical
        severity_label = "LOW"
        if severity_raw >= 8.5:
            severity_label = "CRITICAL"
        elif severity_raw >= 7.0:
            severity_label = "HIGH"
        elif severity_raw >= 4.0:
            severity_label = "MEDIUM"

        severity_score = min(100.0, round(severity_raw * 11.1, 1))

        # Extract resource details
        resource = detail.get("resource", {})
        resource_type = resource.get("resourceType", "UnknownResource")
        account_id = detail.get("accountId", detail.get("AccountId", "unknown-account"))
        region = detail.get("region", detail.get("Region", "us-east-1"))
        created_at = detail.get("createdAt", datetime.now(timezone.utc).isoformat())

        resource_id = "unknown"
        resource_arn = "unknown"
        resource_tags: Dict[str, str] = {}

        if resource_type == "Instance":
            instance_details = resource.get("instanceDetails", {})
            resource_id = instance_details.get("instanceId", "unknown-instance")
            resource_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}"
            resource_type = "AwsEc2Instance"
            for tag in instance_details.get("tags", []):
                if isinstance(tag, dict) and "key" in tag and "value" in tag:
                    resource_tags[tag["key"]] = tag["value"]

        elif resource_type == "AccessKey":
            access_key_details = resource.get("accessKeyDetails", {})
            user_name = access_key_details.get("userName", "unknown-user")
            key_id = access_key_details.get("accessKeyId", "")
            principal_type = access_key_details.get("userType", "IAMUser")
            resource_id = user_name
            resource_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            resource_type = (
                "AwsIamUser" if principal_type == "IAMUser" else "AwsIamRole"
            )
            if key_id:
                resource_tags["AccessKeyId"] = key_id

        elif resource_type == "S3Bucket":
            s3_details = (
                resource.get("s3BucketDetails", [{}])[0]
                if resource.get("s3BucketDetails")
                else {}
            )
            resource_id = s3_details.get("name", "unknown-bucket")
            resource_arn = s3_details.get("arn", f"arn:aws:s3:::{resource_id}")
            resource_type = "AwsS3Bucket"

        # Actor details
        service = detail.get("service", {})
        action = service.get("action", {})
        network_connection = (
            action.get("networkConnectionAction", {})
            or action.get("awsApiCallAction", {})
            or action.get("portProbeAction", {})
        )
        remote_ip = network_connection.get("remoteIpDetails", {})
        threat_actor_ip = remote_ip.get("ipAddressV4")
        country_info = remote_ip.get("country", {})
        threat_actor_country = (
            country_info.get("countryName") if isinstance(country_info, dict) else None
        )
        city_info = remote_ip.get("city", {})
        threat_actor_city = (
            city_info.get("cityName") if isinstance(city_info, dict) else None
        )

        is_production = any(
            k.lower() == "environment" and v.lower() in ["prod", "production"]
            for k, v in resource_tags.items()
        )

        return SecurityFinding(
            finding_id=finding_id,
            source=source,
            finding_type=finding_type,
            title=title,
            description=description,
            severity=severity_label,
            severity_score=severity_score,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            created_at=created_at,
            threat_actor_ip=threat_actor_ip,
            threat_actor_country=threat_actor_country,
            threat_actor_city=threat_actor_city,
            resource_tags=resource_tags,
            is_production=is_production,
            raw_finding=detail,
        )

    @staticmethod
    def _parse_securityhub_finding(
        finding: Dict[str, Any], source: str
    ) -> SecurityFinding:
        """Parses AWS Security Finding Format (ASFF)."""
        finding_id = finding.get("Id", "unknown-sh-id")
        finding_type = (
            finding.get("Types", ["Unknown/SecurityHub"])[0]
            if finding.get("Types")
            else "Unknown/SecurityHub"
        )
        title = finding.get("Title", "Untitled Finding")
        description = finding.get("Description", "")

        severity_dict = finding.get("Severity", {})
        severity_label = severity_dict.get("Label", "MEDIUM").upper()
        severity_score = float(severity_dict.get("Normalized", 50.0))

        account_id = finding.get("AwsAccountId", "unknown-account")
        region = finding.get("Region", "us-east-1")
        created_at = finding.get("CreatedAt", datetime.now(timezone.utc).isoformat())

        resources = finding.get("Resources", [{}])
        primary_resource = resources[0] if resources else {}
        resource_type = primary_resource.get("Type", "UnknownResource")
        resource_id = primary_resource.get("Id", "unknown-resource")
        resource_arn = primary_resource.get("Arn", resource_id)
        resource_tags = primary_resource.get("Tags", {}) or {}

        # Normalize clean resource ID
        if resource_type == "AwsIamUser" and "/" in resource_id:
            resource_id = resource_id.split("/")[-1]
        elif resource_type == "AwsEc2Instance" and "/" in resource_id:
            resource_id = resource_id.split("/")[-1]
        elif resource_type == "AwsS3Bucket" and ":::" in resource_id:
            resource_id = resource_id.split(":::")[-1]

        # Threat actor info if present in network details
        network = finding.get("Network", {})
        threat_actor_ip = network.get("SourceIpV4")

        is_production = any(
            k.lower() == "environment" and str(v).lower() in ["prod", "production"]
            for k, v in resource_tags.items()
        )

        return SecurityFinding(
            finding_id=finding_id,
            source=source,
            finding_type=finding_type,
            title=title,
            description=description,
            severity=severity_label,
            severity_score=severity_score,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            created_at=created_at,
            threat_actor_ip=threat_actor_ip,
            resource_tags=resource_tags,
            is_production=is_production,
            raw_finding=finding,
        )

    @staticmethod
    def _parse_custom_finding(data: Dict[str, Any]) -> SecurityFinding:
        """Parses simulated test payloads and arbitrary dictionaries."""
        severity = data.get("severity", "HIGH").upper()
        severity_scores = {
            "CRITICAL": 95.0,
            "HIGH": 80.0,
            "MEDIUM": 50.0,
            "LOW": 25.0,
            "INFORMATIONAL": 5.0,
        }
        score = float(data.get("severity_score", severity_scores.get(severity, 50.0)))

        return SecurityFinding(
            finding_id=data.get(
                "finding_id", f"soar-sim-{int(datetime.now(timezone.utc).timestamp())}"
            ),
            source=data.get("source", "simulation"),
            finding_type=data.get(
                "finding_type",
                "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            ),
            title=data.get("title", "Simulated Incident Finding"),
            description=data.get(
                "description",
                "Simulated security event for automated containment testing.",
            ),
            severity=severity,
            severity_score=score,
            resource_type=data.get("resource_type", "AwsIamUser"),
            resource_id=data.get("resource_id", "dev-compromised-user"),
            resource_arn=data.get(
                "resource_arn", "arn:aws:iam::123456789012:user/dev-compromised-user"
            ),
            account_id=data.get("account_id", "123456789012"),
            region=data.get("region", "us-east-1"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            threat_actor_ip=data.get("threat_actor_ip", "198.51.100.44"),
            threat_actor_country=data.get("threat_actor_country", "Unknown"),
            threat_actor_city=data.get("threat_actor_city", "Unknown"),
            resource_tags=data.get("resource_tags", {"Environment": "Production"}),
            is_production=data.get("is_production", True),
            raw_finding=data,
        )
