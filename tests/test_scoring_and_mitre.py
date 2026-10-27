"""Unit tests for MitreMapper and IncidentScoringEngine."""

from src.core.finding_parser import SecurityFinding
from src.core.mitre_mapper import MitreMapper
from src.core.scoring_engine import IncidentScoringEngine, IncidentPriority


def test_mitre_mapper_exact_match():
    mitre = MitreMapper.map_finding("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration")
    assert mitre.tactic == "Credential Access"
    assert mitre.tactic_id == "TA0006"
    assert mitre.technique_id == "T1528"


def test_mitre_mapper_prefix_fallback():
    mitre = MitreMapper.map_finding("CryptoCurrency:EC2/UnknownNewCoinMiner")
    assert mitre.tactic == "Impact"
    assert mitre.technique_id == "T1496"


def test_scoring_engine_production_admin_multiplier():
    finding = SecurityFinding(
        finding_id="score-test-1",
        source="aws.guardduty",
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        title="Admin Key Compromise",
        description="Admin credentials leaked",
        severity="CRITICAL",
        severity_score=85.0,
        resource_type="AwsIamUser",
        resource_id="admin-master-user",
        resource_arn="arn:aws:iam::123:user/admin-master-user",
        account_id="123456789012",
        region="us-east-1",
        is_production=True,
    )

    triage = IncidentScoringEngine.evaluate(finding)
    assert triage.priority == IncidentPriority.P1_CRITICAL
    assert triage.composite_score == 100.0  # 85 + 15 (prod) + 25 (admin) capped at 100
    assert triage.auto_remediate_recommended is True
    assert triage.blast_radius == "ACCOUNT_WIDE"


def test_scoring_engine_low_severity_non_prod():
    finding = SecurityFinding(
        finding_id="score-test-2",
        source="aws.securityhub",
        finding_type="Policy:S3/LowRiskNotice",
        title="Minor config notice",
        description="Test",
        severity="LOW",
        severity_score=20.0,
        resource_type="AwsS3Bucket",
        resource_id="dev-scratch-bucket",
        resource_arn="arn:aws:s3:::dev-scratch-bucket",
        account_id="123456789012",
        region="us-east-1",
        is_production=False,
    )

    triage = IncidentScoringEngine.evaluate(finding)
    assert triage.priority == IncidentPriority.P4_LOW
    assert triage.auto_remediate_recommended is False
