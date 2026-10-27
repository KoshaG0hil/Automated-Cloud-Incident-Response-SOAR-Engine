"""End-to-end integration tests for SoarStateMachine and Lambda handler."""

import json

from src.lambda_handler import lambda_handler
from src.orchestrator.state_machine import SoarStateMachine


def test_state_machine_end_to_end_simulation():
    raw_event = {
        "finding_id": "sim-e2e-001",
        "source": "aws.guardduty",
        "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "title": "Exfiltrated IAM credentials",
        "description": "Simulation event",
        "severity": "CRITICAL",
        "severity_score": 90.0,
        "resource_type": "AwsIamUser",
        "resource_id": "sim-analyst",
        "resource_arn": "arn:aws:iam::123:user/sim-analyst",
        "account_id": "123456789012",
        "region": "us-east-1",
        "is_production": True,
    }

    engine = SoarStateMachine(dry_run=True)
    results = engine.process_event(raw_event)

    assert len(results) == 1
    res = results[0]
    assert res.finding.finding_id == "sim-e2e-001"
    assert res.triage.priority.value == "P1_CRITICAL"
    assert res.mitre.technique_id == "T1528"
    assert res.containment.success is True
    assert res.evidence_report.sha256_checksum != ""
    assert len(res.evidence_report.sha256_checksum) == 64


def test_lambda_handler_invocation():
    event = {
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "type": "Trojan:EC2/BlackholeTraffic",
            "id": "lambda-gd-99",
            "severity": 7.5,
            "title": "Trojan Traffic",
            "description": "EC2 C2 outbound traffic",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-09988776655443322",
                    "tags": [{"key": "Environment", "value": "Production"}],
                },
            },
        },
    }

    response = lambda_handler(event, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["processed_count"] == 1
    assert body["incidents"][0]["incident_id"] == "lambda-gd-99"
    assert body["incidents"][0]["priority"] in ["P1_CRITICAL", "P2_HIGH"]
