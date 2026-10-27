"""
AWS Lambda Entrypoint Handler.
Processes Amazon EventBridge events from GuardDuty and Security Hub for serverless SOAR execution.
"""

import json
import logging
import os
from typing import Any, Dict

from .orchestrator.state_machine import SoarStateMachine

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler function.
    Triggered by Amazon EventBridge rules filtering GuardDuty and Security Hub findings.
    """
    logger.info(f"Received SOAR trigger event: {json.dumps(event, default=str)}")

    # Load runtime environment configuration
    dry_run = os.environ.get("SOAR_DRY_RUN", "false").lower() in ["true", "1", "yes"]
    s3_evidence_bucket = os.environ.get("EVIDENCE_S3_BUCKET")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    region = os.environ.get("AWS_REGION", "us-east-1")

    engine = SoarStateMachine(
        dry_run=dry_run,
        s3_evidence_bucket=s3_evidence_bucket,
        sns_topic_arn=sns_topic_arn,
        slack_webhook_url=slack_webhook_url,
        region=region,
    )

    try:
        results = engine.process_event(event)
        summary = [
            {
                "incident_id": r.finding.finding_id,
                "priority": r.triage.priority.value,
                "resource": r.finding.resource_id,
                "containment_status": "SUCCESS" if r.containment.success else "FAILED",
                "sha256": r.evidence_report.sha256_checksum,
                "s3_vault_uri": r.s3_vault_uri,
            }
            for r in results
        ]

        logger.info(f"SOAR Execution successfully processed {len(results)} findings.")
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "SOAR processing completed successfully",
                    "processed_count": len(results),
                    "incidents": summary,
                }
            ),
        }
    except Exception as e:
        logger.error(f"Fatal error executing SOAR Lambda handler: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
