"""
Alert Dispatcher Module.
Dispatches high-fidelity incident containment alerts to Amazon SNS topics and Slack webhooks.
"""

from dataclasses import dataclass
import json
import logging
import urllib.request
from typing import Any, Dict, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("soar.alert_dispatcher")


@dataclass
class AlertNotification:
    """Consolidated alert payload."""

    incident_id: str
    priority: str
    severity: str
    composite_score: float
    finding_type: str
    resource_type: str
    resource_id: str
    containment_status: str
    dry_run: bool
    mitre_tactic: str
    mitre_technique: str
    actions_count: int
    timestamp: str


class AlertDispatcher:
    """Dispatches notifications across enterprise channels (SNS, Slack, Console)."""

    def __init__(
        self,
        sns_topic_arn: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        session: Optional[boto3.Session] = None,
    ):
        self.sns_topic_arn = sns_topic_arn
        self.slack_webhook_url = slack_webhook_url
        self.sns_client = session.client("sns") if session and sns_topic_arn else None

    def dispatch(self, alert: AlertNotification) -> Dict[str, Any]:
        """Dispatches notification to all configured destinations."""
        results = {"console": True, "sns": False, "slack": False}

        # 1. Console Log Dispatch
        icon = "🚨" if alert.priority in ["P1_CRITICAL", "P2_HIGH"] else "⚠️"
        dry_str = " [DRY-RUN]" if alert.dry_run else ""
        logger.info(
            f"{icon} SOAR Incident Alert{dry_str}: {alert.priority} | {alert.finding_type} on {alert.resource_id} | Status: {alert.containment_status}"
        )

        # 2. Amazon SNS Dispatch
        if self.sns_topic_arn:
            results["sns"] = self._send_sns(alert)

        # 3. Slack Webhook Dispatch
        if self.slack_webhook_url:
            results["slack"] = self._send_slack(alert)

        return results

    def _send_sns(self, alert: AlertNotification) -> bool:
        """Publishes formatted message to Amazon SNS."""
        try:
            client = self.sns_client or boto3.client("sns")
            subject = f"[{alert.priority}] AWS SOAR Incident: {alert.resource_id}"[:100]
            message_body = (
                f"=== AWS SOAR INCIDENT CONTAINMENT ALERT ===\n\n"
                f"Incident ID        : {alert.incident_id}\n"
                f"Priority           : {alert.priority} (Composite Risk Score: {alert.composite_score}/100)\n"
                f"Finding Type       : {alert.finding_type}\n"
                f"Affected Resource  : {alert.resource_type} ({alert.resource_id})\n"
                f"Containment Status : {alert.containment_status} (Actions: {alert.actions_count})\n"
                f"Execution Mode     : {'DRY-RUN' if alert.dry_run else 'ACTIVE REMEDIATION'}\n"
                f"MITRE ATT&CK       : {alert.mitre_tactic} ({alert.mitre_technique})\n"
                f"Timestamp (UTC)    : {alert.timestamp}\n\n"
                f"Check CloudWatch & S3 Evidence Vault for full forensic audit logs."
            )

            client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject,
                Message=message_body,
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to publish alert to SNS ({self.sns_topic_arn}): {e}")
            return False

    def _send_slack(self, alert: AlertNotification) -> bool:
        """Sends rich Block Kit payload to Slack webhook."""
        try:
            color = "#E01E5A" if "CRITICAL" in alert.priority else "#ECB22E"
            slack_payload = {
                "attachments": [
                    {
                        "color": color,
                        "blocks": [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": f"🛡️ SOAR Containment Triggered ({alert.priority})",
                                    "emoji": True,
                                },
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{alert.incident_id}`"},
                                    {"type": "mrkdwn", "text": f"*Risk Score:*\n*{alert.composite_score} / 100*"},
                                    {"type": "mrkdwn", "text": f"*Resource:*\n`{alert.resource_id}`"},
                                    {"type": "mrkdwn", "text": f"*Status:*\n*{alert.containment_status}*"},
                                    {"type": "mrkdwn", "text": f"*Finding:*\n_{alert.finding_type}_"},
                                    {"type": "mrkdwn", "text": f"*MITRE:*\n{alert.mitre_tactic} ({alert.mitre_technique})"},
                                ],
                            },
                        ],
                    }
                ]
            }

            req = urllib.request.Request(
                self.slack_webhook_url,
                data=json.dumps(slack_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except Exception as e:
            logger.warning(f"Failed to dispatch Slack alert: {e}")
            return False
