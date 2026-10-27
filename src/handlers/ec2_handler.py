"""
EC2 Incident Remediation Handler.
Automated host isolation, forensic EBS snapshot acquisition, and security group quarantine.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

from ..core.finding_parser import SecurityFinding
from .base_handler import BaseRemediationHandler, ContainmentResult, RemediationAction


class Ec2RemediationHandler(BaseRemediationHandler):
    """Executes network quarantine and forensic snapshot capture for compromised EC2 instances."""

    ISOLATION_SG_NAME = "SOAR-ZeroTrust-Isolation-SG"

    def __init__(self, dry_run: bool = False, session: Optional[boto3.Session] = None, region: str = "us-east-1"):
        super().__init__(dry_run=dry_run, session=session)
        self.region = region
        self.ec2_client = (
            session.client("ec2", region_name=region)
            if session
            else boto3.client("ec2", region_name=region)
        )

    def execute_containment(self, finding: SecurityFinding) -> ContainmentResult:
        instance_id = finding.resource_id
        actions: List[RemediationAction] = []
        evidence: Dict[str, Any] = {"instance_id": instance_id}
        overall_success = True

        self.logger.info(
            f"Initiating EC2 containment on {instance_id} in {self.region} (Dry-Run: {self.dry_run})"
        )

        # -------------------------------------------------------------
        # Action 1: Query Host Metadata & Attached Volumes
        # -------------------------------------------------------------
        vpc_id = "vpc-simulated"
        attached_volumes: List[str] = []
        original_sgs: List[str] = []

        if self.dry_run:
            vpc_id = "vpc-0123456789abcdef0"
            attached_volumes = ["vol-0123456789abcdef0", "vol-0fedcba9876543210"]
            original_sgs = ["sg-01111111111111111"]
            actions.append(
                RemediationAction(
                    action_name="HarvestInstanceMetadata",
                    status="DRY_RUN",
                    details={
                        "instance_id": instance_id,
                        "vpc_id": vpc_id,
                        "volumes": attached_volumes,
                        "original_sgs": original_sgs,
                    },
                )
            )
        else:
            try:
                resp = self.ec2_client.describe_instances(InstanceIds=[instance_id])
                reservations = resp.get("Reservations", [])
                if not reservations or not reservations[0].get("Instances"):
                    raise ValueError(f"Instance {instance_id} not found")

                inst = reservations[0]["Instances"][0]
                vpc_id = inst.get("VpcId", "")
                original_sgs = [g["GroupId"] for g in inst.get("SecurityGroups", [])]

                for bdm in inst.get("BlockDeviceMappings", []):
                    ebs = bdm.get("Ebs")
                    if ebs and "VolumeId" in ebs:
                        attached_volumes.append(ebs["VolumeId"])

                evidence["vpc_id"] = vpc_id
                evidence["original_security_groups"] = original_sgs
                evidence["volumes"] = attached_volumes

                actions.append(
                    RemediationAction(
                        action_name="HarvestInstanceMetadata",
                        status="SUCCESS",
                        details={
                            "vpc_id": vpc_id,
                            "volume_count": len(attached_volumes),
                            "sg_count": len(original_sgs),
                        },
                    )
                )
            except (ClientError, ValueError) as e:
                self.logger.error(f"Failed to query metadata for {instance_id}: {e}")
                actions.append(
                    RemediationAction(
                        action_name="HarvestInstanceMetadata",
                        status="FAILED",
                        error=str(e),
                    )
                )
                return ContainmentResult(
                    resource_type="AwsEc2Instance",
                    resource_id=instance_id,
                    success=False,
                    dry_run=self.dry_run,
                    actions_executed=actions,
                    error_message=str(e),
                )

        # -------------------------------------------------------------
        # Action 2: Forensic Snapshot Acquisition
        # -------------------------------------------------------------
        snapshot_ids: List[str] = []
        if self.dry_run:
            for vol_id in attached_volumes:
                sim_snap_id = f"snap-forensic-{vol_id[-8:]}"
                snapshot_ids.append(sim_snap_id)

            actions.append(
                RemediationAction(
                    action_name="CreateForensicEBSSnapshots",
                    status="DRY_RUN",
                    details={"created_snapshots": snapshot_ids},
                )
            )
        else:
            now_str = datetime.now(timezone.utc).isoformat()
            for vol_id in attached_volumes:
                try:
                    snap_resp = self.ec2_client.create_snapshot(
                        VolumeId=vol_id,
                        Description=f"SOAR Forensic Snapshot for Incident {finding.finding_id} on {instance_id}",
                        TagSpecifications=[
                            {
                                "ResourceType": "snapshot",
                                "Tags": [
                                    {"Key": "SOAR_ForensicSnapshot", "Value": "true"},
                                    {"Key": "SOAR_IncidentId", "Value": finding.finding_id},
                                    {"Key": "SOAR_SourceInstance", "Value": instance_id},
                                    {"Key": "SOAR_SourceVolume", "Value": vol_id},
                                    {"Key": "ChainOfCustodyTimestamp", "Value": now_str},
                                ],
                            }
                        ],
                    )
                    snapshot_ids.append(snap_resp.get("SnapshotId", "unknown-snap"))
                except ClientError as e:
                    self.logger.error(f"Failed to snapshot volume {vol_id}: {e}")
                    overall_success = False

            actions.append(
                RemediationAction(
                    action_name="CreateForensicEBSSnapshots",
                    status="SUCCESS" if snapshot_ids else "FAILED",
                    details={"created_snapshots": snapshot_ids},
                    error=None if snapshot_ids else "Failed to capture volume snapshots",
                )
            )

        evidence["forensic_snapshots"] = snapshot_ids

        # -------------------------------------------------------------
        # Action 3: Identify or Create Zero-Trust Isolation Security Group
        # -------------------------------------------------------------
        isolation_sg_id = ""
        if self.dry_run:
            isolation_sg_id = "sg-0999999999isolation"
            actions.append(
                RemediationAction(
                    action_name="EnsureIsolationSecurityGroup",
                    status="DRY_RUN",
                    details={"isolation_sg_id": isolation_sg_id, "rules": "0 Ingress, 0 Egress"},
                )
            )
        else:
            try:
                # Check if group already exists in the VPC
                sgs_resp = self.ec2_client.describe_security_groups(
                    Filters=[
                        {"Name": "group-name", "Values": [self.ISOLATION_SG_NAME]},
                        {"Name": "vpc-id", "Values": [vpc_id]},
                    ]
                )
                if sgs_resp.get("SecurityGroups"):
                    isolation_sg_id = sgs_resp["SecurityGroups"][0]["GroupId"]
                else:
                    # Create empty security group
                    create_resp = self.ec2_client.create_security_group(
                        GroupName=self.ISOLATION_SG_NAME,
                        Description="SOAR Automated Host Isolation SG - 0 Ingress, 0 Egress",
                        VpcId=vpc_id,
                    )
                    isolation_sg_id = create_resp["GroupId"]

                    # Remove default egress rule created by AWS
                    try:
                        self.ec2_client.revoke_security_group_egress(
                            GroupId=isolation_sg_id,
                            IpPermissions=[
                                {
                                    "IpProtocol": "-1",
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                }
                            ],
                        )
                    except ClientError:
                        pass  # Rule might already be empty

                actions.append(
                    RemediationAction(
                        action_name="EnsureIsolationSecurityGroup",
                        status="SUCCESS",
                        details={"isolation_sg_id": isolation_sg_id, "mode": "Zero-Ingress-Zero-Egress"},
                    )
                )
            except ClientError as e:
                self.logger.error(f"Failed to ensure isolation security group: {e}")
                actions.append(
                    RemediationAction(
                        action_name="EnsureIsolationSecurityGroup",
                        status="FAILED",
                        error=str(e),
                    )
                )
                overall_success = False

        # -------------------------------------------------------------
        # Action 4: Swap Security Groups to Isolate Host
        # -------------------------------------------------------------
        if isolation_sg_id:
            if self.dry_run:
                actions.append(
                    RemediationAction(
                        action_name="SwapInstanceSecurityGroups",
                        status="DRY_RUN",
                        details={
                            "previous_sgs": original_sgs,
                            "new_sgs": [isolation_sg_id],
                        },
                    )
                )
            else:
                try:
                    self.ec2_client.modify_instance_attribute(
                        InstanceId=instance_id,
                        Groups=[isolation_sg_id],
                    )
                    actions.append(
                        RemediationAction(
                            action_name="SwapInstanceSecurityGroups",
                            status="SUCCESS",
                            details={
                                "previous_sgs": original_sgs,
                                "isolated_sg": isolation_sg_id,
                            },
                        )
                    )
                except ClientError as e:
                    self.logger.error(f"Failed to swap security groups on {instance_id}: {e}")
                    actions.append(
                        RemediationAction(
                            action_name="SwapInstanceSecurityGroups",
                            status="FAILED",
                            error=str(e),
                        )
                    )
                    overall_success = False

        # -------------------------------------------------------------
        # Action 5: Tag Instance with Containment Metadata
        # -------------------------------------------------------------
        quarantine_tags = [
            {"Key": "SOAR_Status", "Value": "Quarantined"},
            {"Key": "SOAR_IncidentId", "Value": finding.finding_id},
            {"Key": "SOAR_IsolatedAt", "Value": datetime.now(timezone.utc).isoformat()},
        ]

        if self.dry_run:
            actions.append(
                RemediationAction(
                    action_name="TagQuarantinedInstance",
                    status="DRY_RUN",
                    details={"tags": quarantine_tags},
                )
            )
        else:
            try:
                self.ec2_client.create_tags(
                    Resources=[instance_id],
                    Tags=quarantine_tags,
                )
                actions.append(
                    RemediationAction(
                        action_name="TagQuarantinedInstance",
                        status="SUCCESS",
                        details={"tags": quarantine_tags},
                    )
                )
            except ClientError as e:
                self.logger.warning(f"Failed to tag EC2 instance {instance_id}: {e}")

        return ContainmentResult(
            resource_type="AwsEc2Instance",
            resource_id=instance_id,
            success=overall_success,
            dry_run=self.dry_run,
            quarantine_applied=overall_success,
            actions_executed=actions,
            evidence_collected=evidence,
        )
