# Incident Response Runbooks & Containment Standard Operating Procedures (SOP)

This document provides step-by-step Standard Operating Procedures (SOP) for cloud security analysts responding to automated containment events triggered by the SOAR engine.

---

## SOP-01: Compromised IAM User Containment (Playbook `PLAYBOOK-IAM-001`)

### Trigger Scenarios
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- `Stealth:IAMUser/CloudTrailLoggingDisabled`
- `PenTest:IAMUser/KaliLinux`

### Automated Actions Executed
1. **Revoke Active STS Sessions**: Attached inline policy `SOAR-RevokeOlderSessions` with condition `aws:CurrentTime < [Timestamp]`.
2. **Access Key Invalidation**: Set all active IAM access keys for the identity to `Inactive`.
3. **Quarantine Deny Policy**: Attached inline policy `SOAR-CompromisedIdentity-Containment` with explicit `Deny` on `*` resources.
4. **Evidence Archival**: Captured principal details and generated SHA-256 signed evidence report in S3.

### Post-Containment Analyst Checklist
1. Review CloudTrail events for the principal 24 hours prior to the incident:
   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME>
   ```
2. Verify if additional IAM users, roles, or API keys were created by this identity.
3. Once the identity owner is confirmed and workstations scanned for infostealer malware:
   - Rotate access keys: `aws iam create-access-key --user-name <USERNAME>`
   - Enforce hardware MFA token.
   - Delete the quarantine policy to restore authorized access:
     ```bash
     aws iam delete-user-policy --user-name <USERNAME> --policy-name SOAR-CompromisedIdentity-Containment
     ```

---

## SOP-02: EC2 Host Isolation & Forensics (Playbook `PLAYBOOK-EC2-002`)

### Trigger Scenarios
- `Trojan:EC2/BlackholeTraffic`
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`
- `Backdoor:EC2/Spambot`

### Automated Actions Executed
1. **Forensic EBS Snapshot**: Snapshot created for every attached volume tagged with `SOAR_ForensicSnapshot=true` and `ChainOfCustodyTimestamp`.
2. **Zero-Trust Network Isolation**: Removed all existing Security Groups; attached `SOAR-ZeroTrust-Isolation-SG` (0 ingress, 0 egress).
3. **Quarantine Tagging**: Applied tag `SOAR_Status=Quarantined`.

### Post-Containment Analyst Checklist
1. Retrieve forensic snapshot ID from the incident evidence file:
   ```bash
   aws ec2 describe-snapshots --filters "Name=tag:SOAR_IncidentId,Values=<INCIDENT_ID>"
   ```
2. Create forensic analysis volume in an isolated sandbox VPC:
   ```bash
   aws ec2 create-volume --snapshot-id <SNAPSHOT_ID> --availability-zone us-east-1a --volume-type gp3
   ```
3. Attach to a dedicated forensic workstation AMI (e.g. SANS SIFT Workstation) as read-only.
4. Perform file timeline analysis, check `/var/log`, `/tmp`, and scheduled cron jobs.
5. Decommission or rebuild the compromised instance from the golden image repository.

---

## SOP-03: Public S3 Bucket Lockdown (Playbook `PLAYBOOK-S3-003`)

### Trigger Scenarios
- `Policy:S3/BucketPublicReadWriteGranted`
- `Exfiltration:S3/ObjectReads.Unusual`

### Automated Actions Executed
1. **Public Access Block**: Enabled `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.
2. **ACL Reset**: Set bucket ACL to `private`.
3. **Enforce TLS**: Applied policy requiring TLS/HTTPS encryption in transit.

### Post-Containment Analyst Checklist
1. Inspect S3 access logs and CloudTrail S3 Data Events during the exposure window.
2. Verify if sensitive PII, PHI, or credentials were listed or downloaded by unauthorized IP addresses.
3. Coordinate with data asset owner to determine legitimate business access requirements.
