# System Architecture & Technical Specifications

## 1. Architectural Philosophy

The **Automated Cloud Incident Response & Threat Hunting SOAR Engine** is built on Zero-Trust principles and modern Cloud Security Operations (SecOps) practices. The primary objective is to drive **Mean Time to Remediate (MTTR)** from industry averages of hours or days down to **sub-second automated containment**, preventing lateral movement and data exfiltration while maintaining an immutable, legally defensible chain of custody.

---

## 2. End-to-End Event Lifecycle Flow

```
   ┌─────────────────────────────────────────────────────────────┐
   │                  Threat Detection Tier                      │
   │  Amazon GuardDuty (ML Anomaly, DNS C2, Credential Exfil)    │
   │  AWS Security Hub (ASFF, CIS Benchmarks, FSBP Rules)        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │ EventBridge Bus
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                  Event Ingestion & Routing                  │
   │  Amazon EventBridge Rules (Severity >= 7.0 / High/Critical)  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │ Invocation
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │          AWS Step Functions SOAR State Machine              │
   │                                                             │
   │  1. Ingestion: Normalizes finding to SecurityFinding format │
   │  2. Threat Intel: Maps vector to MITRE ATT&CK Cloud Matrix  │
   │  3. Triage Scoring: Compound risk assessment (P1 to P4)     │
   │  4. Route Selection: Decides target resource containment    │
   └───────┬──────────────────────┬──────────────────────┬───────┘
           │                      │                      │
           ▼                      ▼                      ▼
 ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
 │   IAM Containment │  │  EC2 Quarantine   │  │   S3 Lockdown     │
 │ - Revoke STS      │  │ - EBS Snapshots   │  │ - Enforce PAB     │
 │ - Deactivate Keys │  │ - Isolation SG    │  │ - Private ACL     │
 │ - Deny-All Policy │  │ - Tag Quarantine  │  │ - TLS Only Policy │
 └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
           │                      │                      │
           └──────────────────────┼──────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │               Forensic Evidence Packaging                   │
   │  - Canonical JSON transformation                            │
   │  - Cryptographic SHA-256 Digest Signature                   │
   │  - Immutable S3 Object Lock Evidence Vault                  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                 Real-Time SecOps Alerting                   │
   │  - Amazon SNS Topic (PagerDuty / Email / SMS)               │
   │  - Interactive Slack Block Kit Webhooks                     │
   └─────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Matrix & Containment Runbooks

| Resource Type | Detection Vectors | Automated Containment Action | Rollback / Recovery |
| :--- | :--- | :--- | :--- |
| **IAM User / Credential** | `InstanceCredentialExfiltration`<br>`CloudTrailLoggingDisabled`<br>`KaliLinux` | 1. Invalidate STS sessions via inline condition<br>2. Set all Access Keys to `Inactive`<br>3. Attach `SOAR-CompromisedIdentity-Containment` | Remove deny policy after credential rotation and MFA reset |
| **EC2 Instance** | `BitcoinTool.B!DNS`<br>`BlackholeTraffic`<br>`Backdoor:EC2/Spambot` | 1. Snapshot all attached EBS volumes<br>2. Detach existing SGs; attach `SOAR-Isolation-SG` (0 ingress/egress)<br>3. Apply `SOAR_Status=Quarantined` tag | Mount snapshot to sandbox AMI for forensic memory/disk dump |
| **S3 Bucket** | `BucketPublicReadWriteGranted`<br>`BulkObjectRetrieval`<br>`ObjectReads.Unusual` | 1. Enforce all 4 Public Access Block rules<br>2. Reset ACL to `private`<br>3. Attach strict HTTPS/TLS quarantine policy | Update bucket policy to approved VPC endpoints or identities |

---

## 4. Cryptographic Forensic Integrity

Every incident processed by the engine generates a canonical audit manifest that records:
1. Exact finding metadata (Threat actor IP, geolocation, generator ID)
2. Normalized severity score and calculated environmental multipliers
3. MITRE ATT&CK taxonomy mapping
4. Every API call executed with AWS response timestamps and request IDs
5. Target resource pre- and post-state

The engine calculates a **SHA-256 cryptographic digest** over the canonical representation. When uploaded to the S3 Evidence Vault, the hash is stored as S3 object metadata and verified against future tampering, ensuring legal admissibility for SOC2 and ISO27001 compliance.
