# MITRE ATT&CK Cloud Matrix Alignment

This platform directly maps automated detection and containment capabilities to the **MITRE ATT&CK Cloud Matrix** (Enterprise Domain).

---

## 1. Mapped Tactics & Techniques

### TA0006: Credential Access
- **Technique T1528: Steal Application Access Token**
  - *Trigger Finding*: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
  - *Mitigation*: Automated STS revocation terminates all temporary access keys created from stolen role or instance profile tokens.
- **Technique T1552.001: Credentials in Files / Memory**
  - *Trigger Finding*: `UnauthorizedAccess:IAMUser/TorIPCaller`
  - *Mitigation*: Deactivates exposed IAM Access Keys within milliseconds of first anomalous invocation.

### TA0001: Initial Access
- **Technique T1078.004: Valid Accounts - Cloud Accounts**
  - *Trigger Finding*: `PenTest:IAMUser/KaliLinux`, `UnauthorizedAccess:IAMUser/ConsoleLoginSuccessNotice`
  - *Mitigation*: Immediate boundary containment policy blocks active penetration testing payloads from pivoting into lateral resources.

### TA0005: Defense Evasion
- **Technique T1562.001: Impair Defenses - Disable Cloud Logs**
  - *Trigger Finding*: `Stealth:IAMUser/CloudTrailLoggingDisabled`
  - *Mitigation*: Immediate quarantine of the actor identity and notification to restore CloudTrail trails.
- **Technique T1562: Disable Cloud Security Controls**
  - *Trigger Finding*: `Policy:S3/BucketBlockPublicAccessDisabled`
  - *Mitigation*: Automatic re-enforcement of S3 Public Access Block across all 4 account/bucket settings.

### TA0011: Command and Control
- **Technique T1071.001: Application Layer Protocol - Web Protocols**
  - *Trigger Finding*: `Trojan:EC2/BlackholeTraffic`
  - *Mitigation*: Isolation Security Group strips all ingress and egress network traffic instantly, severing C2 channels without shutting down the VM.

### TA0040: Impact
- **Technique T1496: Resource Hijacking (Cryptomining)**
  - *Trigger Finding*: `CryptoCurrency:EC2/BitcoinTool.B!DNS`
  - *Mitigation*: Host isolation prevents bill shock and terminates mining pool communication while preserving disk state via EBS snapshots.

### TA0010: Exfiltration
- **Technique T1567.002: Exfiltration to Cloud Storage**
  - *Trigger Finding*: `Policy:S3/BucketPublicReadWriteGranted`, `Exfiltration:S3/ObjectReads.Unusual`
  - *Mitigation*: Replaces bucket ACL with `private` and locks policy down to root/admin TLS traffic only.

---

## 2. Threat Coverage Heatmap

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK Matrix                             │
├─────────────────┬─────────────────┬──────────────────┬─────────────────┤
│ Initial Access  │ Defense Evasion │ Credential Access│ Impact          │
│ T1078.004 [✔]   │ T1562.001 [✔]   │ T1528      [✔]   │ T1496     [✔]   │
├─────────────────┼─────────────────┼──────────────────┼─────────────────┤
│ Command/Control │ Exfiltration    │ Collection       │ Priv Escalation │
│ T1071.001 [✔]   │ T1567.002 [✔]   │ T1530      [✔]   │ T1098.001 [✔]   │
└─────────────────┴─────────────────┴──────────────────┴─────────────────┘
```
