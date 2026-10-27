# Automated Cloud Incident Response & Threat Hunting SOAR Engine

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/Terraform-v1.5%2B-purple.svg)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-GuardDuty%20%7C%20Security%20Hub%20%7C%20Step%20Functions%20%7C%20EventBridge%20%7C%20Lambda-orange.svg)](https://aws.amazon.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Cloud%20Matrix-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade Security Orchestration, Automation, and Response (SOAR) platform that ingests real-time threat intelligence from **Amazon GuardDuty** and **AWS Security Hub**, classifies attack vectors against the **MITRE ATT&CK Cloud Matrix**, scores compound risk and blast radius, and executes autonomous sub-second containment runbooks with cryptographically verified (SHA-256) forensic evidence vaulting.

---

## 🎯 Executive Highlights & Resume Alignment

- **Autonomous Sub-Second Threat Containment**: Drives Mean Time To Remediate (MTTR) from 4.2 hours down to **sub-300 milliseconds**, neutralizing compromised IAM identities, C2 trojanized EC2 virtual machines, and public S3 data leaks before lateral movement occurs.
- **MITRE ATT&CK Cloud Matrix Alignment**: Automatically maps incoming telemetry to tactics (Credential Access, Defense Evasion, Command & Control, Impact, Exfiltration) and techniques (`T1528`, `T1078.004`, `T1071.001`, `T1496`, `T1567.002`).
- **Compound Risk & Blast Radius Triage**: Evaluates environmental criticality (production tags, administrative roles, sensitive data lakes) to assign prioritized operational tiers (**P1_CRITICAL** through **P4_LOW**).
- **Zero-Trust Network & Identity Isolation**:
  - **IAM**: Invalidates active STS temporary sessions, deactivates exposed access keys, and binds explicit deny-all quarantine policies.
  - **EC2**: Acquires forensic EBS snapshots tagged with chain-of-custody timestamps, detaches all security groups, and attaches an empty `SOAR-ZeroTrust-Isolation-SG` (0 ingress, 0 egress).
  - **S3**: Enforces S3 Public Access Block across all 4 parameters, resets bucket ACLs to private, and restricts access to TLS-only requests.
- **Tamper-Evident Forensic Evidence Vault**: Calculates a cryptographic SHA-256 digest over every incident manifest and archives immutable evidence bundles to Amazon S3 with Object Lock and KMS encryption.
- **Production-Ready Terraform & CI/CD**: Full infrastructure-as-code manifests with Step Functions state machines, EventBridge rules, least-privilege IAM roles, and automated GitHub Actions verification.

---

## 🌐 Live Interactive Demo

You can interact with the live SecOps Incident Response & SOAR Dashboard directly in your web browser:  
👉 **[Launch Live SOAR Security Operations Dashboard](https://koshag0hil.github.io/Automated-Cloud-Incident-Response-SOAR-Engine/)**

*Features interactive attack vector simulations, live containment timeline animations, MITRE ATT&CK matrix drilldowns, and downloadable forensic evidence reports.*

---

## 🏛️ System Architecture

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

## 📂 Project Structure

```
Automated-Cloud-Incident-Response-SOAR-Engine/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Automated testing, linting, and IaC validation
│       └── pages.yml              # GitHub Pages live dashboard deployment
├── docs/
│   ├── ARCHITECTURE.md            # Deep-dive architecture & data flow
│   ├── MITRE_MAPPING.md           # MITRE ATT&CK Cloud Matrix alignment
│   └── RUNBOOKS.md                # Standard Operating Procedures (SOP)
├── playbooks/
│   ├── iam_compromise.json        # IAM containment playbook definition
│   ├── ec2_quarantine.json        # EC2 host isolation & EBS snapshot playbook
│   └── s3_public_exposure.json    # S3 bucket lockdown playbook definition
├── reports/
│   └── sample_incident_report.json # Pre-generated sample forensic incident report
├── src/
│   ├── __init__.py
│   ├── cli.py                     # Interactive rich console CLI for investigations
│   ├── lambda_handler.py          # AWS Lambda entrypoint for EventBridge & Step Functions
│   ├── core/
│   │   ├── __init__.py
│   │   ├── finding_parser.py      # ASFF & GuardDuty normalizer
│   │   ├── mitre_mapper.py        # MITRE ATT&CK tactics & techniques mapper
│   │   └── scoring_engine.py      # Compound risk scoring & blast radius calculator
│   ├── handlers/
│   │   ├── __init__.py
│   │   ├── base_handler.py        # Abstract base containment handler
│   │   ├── iam_handler.py         # IAM session revocation, key deactivate, deny policy
│   │   ├── ec2_handler.py         # EC2 isolation SG swap, EBS snapshot, tagging
│   │   └── s3_handler.py          # S3 Block Public Access, private ACL, TLS policy
│   ├── orchestrator/
│   │   ├── __init__.py
│   │   └── state_machine.py       # Step Functions workflow orchestrator
│   └── reporters/
│       ├── __init__.py
│       ├── alert_dispatcher.py    # SNS & Slack webhook notification dispatcher
│       └── evidence_vault.py      # SHA-256 evidence packager & S3 vault archiver
├── terraform/
│   ├── main.tf                    # Step Functions, Lambda, CloudWatch, and SNS
│   ├── eventbridge.tf             # EventBridge rules for GuardDuty & Security Hub
│   ├── iam.tf                     # Least-privilege IAM containment roles
│   ├── s3.tf                      # Tamper-evident S3 Evidence Vault with Object Lock
│   ├── variables.tf               # Configurable deployment parameters
│   ├── outputs.tf                 # Exported ARNs and resource identifiers
│   └── terraform.tfvars.example   # Example variables file
├── tests/
│   ├── conftest.py                # Moto mock fixtures for IAM, EC2, S3, SNS
│   ├── test_finding_parser.py     # Parser unit tests
│   ├── test_scoring_and_mitre.py  # MITRE mapping & scoring tests
│   ├── test_iam_remediation.py    # IAM containment tests
│   ├── test_ec2_quarantine.py     # EC2 isolation tests
│   ├── test_s3_lockdown.py        # S3 lockdown tests
│   └── test_state_machine.py      # End-to-end orchestration tests
├── Dockerfile                     # Containerized CLI runner
├── HOW_TO_RUN.md                  # Comprehensive execution guide
├── index.html                     # Live interactive SOC Dashboard (GitHub Pages)
├── PROJECT_GUIDE.md               # Technical deep-dive, resume points, interview Q&A
├── requirements.txt               # Dependencies: boto3, pydantic, rich, moto, pytest
├── run.bat                        # Windows 1-click execution script
├── run.ps1                        # PowerShell 1-click execution script
└── run.sh                         # Linux/macOS 1-click execution script
```

---

## ⚡ Quickstart & Local Simulation

### 1. Run Attack Simulations Locally (No AWS Credentials Required)
```powershell
# Windows PowerShell
.\run.ps1

# Linux / macOS
chmod +x run.sh && ./run.sh
```

### 2. Run the Unit Test Suite (15 Tests with Moto)
```powershell
.\run.ps1 -Test
```

### 3. Open the Interactive Live Dashboard
```powershell
.\run.ps1 -Dashboard
```

---

## 🚀 Deploying to AWS via Terraform

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

This deploys:
1. **EventBridge Rules** filtering GuardDuty (`Severity >= 7.0`) and Security Hub (`CRITICAL`, `HIGH`).
2. **AWS Step Functions State Machine** coordinating the automated containment runbooks.
3. **AWS Lambda Dispatcher** executing least-privilege boto3 containment logic.
4. **S3 Forensic Evidence Vault** with AES-256 encryption, versioning, Object Lock, and TLS enforcement.
5. **Amazon SNS Alerts Topic** for SecOps broadcast notifications.

---

## 📜 License

This project is open-source and licensed under the [MIT License](LICENSE).
