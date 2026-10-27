# How to Run & Validate the SOAR Platform

This guide walks you through running local simulations (no AWS account required), running the automated test suite, viewing the live dashboard, and deploying to AWS via Terraform.

---

## 1. Quickstart (Offline Local Simulation)

The engine includes a full **Dry-Run & Simulation Engine** that models AWS GuardDuty findings, assesses blast radius, maps MITRE ATT&CK techniques, executes mock containment, and generates signed SHA-256 evidence reports locally.

### Windows (PowerShell)
```powershell
# Run all simulated attack scenarios (IAM, EC2, S3)
.\run.ps1

# Inspect active automated playbooks
.\run.ps1 -Command playbooks

# Launch the live interactive SOC dashboard in your browser
.\run.ps1 -Dashboard
```

### macOS / Linux
```bash
chmod +x run.sh

# Run all attack simulations
./run.sh

# Inspect playbooks
./run.sh playbooks

# Launch dashboard
./run.sh dashboard
```

---

## 2. Running the Automated Test Suite

The test suite leverages **Moto** to mock AWS IAM, EC2, S3, and SNS services in-memory:

```powershell
# Using the runner
.\run.ps1 -Test

# Or via pytest directly
$env:PYTHONPATH = "."
python -m pytest tests/ -v --cov=src
```

Expected output:
```
tests/test_ec2_quarantine.py::test_ec2_quarantine_live_mock PASSED
tests/test_finding_parser.py::test_parse_guardduty_event PASSED
tests/test_iam_remediation.py::test_iam_containment_live_mock PASSED
tests/test_s3_lockdown.py::test_s3_lockdown_live_mock PASSED
tests/test_state_machine.py::test_state_machine_end_to_end_simulation PASSED
============================= 15 passed in 4.81s ==============================
```

---

## 3. CLI Command Reference

Execute targeted simulations directly via `python -m src.cli`:

```bash
# Simulate specific attack vector:
python -m src.cli simulate --scenario iam_exfiltration
python -m src.cli simulate --scenario ec2_cryptominer
python -m src.cli simulate --scenario s3_leak

# Investigate a custom AWS Security Finding JSON file:
python -m src.cli investigate path/to/finding.json --dry-run
```

---

## 4. Running with Docker

You can containerize and run the SOAR CLI without installing Python locally:

```bash
# Build the Docker image
docker build -t aws-soar-engine .

# Run the simulation container
docker run --rm -it aws-soar-engine
```

---

## 5. Deploying to AWS via Terraform

When you are ready to deploy the serverless SOAR architecture into your AWS account:

### Prerequisites
- AWS CLI configured with valid credentials (`aws sts get-caller-identity`)
- Terraform v1.5.0 or higher

### Steps
```bash
cd terraform

# 1. Initialize Terraform
terraform init

# 2. Review execution plan
terraform plan

# 3. Apply infrastructure
terraform apply
```

This provisions:
1. **EventBridge Rules** filtering GuardDuty (`Severity >= 7.0`) and Security Hub (`CRITICAL`, `HIGH`).
2. **AWS Step Functions State Machine** coordinating the automated containment runbooks.
3. **AWS Lambda Dispatcher** executing least-privilege boto3 containment logic.
4. **S3 Forensic Evidence Vault** with AES-256 encryption, versioning, Object Lock, and TLS enforcement.
5. **Amazon SNS Alerts Topic** for SecOps broadcast notifications.
