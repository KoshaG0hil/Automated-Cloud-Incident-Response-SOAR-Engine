"""
SOAR Interactive Command Line Interface.
Provides realistic incident simulations, triage investigation, playbook inspection, and rich terminal reporting.
"""

import argparse
import json
from pathlib import Path
import sys

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .orchestrator.state_machine import SoarStateMachine

console = Console(force_terminal=True)

BANNER = r"""[bold cyan]
    ___   _       _______   _____ ____  ___    ____ 
   /   | | |     / / ___/  / ___// __ \/   |  / __ \
  / /| | | | /| / /\__ \   \__ \/ / / / /| | / /_/ /
 / ___ | | |/ |/ /___/ /  ___/ / /_/ / ___ |/ _, _/ 
/_/  |_| |__/|__//____/  /____/\____/_/  |_/_/ |_|  
[/bold cyan][bold dim]Enterprise Cloud Incident Response & Threat Hunting Orchestrator[/bold dim]
"""

SIMULATED_SCENARIOS = {
    "iam_exfiltration": {
        "finding_id": "guardduty-iam-exfil-98124",
        "source": "aws.guardduty",
        "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "title": "Compromised IAM Credentials Exfiltrated from External IP",
        "description": "Credentials for IAM User 'deploy-pipeline-bot' were used from an unusual external IP address (198.51.100.44) known for anonymizing proxies.",
        "severity": "CRITICAL",
        "severity_score": 92.0,
        "resource_type": "AwsIamUser",
        "resource_id": "deploy-pipeline-bot",
        "resource_arn": "arn:aws:iam::123456789012:user/deploy-pipeline-bot",
        "account_id": "123456789012",
        "region": "us-east-1",
        "threat_actor_ip": "198.51.100.44",
        "threat_actor_country": "Netherlands",
        "threat_actor_city": "Amsterdam",
        "resource_tags": {"Environment": "Production", "Owner": "DevOps"},
        "is_production": True,
    },
    "ec2_cryptominer": {
        "finding_id": "guardduty-ec2-crypto-44211",
        "source": "aws.guardduty",
        "finding_type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "title": "EC2 Host Querying Known Cryptocurrency Mining Pools",
        "description": "EC2 instance 'i-0a8b9c7d6e5f43210' generated repeated DNS queries associated with the Monero / Bitcoin mining network xmr.pool-pool.org.",
        "severity": "HIGH",
        "severity_score": 84.0,
        "resource_type": "AwsEc2Instance",
        "resource_id": "i-0a8b9c7d6e5f43210",
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0a8b9c7d6e5f43210",
        "account_id": "123456789012",
        "region": "us-east-1",
        "threat_actor_ip": "203.0.113.88",
        "threat_actor_country": "Russia",
        "threat_actor_city": "Moscow",
        "resource_tags": {"Environment": "Production", "Role": "WorkerNode"},
        "is_production": True,
    },
    "s3_leak": {
        "finding_id": "sechub-s3-public-77192",
        "source": "aws.securityhub",
        "finding_type": "Policy:S3/BucketPublicReadWriteGranted",
        "title": "S3 Data Lake Bucket Configured with Public Read/Write Access",
        "description": "S3 bucket 'corp-customer-analytics-lake-prod' grants unrestricted public read/write permissions via Bucket ACL and Bucket Policy.",
        "severity": "HIGH",
        "severity_score": 88.0,
        "resource_type": "AwsS3Bucket",
        "resource_id": "corp-customer-analytics-lake-prod",
        "resource_arn": "arn:aws:s3:::corp-customer-analytics-lake-prod",
        "account_id": "123456789012",
        "region": "us-east-1",
        "threat_actor_ip": "192.0.2.105",
        "resource_tags": {"Environment": "Production", "DataClassification": "Confidential"},
        "is_production": True,
    },
}


def render_banner():
    console.print(BANNER)


def cmd_playbooks(args):
    """List available playbooks and active triggers."""
    playbooks_dir = Path(__file__).resolve().parent.parent / "playbooks"
    table = Table(title="[Active Incident Response Containment Playbooks]", show_header=True, header_style="bold magenta")
    table.add_column("Playbook ID", style="cyan", width=18)
    table.add_column("Name", style="white", width=34)
    table.add_column("Severity Threshold", style="yellow", width=18)
    table.add_column("Key Triggers", style="dim", width=40)

    if playbooks_dir.exists():
        for pfile in playbooks_dir.glob("*.json"):
            with open(pfile, "r", encoding="utf-8") as f:
                data = json.load(f)
                triggers = ", ".join(data.get("triggers", [])[:2]) + "..."
                table.add_row(
                    data.get("id", pfile.stem),
                    data.get("name", ""),
                    data.get("severity_threshold", "HIGH"),
                    triggers,
                )
    console.print(table)


def cmd_simulate(args):
    """Execute automated incident response on simulated attack scenarios."""
    scenarios_to_run = (
        list(SIMULATED_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    )

    engine = SoarStateMachine(
        dry_run=args.dry_run,
        s3_evidence_bucket=args.s3_bucket,
        sns_topic_arn=args.sns_topic,
        slack_webhook_url=args.slack_webhook,
    )

    for sc_name in scenarios_to_run:
        if sc_name not in SIMULATED_SCENARIOS:
            console.print(f"[bold red]Unknown scenario '{sc_name}'. Available: {list(SIMULATED_SCENARIOS.keys())}[/bold red]")
            continue

        raw_finding = SIMULATED_SCENARIOS[sc_name]
        console.print(Panel(
            f"[bold yellow]Simulating Incident Vector:[/bold yellow] [bold white]{sc_name.upper()}[/bold white]\n"
            f"[dim]Resource: {raw_finding['resource_type']} -> {raw_finding['resource_id']}[/dim]\n"
            f"[dim]Threat Type: {raw_finding['finding_type']}[/dim]\n"
            f"[dim]Mode: {'DRY-RUN (Safe Simulation)' if args.dry_run else 'ACTIVE AWS EXECUTION'}[/dim]",
            title="[Scenario Trigger]",
            border_style="cyan"
        ))

        results = engine.process_event(raw_finding)

        for res in results:
            # Triage & MITRE Table
            triage_table = Table(show_header=True, header_style="bold green", title="[Triage & Threat Intelligence]")
            triage_table.add_column("Field", style="cyan")
            triage_table.add_column("Value", style="white")

            triage_table.add_row("Incident ID", res.finding.finding_id)
            triage_table.add_row("Priority Tier", f"[bold red]{res.triage.priority.value}[/bold red]")
            triage_table.add_row("Risk Score", f"{res.triage.composite_score} / 100.0")
            triage_table.add_row("Blast Radius", res.triage.blast_radius)
            triage_table.add_row("MITRE Tactic", f"{res.mitre.tactic} ({res.mitre.tactic_id})")
            triage_table.add_row("MITRE Technique", f"{res.mitre.technique} ({res.mitre.technique_id})")
            triage_table.add_row("Threat Actor IP", f"{res.finding.threat_actor_ip} ({res.finding.threat_actor_country or 'Unknown'})")
            console.print(triage_table)

            # Containment Actions Table
            actions_table = Table(show_header=True, header_style="bold blue", title="[Automated Containment Actions]")
            actions_table.add_column("Action Step", style="bold")
            actions_table.add_column("Execution Status", style="green")
            actions_table.add_column("Details", style="dim")

            for act in res.containment.actions_executed:
                status_color = "green" if act.status in ["SUCCESS", "DRY_RUN"] else "red"
                actions_table.add_row(
                    act.action_name,
                    f"[{status_color}]{act.status}[/{status_color}]",
                    str(act.details)[:60] + "...",
                )
            console.print(actions_table)

            # Forensic Evidence Box
            console.print(Panel(
                f"[bold green]Tamper-Evident SHA-256 Digest:[/bold green] [cyan]{res.evidence_report.sha256_checksum}[/cyan]\n"
                f"[bold green]Local Evidence Archive:[/bold green] {res.local_evidence_path}\n"
                f"[bold green]Execution Latency:[/bold green] {res.execution_duration_ms} ms",
                title="[Forensic Chain of Custody]",
                border_style="green"
            ))
            console.print("\n" + "=" * 70 + "\n")


def cmd_investigate(args):
    """Investigate a custom security finding JSON file."""
    filepath = Path(args.file)
    if not filepath.exists():
        console.print(f"[bold red]Finding file not found: {filepath}[/bold red]")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = SoarStateMachine(dry_run=args.dry_run)
    results = engine.process_event(data)

    console.print(f"[bold green]Processed {len(results)} findings from {filepath.name}[/bold green]")
    for r in results:
        console.print(f"Incident: {r.finding.finding_id} | Priority: {r.triage.priority.value} | Contained: {r.containment.success}")


def main():
    parser = argparse.ArgumentParser(description="AWS Cloud Incident Response & Threat Hunting SOAR Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: playbooks
    subparsers.add_parser("playbooks", help="List active incident response containment playbooks")

    # Command: simulate
    sim_parser = subparsers.add_parser("simulate", help="Run realistic attack simulations")
    sim_parser.add_argument(
        "--scenario",
        choices=["all", "iam_exfiltration", "ec2_cryptominer", "s3_leak"],
        default="all",
        help="Select attack scenario (default: all)",
    )
    sim_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Execute in safe dry-run simulation mode (default: True)",
    )
    sim_parser.add_argument(
        "--live",
        dest="dry_run",
        action="store_false",
        help="Execute active changes against real AWS resources",
    )
    sim_parser.add_argument("--s3-bucket", help="Target S3 bucket for evidence archival")
    sim_parser.add_argument("--sns-topic", help="Target SNS topic ARN for incident alerts")
    sim_parser.add_argument("--slack-webhook", help="Slack webhook URL for alerts")

    # Command: investigate
    inv_parser = subparsers.add_parser("investigate", help="Investigate a custom finding JSON")
    inv_parser.add_argument("file", help="Path to input finding JSON file")
    inv_parser.add_argument("--dry-run", action="store_true", default=True)

    args = parser.parse_args()

    render_banner()

    if args.command == "playbooks":
        cmd_playbooks(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "investigate":
        cmd_investigate(args)
    else:
        # Default behavior: run all simulations in dry-run mode
        args.scenario = "all"
        args.dry_run = True
        args.s3_bucket = None
        args.sns_topic = None
        args.slack_webhook = None
        cmd_simulate(args)


if __name__ == "__main__":
    main()
