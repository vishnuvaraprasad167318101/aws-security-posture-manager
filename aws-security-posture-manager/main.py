"""
main.py — CLI entry point for AWS Multi-Account Security Posture Manager.

Usage:
  python main.py scan                        # run full scan, save results, send alerts
  python main.py scan --no-alerts            # scan only, no notifications
  python main.py scan --accounts config/accounts.yaml
  python main.py report --days 7             # generate HTML report from stored history
  python main.py history --account 123456789012 --region us-east-1
"""

import logging
import os
import sys
from pathlib import Path
from typing import List, Dict, Tuple

import click
import yaml
from dotenv import load_dotenv

load_dotenv()

# Ensure src/ is importable when running from project root
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import ScanFinding, assume_role, scan_account_region
from src.findings import get_guardduty_findings
from src.risk_engine import score_all_accounts, RiskScore
from src.storage import ScanHistoryStore
from src.alerts import send_slack_alert, send_email_alert
from src.report_generator import generate_html_report, generate_json_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("main")


def load_config(config_path: str) -> Dict:
    with open(config_path, "r") as fh:
        return yaml.safe_load(fh)


def run_scan(config: Dict, enable_guardduty: bool = True) -> Tuple[List[ScanFinding], List[RiskScore]]:
    """Execute a full multi-account scan. Returns (findings, risk_scores)."""
    settings = config.get("settings", {})
    dynamodb_table = os.getenv("DYNAMODB_TABLE", settings.get("dynamodb_table", "security-posture-history"))
    dynamodb_region = os.getenv("DYNAMODB_REGION", "us-east-1")

    store = ScanHistoryStore(table_name=dynamodb_table, region=dynamodb_region)
    all_findings: List[ScanFinding] = []
    previous_scan_map: Dict[Tuple[str, str], List[str]] = {}

    for account in config.get("accounts", []):
        account_id = account["id"]
        account_name = account["name"]
        role_name = account["role_name"]
        regions = account.get("regions", ["us-east-1"])

        try:
            session = assume_role(account_id, role_name)
        except Exception as exc:
            logger.error("Skipping account %s — cannot assume role: %s", account_id, exc)
            continue

        for region in regions:
            prev_keys = store.get_latest_finding_keys(account_id, region)
            if prev_keys is not None:
                previous_scan_map[(account_id, region)] = prev_keys

            region_findings = scan_account_region(session, account_id, account_name, region)

            if enable_guardduty and settings.get("guardduty_enabled", True):
                region_findings += get_guardduty_findings(session, account_id, account_name, region)

            all_findings.extend(region_findings)
            logger.info(
                "  [%s] %s / %s — %d finding(s)",
                account_name, account_id, region, len(region_findings),
            )

    risk_scores = score_all_accounts(all_findings, previous_scan_map)
    store.save_scan(all_findings, risk_scores)

    # Purge old records
    retention = settings.get("retention_days", 90)
    purged = store.purge_old_scans(retention_days=retention)
    if purged:
        logger.info("Purged %d old scan records (retention=%d days).", purged, retention)

    return all_findings, risk_scores


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """AWS Multi-Account Security Posture Manager"""


@cli.command()
@click.option("--accounts", "config_path", default="config/accounts.yaml",
              show_default=True, help="Path to accounts config YAML.")
@click.option("--no-alerts", is_flag=True, default=False, help="Skip Slack/email notifications.")
@click.option("--no-guardduty", is_flag=True, default=False, help="Skip GuardDuty findings.")
@click.option("--output-dir", default="reports/output", show_default=True)
@click.option("--threshold", default=50, show_default=True,
              help="Minimum risk score to trigger alerts.")
@click.option("--demo", is_flag=True, default=False,
              help="Run with mock data (no AWS credentials required).")
def scan(config_path, no_alerts, no_guardduty, output_dir, threshold, demo):
    """Run a full security posture scan across all configured accounts."""
    if demo:
        from demo_data import get_demo_findings, get_demo_scores
        click.echo("\n[DEMO MODE] Using mock data — no AWS credentials required.\n")
        findings, scores = get_demo_findings(), get_demo_scores()
    else:
        config = load_config(config_path)
        findings, scores = run_scan(config, enable_guardduty=not no_guardduty)

    # Print summary table
    click.echo("\n" + "=" * 70)
    click.echo(f"{'Account':<20} {'Region':<15} {'Score':>6}  {'Level':<10}  {'C/H/M/L'}")
    click.echo("-" * 70)
    for s in scores:
        c = s.findings_count
        counts = f"{c.get('CRITICAL',0)}/{c.get('HIGH',0)}/{c.get('MEDIUM',0)}/{c.get('LOW',0)}"
        click.echo(f"{s.account_name:<20} {s.region:<15} {s.normalized_score:>5}%  {s.risk_level:<10}  {counts}")
    click.echo("=" * 70)

    # Generate reports
    html_path = generate_html_report(findings, scores, output_dir=output_dir)
    json_path = generate_json_report(findings, scores, output_dir=output_dir)
    click.echo(f"\nReports saved:\n  HTML: {html_path}\n  JSON: {json_path}")

    # Send alerts
    if not no_alerts:
        send_slack_alert(scores, threshold=threshold)
        send_email_alert(scores, threshold=threshold)

    # Exit with non-zero code if any CRITICAL accounts found
    if any(s.risk_level == "CRITICAL" for s in scores):
        sys.exit(2)
    elif any(s.risk_level == "HIGH" for s in scores):
        sys.exit(1)


@cli.command()
@click.option("--account", required=True, help="AWS account ID.")
@click.option("--region", default="us-east-1", show_default=True)
@click.option("--days", default=30, show_default=True, help="Number of days of history to show.")
def history(account, region, days):
    """Show scan history for a specific account/region."""
    table = os.getenv("DYNAMODB_TABLE", "security-posture-history")
    store = ScanHistoryStore(table_name=table)
    records = store.get_scan_history(account_id=account, region=region, days=days)

    if not records:
        click.echo(f"No history found for {account} / {region} in the last {days} days.")
        return

    click.echo(f"\nScan history — {account} / {region} (last {days} days):\n")
    click.echo(f"{'Date':<30} {'Score':>6}  {'Level':<10}  {'Findings'}")
    click.echo("-" * 60)
    for r in records:
        click.echo(f"{r['scan_date']:<30} {r['risk_score']:>5}%  {r['risk_level']:<10}  {r['finding_count']}")


if __name__ == "__main__":
    cli()
