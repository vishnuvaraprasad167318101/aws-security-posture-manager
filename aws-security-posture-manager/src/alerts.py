"""
alerts.py — Send Slack webhook notifications and AWS SES emails for high-risk findings.
"""

import json
import logging
import os
from typing import List

import boto3
import requests

from src.risk_engine import RiskScore

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SES_SENDER = os.getenv("SES_SENDER_EMAIL", "")
SES_RECIPIENT = os.getenv("SES_RECIPIENT_EMAIL", "")

SEVERITY_EMOJI = {"CRITICAL": ":red_circle:", "HIGH": ":orange_circle:",
                  "MEDIUM": ":yellow_circle:", "LOW": ":white_circle:", "PASS": ":large_green_circle:"}


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def _build_slack_payload(scores: List[RiskScore]) -> dict:
    critical = [s for s in scores if s.risk_level in ("CRITICAL", "HIGH")]

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "AWS Security Posture Report"}},
        {"type": "divider"},
    ]

    for score in critical[:10]:  # cap at 10 accounts per message
        emoji = SEVERITY_EMOJI.get(score.risk_level, ":white_circle:")
        issue_lines = "\n".join(f"  • {i}" for i in score.top_issues) or "  None"
        drift_line = f"\n*Drift (new findings):* {len(score.drift)}" if score.drift else ""
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{score.account_name}* (`{score.account_id}`) — "
                    f"{score.region}  |  Score: *{score.normalized_score}/100* "
                    f"({score.risk_level})\n"
                    f"*Top issues:*\n{issue_lines}{drift_line}"
                ),
            },
        })
        blocks.append({"type": "divider"})

    if not critical:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": ":large_green_circle: All accounts are within acceptable risk thresholds."},
        })

    return {"blocks": blocks}


def send_slack_alert(scores: List[RiskScore], threshold: int = 50) -> bool:
    """Post a Slack message for any accounts scoring above threshold."""
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not set — skipping Slack alert.")
        return False

    at_risk = [s for s in scores if s.normalized_score >= threshold]
    if not at_risk:
        logger.info("No accounts above threshold %d — no Slack alert sent.", threshold)
        return True

    payload = _build_slack_payload(at_risk)
    try:
        resp = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Slack alert sent successfully.")
        return True
    except requests.RequestException as exc:
        logger.error("Failed to send Slack alert: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Email via SES
# ---------------------------------------------------------------------------

def send_email_alert(scores: List[RiskScore], threshold: int = 50) -> bool:
    """Send an email report via AWS SES for high-risk accounts."""
    if not SES_SENDER or not SES_RECIPIENT:
        logger.warning("SES_SENDER_EMAIL or SES_RECIPIENT_EMAIL not set — skipping email.")
        return False

    at_risk = [s for s in scores if s.normalized_score >= threshold]
    if not at_risk:
        return True

    lines = ["AWS Security Posture Report\n", "=" * 60]
    for score in at_risk:
        lines += [
            f"\nAccount : {score.account_name} ({score.account_id})",
            f"Region  : {score.region}",
            f"Score   : {score.normalized_score}/100  [{score.risk_level}]",
            f"Findings: {score.findings_count}",
            "Top Issues:",
        ]
        for issue in score.top_issues:
            lines.append(f"  - {issue}")
        if score.drift:
            lines.append(f"Drift   : {len(score.drift)} new finding(s) since last scan")

    body = "\n".join(lines)

    try:
        ses = boto3.client("ses", region_name=os.getenv("DYNAMODB_REGION", "us-east-1"))
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [SES_RECIPIENT]},
            Message={
                "Subject": {"Data": f"[Security Posture] {len(at_risk)} account(s) require attention"},
                "Body": {"Text": {"Data": body}},
            },
        )
        logger.info("Email alert sent to %s.", SES_RECIPIENT)
        return True
    except Exception as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False
