# AWS Multi-Account Security Posture Manager

A Python tool that scans multiple AWS accounts for security misconfigurations, scores risk using a weighted engine, detects configuration drift over time, and sends alerts via Slack and email.

## Architecture

```
main.py (CLI)
 ├── src/scanner.py       — Cross-account SG, NACL, VPC, S3 scanning
 ├── src/findings.py      — GuardDuty findings integration
 ├── src/risk_engine.py   — Weighted risk scoring + drift detection
 ├── src/storage.py       — DynamoDB scan history persistence
 ├── src/alerts.py        — Slack webhook + SES email alerts
 └── src/report_generator.py — HTML + JSON report generation
```

## Features

- **Cross-account scanning** via IAM role assumption (AWS Organizations compatible)
- **Security checks**: Security Groups, NACLs, VPC Flow Logs, S3 Public Access, GuardDuty
- **Weighted risk scoring** — normalized 0–100 score per account/region
- **Drift detection** — compares current scan against last stored scan, highlights new findings
- **DynamoDB persistence** — full scan history with configurable retention
- **Slack + SES alerts** — notifies on accounts above a risk threshold
- **HTML + JSON reports** — human-readable and machine-readable output

## Prerequisites

1. AWS CLI configured with credentials that have `sts:AssumeRole` permission
2. `SecurityAuditRole` IAM role deployed in each target account with trust to your management account
3. DynamoDB table with a GSI named `account-region-index` on `(account_id, region)` (optional for history)
4. GuardDuty enabled in target accounts (optional)

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/aws-security-posture-manager
cd aws-security-posture-manager
pip install -r requirements.txt
cp .env.example .env        # fill in your values
cp config/accounts.yaml config/my-accounts.yaml   # update account IDs
```

## Usage

```bash
# Full scan — all accounts, save history, send alerts
python main.py scan

# Scan with custom config, no notifications
python main.py scan --accounts config/my-accounts.yaml --no-alerts

# View 30-day history for a specific account
python main.py history --account 123456789012 --region us-east-1

# Scan without GuardDuty (faster)
python main.py scan --no-guardduty
```

## Sample Output

```
======================================================================
Account              Region          Score  Level       C/H/M/L
----------------------------------------------------------------------
production           us-east-1         78%  CRITICAL    3/5/2/1
production           us-west-2         45%  HIGH        1/3/4/0
staging              us-east-1         20%  MEDIUM      0/1/3/2
development          us-east-1          5%  LOW         0/0/1/2
======================================================================
Reports saved:
  HTML: reports/output/report_20251201_143022.html
  JSON: reports/output/report_20251201_143022.json
```

## IAM Role Requirements

Deploy this trust policy in each target account:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root" },
    "Action": "sts:AssumeRole"
  }]
}
```

Attach `SecurityAudit` AWS managed policy + GuardDuty read permissions.

## Technologies

Python · Boto3 · DynamoDB · GuardDuty · Jinja2 · Click · Slack Webhooks · AWS SES
