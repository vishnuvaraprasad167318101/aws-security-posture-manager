"""
report_generator.py — Produce HTML and JSON reports from scan results.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from jinja2 import Environment, BaseLoader

from src.scanner import ScanFinding
from src.risk_engine import RiskScore

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Posture Report</title>
<style>
  body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; color: #333; }
  h1 { background: #1a252f; color: #fff; padding: 16px 24px; border-radius: 6px; margin: 0 0 20px; }
  .summary { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .card { background: #fff; border-radius: 6px; padding: 16px 24px; flex: 1; min-width: 150px;
          box-shadow: 0 1px 4px rgba(0,0,0,.12); text-align: center; }
  .card .num { font-size: 2rem; font-weight: bold; }
  .CRITICAL { color: #c0392b; } .HIGH { color: #e67e22; }
  .MEDIUM   { color: #f1c40f; } .LOW  { color: #27ae60; } .PASS { color: #2ecc71; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 6px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
  th { background: #1a252f; color: #fff; padding: 10px 14px; text-align: left; }
  td { padding: 9px 14px; border-bottom: 1px solid #eee; font-size: .9rem; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size:.8rem; font-weight:bold; }
  .bg-CRITICAL { background:#c0392b; } .bg-HIGH { background:#e67e22; }
  .bg-MEDIUM   { background:#f39c12; } .bg-LOW  { background:#27ae60; } .bg-PASS { background:#2ecc71; }
  .section-title { margin: 28px 0 10px; font-size: 1.2rem; font-weight: bold; }
  footer { margin-top: 30px; font-size: .8rem; color: #999; }
</style>
</head>
<body>
<h1>AWS Security Posture Report</h1>
<p>Generated: <strong>{{ report_date }}</strong></p>

<div class="summary">
  <div class="card"><div class="num CRITICAL">{{ critical_count }}</div>CRITICAL Accounts</div>
  <div class="card"><div class="num HIGH">{{ high_count }}</div>HIGH Accounts</div>
  <div class="card"><div class="num">{{ total_findings }}</div>Total Findings</div>
  <div class="card"><div class="num">{{ accounts_scanned }}</div>Accounts Scanned</div>
</div>

<div class="section-title">Risk Scores by Account / Region</div>
<table>
  <thead><tr><th>Account</th><th>Account ID</th><th>Region</th><th>Score</th><th>Level</th><th>CRIT</th><th>HIGH</th><th>MED</th><th>Drift</th></tr></thead>
  <tbody>
  {% for s in scores %}
  <tr>
    <td>{{ s.account_name }}</td>
    <td>{{ s.account_id }}</td>
    <td>{{ s.region }}</td>
    <td><strong>{{ s.normalized_score }}/100</strong></td>
    <td><span class="badge bg-{{ s.risk_level }}">{{ s.risk_level }}</span></td>
    <td class="CRITICAL">{{ s.findings_count.get('CRITICAL', 0) }}</td>
    <td class="HIGH">{{ s.findings_count.get('HIGH', 0) }}</td>
    <td class="MEDIUM">{{ s.findings_count.get('MEDIUM', 0) }}</td>
    <td>{% if s.drift %}{{ s.drift|length }} new{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<div class="section-title">All Findings</div>
<table>
  <thead><tr><th>Severity</th><th>Account</th><th>Region</th><th>Resource</th><th>Type</th><th>Description</th><th>Recommendation</th></tr></thead>
  <tbody>
  {% for f in findings %}
  <tr>
    <td><span class="badge bg-{{ f.severity }}">{{ f.severity }}</span></td>
    <td>{{ f.account_name }}</td>
    <td>{{ f.region }}</td>
    <td>{{ f.resource_id }}</td>
    <td>{{ f.finding_type }}</td>
    <td>{{ f.description }}</td>
    <td>{{ f.recommendation }}</td>
  </tr>
  {% endfor %}
  {% if not findings %}<tr><td colspan="7" style="text-align:center">No findings — all clear!</td></tr>{% endif %}
  </tbody>
</table>

<footer>AWS Security Posture Manager &mdash; {{ report_date }}</footer>
</body>
</html>"""


def generate_html_report(
    findings: List[ScanFinding],
    scores: List[RiskScore],
    output_dir: str = "reports/output",
) -> str:
    """Render an HTML report and write it to output_dir. Returns the file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)

    html = template.render(
        report_date=report_date,
        scores=[s.to_dict() | {"findings_count": s.findings_count} for s in scores],
        findings=[f.to_dict() for f in findings],
        critical_count=sum(1 for s in scores if s.risk_level == "CRITICAL"),
        high_count=sum(1 for s in scores if s.risk_level == "HIGH"),
        total_findings=len(findings),
        accounts_scanned=len({(s.account_id, s.region) for s in scores}),
    )

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML report written to %s", filepath)
    return filepath


def generate_json_report(
    findings: List[ScanFinding],
    scores: List[RiskScore],
    output_dir: str = "reports/output",
) -> str:
    """Write a machine-readable JSON report. Returns the file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(output_dir, filename)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_findings": len(findings),
            "accounts_scanned": len({(s.account_id, s.region) for s in scores}),
            "risk_levels": {lvl: sum(1 for s in scores if s.risk_level == lvl)
                            for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS")},
        },
        "scores": [s.to_dict() for s in scores],
        "findings": [f.to_dict() for f in findings],
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    logger.info("JSON report written to %s", filepath)
    return filepath
