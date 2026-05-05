"""
risk_engine.py — Weighted risk scoring for all scan findings.
Produces a normalized 0–100 score per account/region and classifies
overall risk level. Also detects configuration drift vs. prior scans.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from src.scanner import ScanFinding

logger = logging.getLogger(__name__)

# Base score contributed by each severity level
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 40.0,
    "HIGH":     25.0,
    "MEDIUM":   10.0,
    "LOW":       3.0,
}

# Multipliers applied on top of severity weight for specific finding types
FINDING_MULTIPLIERS: Dict[str, float] = {
    "SG_ALL_TRAFFIC_OPEN":             1.6,
    "SG_DANGEROUS_PORT_22_OPEN":       1.4,
    "SG_DANGEROUS_PORT_3389_OPEN":     1.4,
    "SG_DANGEROUS_PORT_3306_OPEN":     1.2,
    "SG_DANGEROUS_PORT_5432_OPEN":     1.2,
    "SG_DANGEROUS_PORT_27017_OPEN":    1.2,
    "NACL_ALLOW_ALL_INBOUND":          1.3,
    "S3_PUBLIC_ACCESS_NOT_FULLY_BLOCKED": 1.2,
    "S3_NO_PUBLIC_ACCESS_BLOCK":       1.3,
    "VPC_FLOW_LOGS_DISABLED":          0.7,
    "GUARDDUTY_HIGH":                  1.5,
    "GUARDDUTY_MEDIUM":                1.0,
    "GUARDDUTY_LOW":                   0.6,
}

# Raw score at which normalized score saturates at 100
SATURATION_THRESHOLD = 250.0


@dataclass
class RiskScore:
    account_id: str
    account_name: str
    region: str
    raw_score: float
    normalized_score: int          # 0–100
    risk_level: str                # CRITICAL | HIGH | MEDIUM | LOW | PASS
    findings_count: Dict[str, int]
    top_issues: List[str]
    drift: List[str] = field(default_factory=list)   # new findings since last scan

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "PASS"


def calculate_risk_score(
    findings: List[ScanFinding],
    account_id: str,
    account_name: str,
    region: str,
    previous_finding_ids: List[str] | None = None,
) -> RiskScore:
    """
    Calculate a weighted risk score for a single account/region pair.

    Args:
        findings: Full list of findings from the current scan.
        account_id: AWS account ID to score.
        account_name: Human-readable account name.
        region: AWS region to scope the score.
        previous_finding_ids: Optional list of resource_id+finding_type keys from the
                              last stored scan, used to detect new (drifted) findings.
    """
    scoped = [
        f for f in findings
        if f.account_id == account_id and f.region == region
    ]

    raw_score = 0.0
    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in scoped:
        base = SEVERITY_WEIGHTS.get(finding.severity, 5.0)
        multiplier = FINDING_MULTIPLIERS.get(finding.finding_type, 1.0)
        raw_score += base * multiplier
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    normalized = min(int((raw_score / SATURATION_THRESHOLD) * 100), 100)

    # Top-3 highest-weighted issues for the summary
    sorted_findings = sorted(
        scoped,
        key=lambda f: (
            SEVERITY_WEIGHTS.get(f.severity, 0) *
            FINDING_MULTIPLIERS.get(f.finding_type, 1.0)
        ),
        reverse=True,
    )
    top_issues = [f.description[:120] for f in sorted_findings[:3]]

    # Drift detection
    drift: List[str] = []
    if previous_finding_ids is not None:
        prev_set = set(previous_finding_ids)
        for f in scoped:
            key = f"{f.resource_id}::{f.finding_type}"
            if key not in prev_set:
                drift.append(f"NEW: [{f.severity}] {f.finding_type} on {f.resource_id}")

    return RiskScore(
        account_id=account_id,
        account_name=account_name,
        region=region,
        raw_score=round(raw_score, 2),
        normalized_score=normalized,
        risk_level=_risk_level(normalized),
        findings_count=counts,
        top_issues=top_issues,
        drift=drift,
    )


def score_all_accounts(
    findings: List[ScanFinding],
    previous_scan_map: Dict[Tuple[str, str], List[str]] | None = None,
) -> List[RiskScore]:
    """
    Score every unique (account_id, region) pair found in findings.

    Args:
        findings: All findings from the current scan run.
        previous_scan_map: Dict mapping (account_id, region) → list of
                           "resource_id::finding_type" keys from the last scan.
    Returns:
        List of RiskScore objects sorted descending by normalized_score.
    """
    seen: set = set()
    scores: List[RiskScore] = []
    previous_scan_map = previous_scan_map or {}

    for f in findings:
        key = (f.account_id, f.region)
        if key not in seen:
            seen.add(key)
            prev_ids = previous_scan_map.get(key)
            scores.append(
                calculate_risk_score(findings, f.account_id, f.account_name, f.region, prev_ids)
            )

    return sorted(scores, key=lambda s: s.normalized_score, reverse=True)
