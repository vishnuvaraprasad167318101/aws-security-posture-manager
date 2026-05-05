"""
findings.py — Pull GuardDuty findings and correlate with scanner findings.
"""

import boto3
import logging
from typing import Dict, List
from src.scanner import ScanFinding

logger = logging.getLogger(__name__)

GUARDDUTY_SEVERITY_MAP = {
    range(7, 11): ("HIGH",   "GUARDDUTY_HIGH"),
    range(4, 7):  ("MEDIUM", "GUARDDUTY_MEDIUM"),
    range(1, 4):  ("LOW",    "GUARDDUTY_LOW"),
}


def _map_severity(score: float) -> tuple:
    for r, val in GUARDDUTY_SEVERITY_MAP.items():
        if int(score) in r:
            return val
    return ("LOW", "GUARDDUTY_LOW")


def get_guardduty_findings(
    session: boto3.Session, account_id: str, account_name: str, region: str
) -> List[ScanFinding]:
    """Fetch active GuardDuty findings for an account/region."""
    findings: List[ScanFinding] = []

    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            logger.info("GuardDuty not enabled in %s / %s", account_id, region)
            return findings

        detector_id = detectors[0]

        paginator = gd.get_paginator("list_findings")
        for page in paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                    "severity": {"Gte": 1},
                }
            },
        ):
            if not page["FindingIds"]:
                continue

            details_resp = gd.get_findings(
                DetectorId=detector_id,
                FindingIds=page["FindingIds"],
            )
            for gd_finding in details_resp.get("Findings", []):
                severity_score = gd_finding.get("Severity", 1)
                severity, ftype = _map_severity(severity_score)
                resource_type = gd_finding.get("Resource", {}).get("ResourceType", "Unknown")
                resource_id = (
                    gd_finding.get("Resource", {})
                    .get("InstanceDetails", {})
                    .get("InstanceId", gd_finding.get("Id", "unknown"))
                )

                findings.append(ScanFinding(
                    account_id=account_id,
                    account_name=account_name,
                    region=region,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    finding_type=ftype,
                    severity=severity,
                    description=gd_finding.get("Title", "GuardDuty finding"),
                    recommendation=gd_finding.get("Description", "Review GuardDuty finding details."),
                    details={
                        "guardduty_id": gd_finding.get("Id"),
                        "severity_score": severity_score,
                        "type": gd_finding.get("Type"),
                        "updated_at": gd_finding.get("UpdatedAt"),
                    },
                ))
    except Exception as exc:
        logger.error("GuardDuty scan failed for %s / %s: %s", account_id, region, exc)

    return findings
