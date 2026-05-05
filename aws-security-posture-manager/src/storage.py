"""
storage.py — DynamoDB persistence for scan history and drift detection.

Table schema:
  PK: scan_id (string, UUID)
  scan_date (ISO8601 string)
  account_id (string)
  region (string)
  findings (JSON string)
  risk_score (number)
  risk_level (string)

GSI: account-region-index on (account_id, region) for latest-scan queries.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Key

from src.scanner import ScanFinding
from src.risk_engine import RiskScore

logger = logging.getLogger(__name__)


class ScanHistoryStore:
    """Persist scan results to DynamoDB and retrieve historical data for drift analysis."""

    def __init__(self, table_name: str, region: str = "us-east-1"):
        self._ddb = boto3.resource("dynamodb", region_name=region)
        self._table = self._ddb.Table(table_name)
        self._table_name = table_name

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_scan(self, findings: List[ScanFinding], scores: List[RiskScore]) -> str:
        """Persist a full scan run. Returns the generated scan_id."""
        scan_id = str(uuid.uuid4())
        scan_date = datetime.now(timezone.utc).isoformat()

        # Group findings by (account_id, region)
        grouped: Dict[Tuple[str, str], List[Dict]] = {}
        for f in findings:
            key = (f.account_id, f.region)
            grouped.setdefault(key, []).append(f.to_dict())

        score_map = {(s.account_id, s.region): s for s in scores}

        with self._table.batch_writer() as batch:
            for (account_id, region), finding_list in grouped.items():
                score = score_map.get((account_id, region))
                batch.put_item(Item={
                    "scan_id": f"{scan_id}#{account_id}#{region}",
                    "scan_date": scan_date,
                    "account_id": account_id,
                    "region": region,
                    "findings": json.dumps(finding_list),
                    "finding_count": len(finding_list),
                    "risk_score": int(score.normalized_score) if score else 0,
                    "risk_level": score.risk_level if score else "UNKNOWN",
                    "drift": json.dumps(score.drift) if score else "[]",
                })

        logger.info("Saved scan %s (%d findings across %d account-regions)",
                    scan_id, len(findings), len(grouped))
        return scan_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_latest_finding_keys(
        self, account_id: str, region: str
    ) -> Optional[List[str]]:
        """
        Return a list of 'resource_id::finding_type' keys from the most recent
        scan for a given account/region. Returns None if no history exists.
        """
        try:
            response = self._table.query(
                IndexName="account-region-index",
                KeyConditionExpression=Key("account_id").eq(account_id) & Key("region").eq(region),
                ScanIndexForward=False,
                Limit=1,
            )
            items = response.get("Items", [])
            if not items:
                return None

            raw_findings: List[Dict] = json.loads(items[0]["findings"])
            return [f"{f['resource_id']}::{f['finding_type']}" for f in raw_findings]
        except Exception as exc:
            logger.error("Failed to fetch latest findings for %s/%s: %s", account_id, region, exc)
            return None

    def get_scan_history(self, account_id: str, region: str, days: int = 30) -> List[Dict]:
        """Return the last `days` days of scan records for trend analysis."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        try:
            response = self._table.query(
                IndexName="account-region-index",
                KeyConditionExpression=Key("account_id").eq(account_id) & Key("region").eq(region),
                FilterExpression=boto3.dynamodb.conditions.Attr("scan_date").gte(cutoff),
                ScanIndexForward=False,
            )
            return [
                {
                    "scan_date": item["scan_date"],
                    "risk_score": item.get("risk_score", 0),
                    "risk_level": item.get("risk_level", "UNKNOWN"),
                    "finding_count": item.get("finding_count", 0),
                }
                for item in response.get("Items", [])
            ]
        except Exception as exc:
            logger.error("Failed to retrieve scan history: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def purge_old_scans(self, retention_days: int = 90) -> int:
        """Delete scan records older than retention_days. Returns deleted count."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        deleted = 0
        try:
            response = self._table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr("scan_date").lt(cutoff),
                ProjectionExpression="scan_id",
            )
            with self._table.batch_writer() as batch:
                for item in response.get("Items", []):
                    batch.delete_item(Key={"scan_id": item["scan_id"]})
                    deleted += 1
        except Exception as exc:
            logger.error("Error purging old scans: %s", exc)
        return deleted
