"""
scanner.py — Cross-account AWS resource scanner.
Assumes IAM roles in each target account, then scans Security Groups,
NACLs, VPC Flow Logs, and S3 public access settings.
"""

import boto3
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

DANGEROUS_PORTS: Dict[int, str] = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}


@dataclass
class ScanFinding:
    account_id: str
    account_name: str
    region: str
    resource_type: str
    resource_id: str
    finding_type: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    recommendation: str
    details: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


def assume_role(account_id: str, role_name: str, session_name: str = "SecurityAudit") -> boto3.Session:
    """Assume a cross-account IAM role and return an authenticated boto3 Session."""
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600,
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except Exception as exc:
        logger.error("Failed to assume role %s: %s", role_arn, exc)
        raise


# ---------------------------------------------------------------------------
# Security Group scanner
# ---------------------------------------------------------------------------

def _port_in_range(port: int, from_port: int, to_port: int) -> bool:
    return from_port <= port <= to_port


def scan_security_groups(
    ec2, account_id: str, account_name: str, region: str
) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    paginator = ec2.get_paginator("describe_security_groups")

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            vpc_id = sg.get("VpcId", "no-vpc")

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                protocol = rule.get("IpProtocol", "-1")

                open_cidrs = [
                    r["CidrIp"] for r in rule.get("IpRanges", [])
                    if r.get("CidrIp") in ("0.0.0.0/0", "::/0")
                ] + [
                    r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                    if r.get("CidrIpv6") == "::/0"
                ]

                for cidr in open_cidrs:
                    if protocol == "-1":
                        severity, ftype = "CRITICAL", "SG_ALL_TRAFFIC_OPEN"
                        desc = (f"SG {sg_name} ({sg_id}) allows ALL inbound traffic from {cidr}.")
                        rec = "Restrict to specific ports and CIDR ranges required for your workload."
                    else:
                        matched = next(
                            (p for p in DANGEROUS_PORTS if _port_in_range(p, from_port, to_port)),
                            None,
                        )
                        if matched:
                            severity = "CRITICAL" if matched in (22, 3389) else "HIGH"
                            ftype = f"SG_DANGEROUS_PORT_{matched}_OPEN"
                            desc = (
                                f"SG {sg_name} ({sg_id}) exposes {DANGEROUS_PORTS[matched]} "
                                f"(port {matched}) to {cidr}."
                            )
                            rec = (
                                f"Restrict port {matched} to known trusted IPs or use a VPN/bastion host."
                            )
                        else:
                            severity, ftype = "MEDIUM", "SG_PORT_OPEN_TO_INTERNET"
                            desc = (
                                f"SG {sg_name} ({sg_id}) allows inbound ports {from_port}-{to_port} "
                                f"({protocol}) from {cidr}."
                            )
                            rec = "Evaluate whether broad internet access is necessary; restrict if possible."

                    findings.append(ScanFinding(
                        account_id=account_id, account_name=account_name, region=region,
                        resource_type="SecurityGroup", resource_id=sg_id,
                        finding_type=ftype, severity=severity,
                        description=desc, recommendation=rec,
                        details={
                            "sg_name": sg_name, "vpc_id": vpc_id,
                            "cidr": cidr, "ports": f"{from_port}-{to_port}", "protocol": protocol,
                        },
                    ))
    return findings


# ---------------------------------------------------------------------------
# NACL scanner
# ---------------------------------------------------------------------------

def scan_nacls(ec2, account_id: str, account_name: str, region: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    paginator = ec2.get_paginator("describe_network_acls")

    for page in paginator.paginate():
        for nacl in page["NetworkAcls"]:
            nacl_id = nacl["NetworkAclId"]
            vpc_id = nacl.get("VpcId", "")

            for entry in nacl.get("Entries", []):
                if entry.get("Egress"):
                    continue
                cidr = entry.get("CidrBlock", entry.get("Ipv6CidrBlock", ""))
                if cidr in ("0.0.0.0/0", "::/0") and entry.get("RuleAction") == "allow":
                    if entry.get("Protocol") in ("-1", "all"):
                        findings.append(ScanFinding(
                            account_id=account_id, account_name=account_name, region=region,
                            resource_type="NetworkACL", resource_id=nacl_id,
                            finding_type="NACL_ALLOW_ALL_INBOUND", severity="HIGH",
                            description=(
                                f"NACL {nacl_id} (VPC {vpc_id}) has ALLOW ALL inbound rule #{entry.get('RuleNumber')} "
                                f"for {cidr}."
                            ),
                            recommendation="Remove the ALLOW ALL rule; replace with specific port/protocol entries.",
                            details={"vpc_id": vpc_id, "rule_number": entry.get("RuleNumber"), "cidr": cidr},
                        ))
    return findings


# ---------------------------------------------------------------------------
# VPC Flow Logs scanner
# ---------------------------------------------------------------------------

def scan_vpc_flow_logs(ec2, account_id: str, account_name: str, region: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    active_vpcs = {
        fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc_id not in active_vpcs:
            name = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), vpc_id)
            findings.append(ScanFinding(
                account_id=account_id, account_name=account_name, region=region,
                resource_type="VPC", resource_id=vpc_id,
                finding_type="VPC_FLOW_LOGS_DISABLED", severity="MEDIUM",
                description=f"VPC {name} ({vpc_id}) does not have active VPC Flow Logs.",
                recommendation="Enable VPC Flow Logs to CloudWatch Logs or S3 for network visibility.",
                details={"vpc_name": name, "is_default": vpc.get("IsDefault", False)},
            ))
    return findings


# ---------------------------------------------------------------------------
# S3 Public Access scanner
# ---------------------------------------------------------------------------

def scan_s3_public_access(s3, account_id: str, account_name: str, region: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration", {}
            )
            if not all([
                cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets"),
            ]):
                missing = [k for k, v in cfg.items() if not v]
                findings.append(ScanFinding(
                    account_id=account_id, account_name=account_name, region=region,
                    resource_type="S3Bucket", resource_id=name,
                    finding_type="S3_PUBLIC_ACCESS_NOT_FULLY_BLOCKED", severity="HIGH",
                    description=f"S3 bucket '{name}' has incomplete Public Access Block settings.",
                    recommendation="Enable all four S3 Block Public Access settings.",
                    details={"missing_settings": missing, "current_config": cfg},
                ))
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append(ScanFinding(
                account_id=account_id, account_name=account_name, region=region,
                resource_type="S3Bucket", resource_id=name,
                finding_type="S3_NO_PUBLIC_ACCESS_BLOCK", severity="HIGH",
                description=f"S3 bucket '{name}' has no Public Access Block configuration.",
                recommendation="Apply S3 Block Public Access at the bucket and account level.",
                details={},
            ))
        except Exception as exc:
            logger.warning("Cannot check public access block for bucket %s: %s", name, exc)

    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_account_region(
    session: boto3.Session, account_id: str, account_name: str, region: str
) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    try:
        ec2 = session.client("ec2", region_name=region)
        s3 = session.client("s3", region_name=region)

        logger.info("Scanning %s (%s) in %s …", account_name, account_id, region)
        findings += scan_security_groups(ec2, account_id, account_name, region)
        findings += scan_nacls(ec2, account_id, account_name, region)
        findings += scan_vpc_flow_logs(ec2, account_id, account_name, region)

        if region == "us-east-1":          # S3 is global; scan once per account
            findings += scan_s3_public_access(s3, account_id, account_name, region)

    except Exception as exc:
        logger.error("Error scanning %s / %s: %s", account_id, region, exc)

    return findings
