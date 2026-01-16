#!/usr/bin/env python3
"""
Generate synthetic infrastructure deception assets.

Each decoy contains hostnames, credentials, and tracking tags that can be
deployed to Git repos, DNS zones, or config backups to detect unauthorized use.
"""
from __future__ import annotations

import argparse
import json
import random
import string
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SERVICES = ["vpn", "db", "s3", "jira", "grafana", "splunk", "vault"]
REGIONS = ["us-east-1", "eu-central-1", "me-south-1", "ap-southeast-2"]


def rand_secret(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@$%^&*"
    return "".join(random.choice(alphabet) for _ in range(length))


@dataclass
class DecoyAsset:
    service: str
    hostname: str
    username: str
    password: str
    tracking_tag: str
    region: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def make_decoy(operation_id: str) -> DecoyAsset:
    service = random.choice(SERVICES)
    hostname = f"{service}-{random.randint(10, 999)}.corp.internal"
    username = f"{service}_svc_{random.randint(1000, 9999)}"
    password = rand_secret()
    tag = f"{operation_id}-{random.randint(100000, 999999)}"
    region = random.choice(REGIONS)
    return DecoyAsset(
        service=service,
        hostname=hostname,
        username=username,
        password=password,
        tracking_tag=tag,
        region=region,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("decoys.json"))
    args = parser.parse_args()

    decoys = [asdict(make_decoy(args.operation_id)) for _ in range(args.count)]
    args.output.write_text(json.dumps(decoys, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(decoys)} decoys to {args.output}")


if __name__ == "__main__":
    main()
