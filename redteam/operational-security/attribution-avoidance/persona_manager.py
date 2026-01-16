#!/usr/bin/env python3
"""Create disposable personas for authorized engagements."""
from __future__ import annotations

import argparse
import json
import secrets
import string
from pathlib import Path

COVER_ORGS = ["NorthSea Logistics", "Atlas Compliance", "Eclipse Holdings"]
DOMAINS = ["mail.la", "consulting.one", "ops-brief.net"]


def random_name() -> str:
    first = secrets.token_hex(2)
    last = secrets.token_hex(2)
    return f"{first.capitalize()} {last.capitalize()}"


def random_email() -> str:
    user = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
    domain = secrets.choice(DOMAINS)
    return f"{user}@{domain}"


def build_persona(operation_id: str) -> dict:
    return {
        "operation": operation_id,
        "name": random_name(),
        "email": random_email(),
        "cover_org": secrets.choice(COVER_ORGS),
        "vpn_exit": f"{secrets.choice(['ams', 'lis', 'ath'])}{secrets.randbelow(999)}",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--output", type=Path, default=Path("personas.json"))
    args = parser.parse_args()

    personas = [build_persona(args.operation_id) for _ in range(args.count)]
    args.output.write_text(json.dumps(personas, indent=2), encoding="utf-8")
    print(f"[+] Created {len(personas)} personas -> {args.output}")


if __name__ == "__main__":
    main()
