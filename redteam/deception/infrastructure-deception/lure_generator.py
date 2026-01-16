#!/usr/bin/env python3
"""Produce simple lure documents with traceable beacons."""
from __future__ import annotations

import argparse
import secrets
from pathlib import Path

TEMPLATE = """# {title}

This confidential briefing outlines high-value actions for the Ruja operation.

Tracking ID: `{tracking_id}`

Authorized recipients MUST acknowledge via the Apollo portal. Any access outside
approved networks will trigger automatic incident response.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Lure title/target")
    parser.add_argument("--out", type=Path, default=Path("lures"))
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    for idx in range(args.count):
        tracking_id = secrets.token_hex(8)
        path = args.out / f"{args.target.replace(' ', '_').lower()}_{idx}.md"
        path.write_text(
            TEMPLATE.format(title=args.target, tracking_id=tracking_id),
            encoding="utf-8",
        )
        print(f"[+] Lure written to {path} (tracking {tracking_id})")


if __name__ == "__main__":
    main()
