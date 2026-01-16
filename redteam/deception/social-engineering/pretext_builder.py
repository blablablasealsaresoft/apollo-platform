#!/usr/bin/env python3
"""Create customized social-engineering pretexts referencing authorization IDs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

TEMPLATE = """Pretext: {title}
Operation: {operation_id}
Channel: {channel}
Constraints: {constraints}

Script:
\"\"\"
Hello, this is {alias} from {title}. We're validating records for {target}.
Could you please help me confirm the following details?
\"\"\"
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=Path("pretext_library.json"))
    parser.add_argument("--pretext-id", required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--alias", default="Operations Liaison")
    parser.add_argument("--channel", default="phone")
    parser.add_argument("--output", type=Path, default=Path("pretext.txt"))
    args = parser.parse_args()

    library = json.loads(args.library.read_text(encoding="utf-8"))
    record = next((item for item in library if item["id"] == args.pretext_id), None)
    if not record:
        raise SystemExit(f"Pretext {args.pretext_id} not found")

    text = TEMPLATE.format(
        title=record["title"],
        operation_id=args.operation_id,
        channel=args.channel or ",".join(record["channels"]),
        constraints=", ".join(record["constraints"]),
        alias=args.alias,
        target=args.target,
    )
    args.output.write_text(text, encoding="utf-8")
    print(f"[+] Pretext saved to {args.output}")


if __name__ == "__main__":
    main()
