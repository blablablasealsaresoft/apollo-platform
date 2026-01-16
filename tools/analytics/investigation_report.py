#!/usr/bin/env python3
"""Generate a quick investigation readiness report from CSV exports."""
import argparse
import csv
import pathlib
from collections import Counter

REQUIRED_COLUMNS = {"case_number", "title", "status", "priority", "lead", "targets"}


def load_rows(path: pathlib.Path) -> list[dict]:
    with path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"Missing columns: {', '.join(missing)}")
        return list(reader)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=pathlib.Path)
    args = parser.parse_args()
    rows = load_rows(args.input)
    totals = Counter(row["status"] for row in rows)
    targets = sum(len((row["targets"] or "").split(";")) for row in rows)
    print(f"Investigations: {len(rows)}")
    for status, count in totals.items():
        print(f"  - {status}: {count}")
    print(f"Total targets tracked: {targets}")
    critical = [row for row in rows if row.get("priority") == "critical"]
    print("Critical cases:")
    for row in critical[:5]:
        print(f"  * {row['case_number']} :: {row['title']} (lead {row['lead']})")


if __name__ == "__main__":
    main()
