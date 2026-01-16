#!/usr/bin/env python3
"""Overlay blockchain transaction counts vs surveillance hits."""
import argparse
import csv
import datetime as dt
from collections import defaultdict
import pathlib


def load_series(path: pathlib.Path, key_field: str, value_field: str):
    data = defaultdict(float)
    with path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            day = dt.date.fromisoformat(row[key_field])
            data[day] += float(row[value_field])
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blockchain", type=pathlib.Path, required=True)
    parser.add_argument("--surveillance", type=pathlib.Path, required=True)
    args = parser.parse_args()
    chain = load_series(args.blockchain, "day", "transactions")
    surv = load_series(args.surveillance, "day", "matches")
    print("Day,BlockchainTx,SurveillanceHits,Delta")
    for day in sorted(set(chain) | set(surv)):
        c = chain.get(day, 0.0)
        s = surv.get(day, 0.0)
        print(f"{day},{c},{s},{c - s}")


if __name__ == "__main__":
    main()
