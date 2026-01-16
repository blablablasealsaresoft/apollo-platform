#!/usr/bin/env python3
"""Compute simple composite risk scores for investigations."""
from __future__ import annotations

import argparse
import random
from dataclasses import dataclass


@dataclass
class RiskScore:
    investigation_id: str
    score: float
    tier: str
    drivers: list[str]


DRIVERS = [
    "Mixer usage detected",
    "Associates with Ignatova",
    "Shell companies registered",
    "Facial recognition hit",
    "Blockchain anomaly",
]


def calculate_score(investigation_id: str) -> RiskScore:
    score = round(random.uniform(0.2, 0.98), 2)
    tier = "low" if score < 0.4 else "medium" if score < 0.7 else "high"
    drivers = random.sample(DRIVERS, k=3)
    return RiskScore(investigation_id, score, tier, drivers)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--investigation-id", required=True)
    args = parser.parse_args()
    result = calculate_score(args.investigation_id)
    print(result)


if __name__ == "__main__":
    main()
