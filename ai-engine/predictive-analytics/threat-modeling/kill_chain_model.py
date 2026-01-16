#!/usr/bin/env python3
"""Produce a lightweight kill chain view for an actor."""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Phase:
    name: str
    techniques: list[str]


def build_kill_chain(actor: str) -> list[Phase]:
    phases = [
        Phase("Reconnaissance", ["T1595", "T1597"]),
        Phase("Resource Development", ["T1587", "T1588"]),
        Phase("Execution", ["T1204", "T1059"]),
        Phase("Exfiltration", ["T1041", "T1567"]),
    ]
    print(json.dumps({"actor": actor, "phases": [phase.__dict__ for phase in phases]}, indent=2))
    return phases


if __name__ == "__main__":
    build_kill_chain("OneCoin Operators")
