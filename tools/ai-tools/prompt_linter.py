#!/usr/bin/env python3
"""Simple linting for Apollo AI prompt files."""
import argparse
import pathlib
import re
import sys

RULES = {
    "length": lambda text: len(text.split()) <= 800,
    "no_personal_data": lambda text: "SSN" not in text and "passport" not in text,
    "mission": lambda text: bool(re.search(r"Ruja|Ignatova|OneCoin", text, re.IGNORECASE)),
}

MESSAGES = {
    "length": "Prompt exceeds 800 words (split long narratives).",
    "no_personal_data": "Prompt references raw identifiers (SSN/passport). Redact before submission.",
    "mission": "Prompt must reference Ruja/OneCoin context to keep AI focused.",
}

def lint_file(path: pathlib.Path) -> int:
    text = path.read_text(encoding="utf-8")
    failures = [name for name, fn in RULES.items() if not fn(text)]
    if failures:
        for rule in failures:
            print(f"[FAIL] {path}: {MESSAGES[rule]}")
        return 1
    print(f"[OK] {path}")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    status = 0
    for file in args.files:
        if not file.exists():
            print(f"[ERR] {file} missing", file=sys.stderr)
            status = 1
            continue
        status |= lint_file(file)
    return status

if __name__ == "__main__":
    raise SystemExit(main())
