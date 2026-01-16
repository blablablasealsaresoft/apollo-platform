#!/usr/bin/env python3
"""Scan directories for residual artifacts (payloads, logs, creds)."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

SIGNATURES = ["meterpreter", "sliver", "payload.bin", "creds.txt"]


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path("."), help="Path to audit")
    args = parser.parse_args()

    findings = []
    for root, _dirs, files in os.walk(args.path):
        for fname in files:
            path = Path(root) / fname
            with path.open("rb") as fh:
                blob = fh.read(2048).decode("utf-8", errors="ignore")
            if any(sig in blob for sig in SIGNATURES):
                findings.append((path, hash_file(path)))

    if not findings:
        print("[+] No residual artifacts detected.")
        return

    print("[!] Residual artifacts identified:")
    for path, digest in findings:
        print(f" - {path} (sha256={digest})")


if __name__ == "__main__":
    main()
