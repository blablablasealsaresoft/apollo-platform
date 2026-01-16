#!/usr/bin/env python3
"""Thin wrapper around osv-scanner to keep reports consistent."""
import argparse
import subprocess
from pathlib import Path

DEFAULT_MANIFESTS = ["package-lock.json", "poetry.lock", "requirements.txt"]


def run_scan(manifest: Path) -> None:
    print(f"[scan] {manifest}")
    subprocess.run(["osv-scanner", "--sbom", str(manifest)], check=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="*", type=Path, default=list(map(Path, DEFAULT_MANIFESTS)))
    args = parser.parse_args()
    for manifest in args.manifests:
        if manifest.exists():
            run_scan(manifest)
        else:
            print(f"[skip] {manifest} missing")

if __name__ == "__main__":
    main()
