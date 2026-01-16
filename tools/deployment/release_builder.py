#!/usr/bin/env python3
"""Bundle Apollo artifacts for offline deployment."""
import argparse
import hashlib
import shutil
import tarfile
import tempfile
from pathlib import Path

PARTS = [
    ("backend", Path("services")),
    ("frontend", Path("frontend")),
    ("k8s", Path("infrastructure/kubernetes")),
]


def add_part(tmpdir: Path, name: str, source: Path) -> None:
    target = tmpdir / name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="Semantic version tag, e.g., 1.4.0")
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for name, source in PARTS:
            if not source.exists():
                raise SystemExit(f"Missing part {source}")
            add_part(tmpdir, name, source)
        archive = args.output / f"apollo-{args.version}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(tmpdir, arcname="apollo")
        checksum = sha256(archive)
        (archive.with_suffix(archive.suffix + ".sha256")).write_text(f"{checksum}  {archive.name}\n")
        print(f"Built {archive} (sha256 {checksum})")


if __name__ == "__main__":
    main()
