#!/usr/bin/env python3
"""Create fake embeddings for docs so tooling can be validated offline."""
import argparse
import hashlib
import json
import pathlib


def make_embedding(text: str, dimensions: int = 8) -> list[float]:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    chunk = len(digest) // dimensions
    return [int.from_bytes(digest[i * chunk:(i + 1) * chunk], "big") / 2**32 for i in range(dimensions)]


def process_file(path: pathlib.Path) -> dict:
    text = path.read_text(encoding="utf-8")
    return {
        "id": path.stem,
        "text": text.strip(),
        "embedding": make_embedding(text),
        "metadata": {
            "case": "OneCoin",
            "source": str(path),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=pathlib.Path, help="Directory or file with docs")
    parser.add_argument("--output", required=True, type=pathlib.Path, help="Path to JSONL output")
    args = parser.parse_args()

    files = [args.input] if args.input.is_file() else sorted(args.input.glob("**/*.txt"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for fpath in files:
            record = process_file(fpath)
            fh.write(json.dumps(record) + "\n")
            print(f"[embedding] {fpath} -> {args.output}")


if __name__ == "__main__":
    main()
