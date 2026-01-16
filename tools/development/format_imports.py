#!/usr/bin/env python3
"""Sort imports in provided Python files; fallback for environments without isort."""
import argparse
import pathlib


def sort_imports(path: pathlib.Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    imports = [line for line in lines if line.startswith("import") or line.startswith("from")]
    stripped = [line for line in lines if line not in imports]
    new_content = "\n".join(sorted(imports) + ["", *stripped]).strip() + "\n"
    path.write_text(new_content, encoding="utf-8")
    print(f"Formatted {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    for file in args.files:
        sort_imports(file)


if __name__ == "__main__":
    main()
