#!/usr/bin/env python3
"""Generate a basic Apollo service scaffold."""
import argparse
import pathlib
import textwrap

TEMPLATE = textwrap.dedent(
    """from fastapi import FastAPI\n\napp = FastAPI(title=\"{name}\")\n\n@app.get('/healthz')\ndef health() -> dict:\n    return {{'status': 'ok', 'service': '{name}'}}\n"""
)

DOCKERFILE = textwrap.dedent(
    """FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt ./\nRUN pip install -r requirements.txt\nCOPY . .\nCMD [\"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8080\"]\n"""
)

REQUIREMENTS = "fastapi\nuvicorn[standard]\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Service slug, e.g., evidence-service")
    parser.add_argument("--path", type=pathlib.Path, default=pathlib.Path("services"))
    args = parser.parse_args()

    target = args.path / args.name
    target.mkdir(parents=True, exist_ok=True)
    (target / "main.py").write_text(TEMPLATE.format(name=args.name), encoding="utf-8")
    (target / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (target / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (target / "README.md").write_text(f"# {args.name}\n\nAuto-generated service skeleton.\n", encoding="utf-8")
    print(f"Created service at {target}")


if __name__ == "__main__":
    main()
