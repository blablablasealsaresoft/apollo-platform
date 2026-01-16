#!/usr/bin/env bash
set -euo pipefail

trs() { printf '\n[security] %s\n' "$1"; }
trs "Running Trivy filesystem scan"
trivy fs --exit-code 1 --severity HIGH,CRITICAL .

trs "Scanning dependencies"
if command -v npm >/dev/null; then
  npm audit --audit-level=high || true
fi
if command -v pip-audit >/dev/null; then
  pip-audit || true
fi
