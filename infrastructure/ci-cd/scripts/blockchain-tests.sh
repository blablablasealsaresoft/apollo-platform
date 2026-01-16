#!/usr/bin/env bash
set -euo pipefail

echo "[blockchain] Running transaction tracing checks"
pytest tests/blockchain --maxfail=1
