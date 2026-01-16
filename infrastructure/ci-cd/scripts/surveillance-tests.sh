#!/usr/bin/env bash
set -euo pipefail

echo "[surveillance] Running camera feed simulators"
python -m tests.surveillance.simulator --streams 3 --duration 60
