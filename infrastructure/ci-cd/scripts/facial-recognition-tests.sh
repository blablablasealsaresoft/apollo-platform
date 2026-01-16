#!/usr/bin/env bash
set -euo pipefail

echo "[facial] Running embedding regression suite"
python -m tests.facial_recognition.regression --baseline data/models/facial/baseline.json
