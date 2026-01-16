#!/usr/bin/env bash
set -euo pipefail

echo "[voice] Validating speaker identification models"
pytest tests/voice_processing -m "not slow"
