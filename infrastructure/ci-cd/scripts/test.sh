#!/usr/bin/env bash
set -euo pipefail

npm test --workspace frontend
pytest --maxfail=1 --disable-warnings -q
