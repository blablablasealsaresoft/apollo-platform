#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(git rev-parse --show-toplevel)
pushd "$PROJECT_ROOT" >/dev/null

echo "[build] Compiling shared packages"
npm install --workspace frontend
npm run build --workspace frontend

poetry build || true

docker compose -f docker-compose.dev.yml build
popd >/dev/null
