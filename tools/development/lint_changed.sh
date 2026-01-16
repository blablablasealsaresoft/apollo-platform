#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-origin/main}
FILES=$(git diff --name-only "$BASE" -- '*.ts' '*.tsx' '*.py')
if [ -z "$FILES" ]; then
  echo "No files changed"
  exit 0
fi

echo "$FILES" | grep -E '\.py$' >/tmp/pyfiles || true
if [ -s /tmp/pyfiles ]; then
  pip install black isort >/dev/null
  xargs -a /tmp/pyfiles black --check
fi

echo "$FILES" | grep -E '\.tsx?$' >/tmp/tsfiles || true
if [ -s /tmp/tsfiles ]; then
  npm run lint -- "$(paste -sd' ' /tmp/tsfiles)"
fi
