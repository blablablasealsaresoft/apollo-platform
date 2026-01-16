#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-staging}
REVISION=${2:?"Provide a deployment revision"}

kubectl -n apollo-system rollout undo deployment/apollo-api --to-revision="$REVISION"
kubectl -n apollo-system rollout status deployment/apollo-api --timeout=120s
