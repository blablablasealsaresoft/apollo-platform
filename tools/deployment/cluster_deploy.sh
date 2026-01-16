#!/usr/bin/env bash
set -euo pipefail

KUBECONFIG_PATH=${KUBECONFIG_PATH:-kubeconfig}
MANIFEST_PATH=${1:-infrastructure/kubernetes/kustomization.yaml}

if [ ! -f "$KUBECONFIG_PATH" ]; then
  echo "Missing kubeconfig at $KUBECONFIG_PATH" >&2
  exit 1
fi

echo "Applying manifests from $MANIFEST_PATH"
kubectl --kubeconfig "$KUBECONFIG_PATH" apply -k "$(dirname "$MANIFEST_PATH")"

for deploy in apollo-api apollo-authentication; do
  if kubectl --kubeconfig "$KUBECONFIG_PATH" get deploy "$deploy" >/dev/null 2>&1; then
    kubectl --kubeconfig "$KUBECONFIG_PATH" rollout status deployment/$deploy -n apollo-system --timeout=180s
  fi
done
