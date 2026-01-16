#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG=${1:?"Usage: deploy.sh <image> [env]"}
ENVIRONMENT=${2:-staging}
KUBECONFIG_B64=${KUBECONFIG_B64:?"KUBECONFIG_B64 secret required"}

echo "$KUBECONFIG_B64" | base64 -d > kubeconfig
kubectl --kubeconfig kubeconfig apply -k infrastructure/kubernetes/overlays/${ENVIRONMENT}
kubectl --kubeconfig kubeconfig set image deployment/apollo-api apollo-api=$IMAGE_TAG -n apollo-system
kubectl --kubeconfig kubeconfig rollout status deployment/apollo-api -n apollo-system --timeout=180s
