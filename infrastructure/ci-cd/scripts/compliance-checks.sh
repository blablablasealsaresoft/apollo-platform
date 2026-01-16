#!/usr/bin/env bash
set -euo pipefail

echo "[compliance] Verifying Terraform + K8s policies"
checkov -d infrastructure/terraform
kube-score score infrastructure/kubernetes/**/*.yaml || true
