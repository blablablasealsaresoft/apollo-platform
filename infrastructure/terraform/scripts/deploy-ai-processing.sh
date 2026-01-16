#!/usr/bin/env bash
set -euo pipefail
ENVIRONMENT=${1:-production}
cd "$(dirname "$0")/../environments/${ENVIRONMENT}"
terraform init -upgrade
terraform apply -auto-approve -target=module.kubernetes
