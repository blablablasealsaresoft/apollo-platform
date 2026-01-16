#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-staging}
cd "$(dirname "$0")/../environments/${ENVIRONMENT}"
terraform init
terraform apply -auto-approve
