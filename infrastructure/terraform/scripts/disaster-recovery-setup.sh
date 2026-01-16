#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../environments/disaster-recovery"
terraform init
terraform apply -auto-approve
