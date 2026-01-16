#!/usr/bin/env bash
set -euo pipefail
terraform workspace select compliance || terraform workspace new compliance
terraform apply -var 'enable_audit_logging=true'
