#!/usr/bin/env bash
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
for crt in $dir/../server/*.crt; do
  base=$(basename "$crt" .crt)
  "$dir/generate-server-cert.sh" "$base" "${base}.apollo.local"
done
