#!/usr/bin/env bash
set -euo pipefail

NAME=${1:-apollo-ca}
mkdir -p ../ca
openssl genrsa -out ../ca/${NAME}.key 4096
openssl req -x509 -new -nodes -key ../ca/${NAME}.key -sha256 -days 3650 -subj "/CN=${NAME}" -out ../ca/${NAME}.crt
printf 'Generated CA %s\n' "$NAME"
