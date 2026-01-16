#!/usr/bin/env bash
set -euo pipefail

NAME=${1:-apollo-client}
CA=${2:-apollo-ca}
DIR=$(cd "$(dirname "$0")" && pwd)

openssl genrsa -out "$DIR/../client/${NAME}.key" 4096
openssl req -new -key "$DIR/../client/${NAME}.key" -out "$DIR/../client/${NAME}.csr" -subj "/CN=${NAME}"
cat > "$DIR/../client/${NAME}.ext" <<EXT
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in "$DIR/../client/${NAME}.csr" \
  -CA "$DIR/../ca/${CA}.crt" -CAkey "$DIR/../ca/${CA}.key" -CAcreateserial \
  -out "$DIR/../client/${NAME}.crt" -days 730 -sha256 -extfile "$DIR/../client/${NAME}.ext"
