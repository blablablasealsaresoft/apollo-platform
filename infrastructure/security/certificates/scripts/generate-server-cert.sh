#!/usr/bin/env bash
set -euo pipefail

NAME=${1:-apollo-server}
HOST=${2:-apollo.local}
CA=${3:-apollo-ca}
DIR=$(cd "$(dirname "$0")" && pwd)

openssl genrsa -out "$DIR/../server/${NAME}.key" 4096
cat > "$DIR/../server/${NAME}.csr.cnf" <<CFG
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
CN = ${HOST}
CFG
openssl req -new -key "$DIR/../server/${NAME}.key" -out "$DIR/../server/${NAME}.csr" -config "$DIR/../server/${NAME}.csr.cnf"
cat > "$DIR/../server/${NAME}.ext" <<EXT
subjectAltName=DNS:${HOST}
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "$DIR/../server/${NAME}.csr" \
  -CA "$DIR/../ca/${CA}.crt" -CAkey "$DIR/../ca/${CA}.key" -CAcreateserial \
  -out "$DIR/../server/${NAME}.crt" -days 825 -sha256 -extfile "$DIR/../server/${NAME}.ext"
