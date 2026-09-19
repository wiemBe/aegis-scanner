#!/usr/bin/env bash
# Generate a LOCAL, TEST-ONLY certificate authority and an api.openai.com server certificate for
# the mock-egress validation overlay. These certificates never leave the local machine and must
# never be trusted anywhere except the mock validation run: they let the gateway VERIFY the mock
# provider's TLS certificate (verification stays ON) without contacting the real provider.
#
# In production the gateway uses the system trust store and the real api.openai.com certificate;
# PROVIDER_CA_BUNDLE is unset.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/deploy/certs"
mkdir -p "$DIR"

if [ -f "$DIR/server.crt" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "Certificates already exist in $DIR (set FORCE=1 to regenerate)."
  exit 0
fi

# Test CA.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/test-ca.key" -out "$DIR/test-ca.pem" \
  -subj "/CN=Aegis Local Test CA" -days 825

# Server key + CSR for api.openai.com.
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/server.key" -out "$DIR/server.csr" \
  -subj "/CN=api.openai.com"

# Sign the server certificate with a SAN for api.openai.com.
SAN_FILE="$(mktemp)"
printf "subjectAltName=DNS:api.openai.com\n" > "$SAN_FILE"
openssl x509 -req -in "$DIR/server.csr" \
  -CA "$DIR/test-ca.pem" -CAkey "$DIR/test-ca.key" -CAcreateserial \
  -out "$DIR/server.crt" -days 825 -extfile "$SAN_FILE"
rm -f "$SAN_FILE" "$DIR/server.csr" "$DIR/test-ca.srl"

chmod 644 "$DIR"/*.pem "$DIR"/*.crt
chmod 600 "$DIR"/*.key
echo "Wrote test CA and api.openai.com server certificate to $DIR"
