#!/usr/bin/env bash
set -euo pipefail

HOSTNAME="${1:-dnsnetra.corp.local}"
CERT_DIR=/etc/ssl/dnsnetra

install -d -m 0755 "$CERT_DIR"
openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 825 \
  -keyout "$CERT_DIR/dnsnetra.key" \
  -out "$CERT_DIR/dnsnetra.crt" \
  -subj "/CN=${HOSTNAME}" \
  -addext "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 0600 "$CERT_DIR/dnsnetra.key"
chmod 0644 "$CERT_DIR/dnsnetra.crt"

echo "Installed certificate for ${HOSTNAME} in ${CERT_DIR}"
echo "Distribute ${CERT_DIR}/dnsnetra.crt to clients via GPO/MDM."
