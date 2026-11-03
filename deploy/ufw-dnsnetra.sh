#!/usr/bin/env bash
set -euo pipefail

: "${ADMIN_CIDR:?set ADMIN_CIDR, e.g. 10.0.0.0/8}"
: "${USER_CIDR:?set USER_CIDR, e.g. 10.0.0.0/8}"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$ADMIN_CIDR" to any port 22 proto tcp comment 'SSH admin subnet'
ufw allow from "$USER_CIDR" to any port 443 proto tcp comment 'DNSNetra HTTPS'
ufw --force enable
ufw status verbose
