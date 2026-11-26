#!/usr/bin/env bash
# Prints a user JWT: scripts/login.sh alice   (password read from .demo-credentials)
set -euo pipefail
user="${1:?usage: login.sh <user>}"
dir="$(dirname "$0")/.."
pw="$(grep "^$user:" "$dir/.demo-credentials" | cut -d' ' -f2)"
curl -sf --ssl-revoke-best-effort --cacert "$dir/.local-ca.crt" "https://localhost:8443/api/auth/login" \
  -H 'Content-Type: application/json' -d "{\"username\":\"$user\",\"password\":\"$pw\"}" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
