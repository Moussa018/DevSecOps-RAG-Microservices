#!/usr/bin/env bash
# Obtient un JWT utilisateur aupres de uaa-service (via le gateway : POST /api/auth/login).
#   scripts/login.sh alice            -> affiche le jeton
#   TOKEN=$(scripts/login.sh alice)
set -euo pipefail
PY=python3; python3 -c "" >/dev/null 2>&1 || PY=python
user="${1:?usage: login.sh <user>}"
pw="$(grep "^$user:" "$(dirname "$0")/../.demo-credentials" | cut -d' ' -f2)"
curl -sf "http://localhost:8080/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$user\",\"password\":\"$pw\"}" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
