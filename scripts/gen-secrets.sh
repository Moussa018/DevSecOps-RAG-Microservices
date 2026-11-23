#!/usr/bin/env bash
# Generates the JWT key pair and the demo users, then applies them to the cluster as Kubernetes objects.
# Nothing is written to the repository except .demo-credentials (git-ignored).
#   uaa-jwt-key  (Secret)    : private RSA 3072 key, mounted in uaa-service only
#   jwt-public   (ConfigMap) : public key, mounted in every service that verifies tokens
#   uaa-config   (Secret)    : users.json, passwords hashed with salted PBKDF2-SHA256 (600,000 iterations)
# Requirements: openssl 3, kubectl.
set -euo pipefail
cd "$(dirname "$0")/.."

ITER=600000
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$tmp/private.pem" 2>/dev/null
openssl pkey -in "$tmp/private.pem" -pubout -out "$tmp/public.pem"

# Format read by uaa-service: pbkdf2_sha256$iterations$salt_hex$hash_hex
hash_password() {
  local salt digest
  salt="$(openssl rand -hex 16)"
  digest="$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "pass:$1" -kdfopt "hexsalt:$salt" \
            -kdfopt "iter:$ITER" PBKDF2 | tr -d ':' | tr 'A-F' 'a-f')"
  printf 'pbkdf2_sha256$%s$%s$%s' "$ITER" "$salt" "$digest"
}
random_password() { openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 22; }

ALICE="$(random_password)"
BOB="$(random_password)"
cat > "$tmp/users.json" <<EOF
{"alice": {"password": "$(hash_password "$ALICE")", "roles": ["INGEST", "QUERY"], "groups": ["finance"]},
 "bob":   {"password": "$(hash_password "$BOB")", "roles": ["QUERY"], "groups": ["rh"]}}
EOF
printf 'alice: %s\nbob: %s\n' "$ALICE" "$BOB" > .demo-credentials

kubectl -n rag create secret generic uaa-jwt-key --from-file=private.pem="$tmp/private.pem" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n rag create configmap jwt-public --from-file=public.pem="$tmp/public.pem" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n rag create secret generic uaa-config --from-file=users.json="$tmp/users.json" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "Demo passwords written to .demo-credentials" >&2
