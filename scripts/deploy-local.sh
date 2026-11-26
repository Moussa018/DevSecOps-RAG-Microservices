#!/usr/bin/env bash
# Local deployment on k3d (k3s in Docker): 3 nodes, built-in Traefik, cert-manager mutual TLS, JWT between services.
# Java microservices: gateway, ingestion-service, rag-service (application) and uaa-service (token authority).
# The LLM is simulated (LLM_BACKEND=fake): no cloud account and no Groq key needed.
# Requirements: docker, k3d, kubectl, openssl 3. See README.
set -euo pipefail
cd "$(dirname "$0")/.."

CERT_MANAGER_VERSION=v1.16.2

# 1 server + 2 agents. Host port 8443 -> Traefik HTTPS (443); host port 8080 -> Traefik HTTP (80), which only redirects.
if ! k3d cluster list 2>/dev/null | grep -q "^rag "; then
  k3d cluster create rag --servers 1 --agents 2 -p "8080:80@loadbalancer" -p "8443:443@loadbalancer"
elif ! docker port k3d-rag-serverlb 2>/dev/null | grep -q "^443/"; then
  k3d cluster edit rag --port-add "8443:443@loadbalancer"   # cluster created before HTTPS was added
fi
kubectl config use-context k3d-rag

# cert-manager: issues the certificate of every service.
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
  kubectl -n cert-manager rollout status deploy/"$d" --timeout=300s
done
kubectl -n kube-system rollout status deploy/traefik --timeout=300s

for s in gateway uaa-service ingestion-service rag-service; do
  docker build -t "$s:latest" -f "services/$s/Dockerfile" .
done
k3d image import gateway:latest uaa-service:latest ingestion-service:latest rag-service:latest -c rag

kubectl apply -f k8s/00-namespace.yaml
# JWT key pair and demo users: generated locally, never committed
bash scripts/gen-secrets.sh
# LLM configuration: real Groq model if the groq-api-key Secret exists, otherwise simulated mode
if kubectl -n rag get secret groq-api-key >/dev/null 2>&1; then BACKEND=groq; else BACKEND=fake; fi
echo "LLM backend: $BACKEND"
kubectl -n rag create configmap rag-config --from-literal=LLM_BACKEND="$BACKEND" \
  --dry-run=client -o yaml | kubectl apply -f -

# PKI: the cert-manager webhook can take a few seconds to accept resources
for i in $(seq 1 10); do
  kubectl apply -f k8s/05-pki.yaml && break || sleep 6
done
kubectl -n rag wait --for=condition=Ready certificate --all --timeout=180s

# Traefik verifies the gateway certificate with the private CA (it expects the key "tls.ca")
tmp="$(mktemp -d)"
kubectl -n rag get secret rag-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > "$tmp/ca.crt"
cp "$tmp/ca.crt" .local-ca.crt   # public CA certificate, for curl --cacert or to import in the browser
kubectl -n rag create secret generic backend-ca --from-file=tls.ca="$tmp/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$tmp"

kubectl -n rag delete deploy/audit-service svc/audit-service networkpolicy/audit-service certificate/audit-service --ignore-not-found
kubectl apply -f k8s/10-gateway.yaml -f k8s/11-services.yaml -f k8s/12-uaa.yaml -f k8s/20-qdrant.yaml
for i in $(seq 1 10); do
  kubectl apply -f k8s/40-ingress.yaml && break || sleep 6   # Traefik CRDs may still be loading
done
kubectl apply -f k8s/30-network-policies.yaml
# Images are rebuilt with the same tag: restart so every pod runs the new build, then wait.
kubectl -n rag rollout restart deploy
kubectl -n rag rollout status deploy --timeout=300s
kubectl -n rag get pods -o wide
echo "Web interface: https://localhost:8443/ (private CA: import .local-ca.crt or accept the warning)"
echo "Demo users and passwords: .demo-credentials. Get a token with: scripts/login.sh alice"
