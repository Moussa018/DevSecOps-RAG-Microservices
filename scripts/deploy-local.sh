#!/usr/bin/env bash
# Local deployment on k3d (k3s in Docker): 3 nodes like AWS, built-in Traefik, cert-manager mutual TLS.
# The LLM is simulated (LLM_BACKEND=fake): no AWS account and no Anthropic key needed.
# Requirements: docker, k3d, kubectl, openssl. See README, section 10.
set -euo pipefail
cd "$(dirname "$0")/.."

CERT_MANAGER_VERSION=v1.16.2

# 1 server (role=core) + 2 agents (role=ingest, role=query). Host port 8080 -> Traefik port 80.
if ! k3d cluster list 2>/dev/null | grep -q '^rag '; then
  k3d cluster create rag --servers 1 --agents 2 \
    -p "8080:80@loadbalancer" \
    --k3s-node-label "role=core@server:0" \
    --k3s-node-label "role=ingest@agent:0" \
    --k3s-node-label "role=query@agent:1"
fi
kubectl config use-context k3d-rag

# cert-manager: issues the certificate of every service. Pinned to the core node, like on AWS.
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
  kubectl -n cert-manager patch deploy/"$d" -p '{"spec":{"template":{"spec":{"nodeSelector":{"role":"core"}}}}}'
  kubectl -n cert-manager rollout status deploy/"$d" --timeout=300s
done
kubectl -n kube-system rollout status deploy/traefik --timeout=300s

for s in gateway ingestion-service rag-service; do
  docker build -t "$s:latest" "services/$s"
done
k3d image import gateway:latest ingestion-service:latest rag-service:latest -c rag

kubectl apply -f k8s/00-namespace.yaml
# JWT secret generated locally, never committed
kubectl -n rag create secret generic jwt-secret --from-literal=secret="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
# LLM configuration: simulated mode
kubectl -n rag create configmap rag-config --from-literal=LLM_BACKEND=fake \
  --dry-run=client -o yaml | kubectl apply -f -

# PKI: the cert-manager webhook can take a few seconds to accept resources
for i in $(seq 1 10); do
  kubectl apply -f k8s/05-pki.yaml && break || sleep 6
done
kubectl -n rag wait --for=condition=Ready certificate --all --timeout=180s

# Traefik verifies the gateway certificate with the private CA (it expects the key "tls.ca")
tmp="$(mktemp -d)"
kubectl -n rag get secret rag-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > "$tmp/ca.crt"
kubectl -n rag create secret generic backend-ca --from-file=tls.ca="$tmp/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$tmp"

kubectl apply -f k8s/10-gateway.yaml -f k8s/11-python-services.yaml -f k8s/20-qdrant.yaml
for i in $(seq 1 10); do
  kubectl apply -f k8s/40-ingress.yaml && break || sleep 6   # Traefik CRDs may still be loading
done
kubectl apply -f k8s/30-network-policies.yaml
kubectl -n rag get pods -o wide
