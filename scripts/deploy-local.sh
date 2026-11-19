#!/usr/bin/env bash
# Deploiement local sur kind : cert-manager (TLS mutuel) + ingress-nginx, sans service mesh.
# Le LLM est simule (LLM_BACKEND=fake) : aucun compte AWS necessaire.
# Pour tester Bedrock en local, voir README (section « Tester Bedrock depuis kind »).
set -euo pipefail
cd "$(dirname "$0")/.."

CERT_MANAGER_VERSION=v1.16.2
INGRESS_NGINX_VERSION=controller-v1.11.3

kind create cluster --name rag --config k8s/kind-config.yaml || true

# ingress-nginx : NodePort 30080, relie au port 8080 de l'hote par kind-config.yaml
kubectl apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/${INGRESS_NGINX_VERSION}/deploy/static/provider/baremetal/deploy.yaml"
kubectl -n ingress-nginx patch svc ingress-nginx-controller --type=json \
  -p='[{"op":"replace","path":"/spec/ports/0/nodePort","value":30080}]'

# cert-manager : emet les certificats de chaque service
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
for d in cert-manager cert-manager-cainjector cert-manager-webhook; do
  kubectl -n cert-manager rollout status deploy/"$d" --timeout=300s
done
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=300s

for s in gateway ingestion-service rag-service; do
  docker build -t "$s:latest" "services/$s"
  kind load docker-image "$s:latest" --name rag
done

kubectl apply -f k8s/00-namespace.yaml
# Secret JWT genere localement, jamais commite
kubectl -n rag create secret generic jwt-secret --from-literal=secret="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
# Configuration du LLM : mode simule
kubectl -n rag create configmap rag-config --from-literal=LLM_BACKEND=fake \
  --dry-run=client -o yaml | kubectl apply -f -

# PKI : le webhook de cert-manager peut mettre quelques secondes a accepter les ressources
for i in $(seq 1 10); do
  kubectl apply -f k8s/05-pki.yaml && break || sleep 6
done
kubectl -n rag wait --for=condition=Ready certificate --all --timeout=180s

kubectl apply -f k8s/10-gateway.yaml -f k8s/11-python-services.yaml -f k8s/20-qdrant.yaml
kubectl apply -f k8s/40-ingress.yaml
kubectl apply -f k8s/30-network-policies.yaml
kubectl -n rag get pods
