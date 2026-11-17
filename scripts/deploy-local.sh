#!/usr/bin/env bash
# Deploiement local sur kind. Le LLM est simule (LLM_BACKEND=fake) : aucun compte AWS necessaire.
# Pour tester Bedrock en local, voir README (section « Tester Bedrock depuis kind »).
set -euo pipefail
cd "$(dirname "$0")/.."

kind create cluster --name rag --config k8s/kind-config.yaml || true
istioctl install --set profile=demo -y
kubectl -n istio-system patch svc istio-ingressgateway --type=json \
  -p='[{"op":"replace","path":"/spec/type","value":"NodePort"},{"op":"replace","path":"/spec/ports/1/nodePort","value":30080}]' || true

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

kubectl apply -f k8s/10-gateway.yaml -f k8s/11-python-services.yaml -f k8s/20-qdrant.yaml
kubectl apply -f k8s/istio/
kubectl apply -f k8s/30-network-policies.yaml
kubectl -n rag get pods
