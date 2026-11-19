#!/usr/bin/env bash
# Runs ON THE K3S SERVER NODE (core subnet), started by CI through SSM:
#   bash /opt/rag/deploy-on-node.sh <image-tag>
set -euo pipefail
TAG="${1:?usage: deploy-on-node.sh <tag>}"
source /etc/rag.env
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /opt/rag

aws s3 sync "s3://$BUCKET/release/" /opt/rag/release --delete --region "$REGION"
cd release

# Manifests reference local images: point them to ECR (immutable tag of the commit)
for s in gateway ingestion-service rag-service; do
  sed -i "s#image: $s:latest#image: $REGISTRY/rag-secure/$s:$TAG#" k8s/10-gateway.yaml k8s/11-python-services.yaml
done

kubectl apply -f k8s/00-namespace.yaml

# JWT secret read from Secrets Manager (never stored in the repository)
kubectl -n rag create secret generic jwt-secret \
  --from-literal=secret="$(aws secretsmanager get-secret-value --secret-id "$JWT_SECRET_ID" --region "$REGION" --query SecretString --output text)" \
  --dry-run=client -o yaml | kubectl apply -f -

# Anthropic API key: mounted in the rag-service pod only. It must have been set once with put-secret-value.
if ! KEY="$(aws secretsmanager get-secret-value --secret-id "$ANTHROPIC_SECRET_ID" --region "$REGION" --query SecretString --output text 2>/dev/null)"; then
  echo "Anthropic API key not set. Run: aws secretsmanager put-secret-value --secret-id $ANTHROPIC_SECRET_ID --secret-string <key>" >&2
  exit 1
fi
kubectl -n rag create secret generic anthropic-api-key --from-literal=key="$KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
unset KEY

# LLM configuration: Anthropic API
kubectl -n rag create configmap rag-config \
  --from-literal=LLM_BACKEND=anthropic \
  --from-literal=LLM_MODEL_ID="$LLM_MODEL_ID" \
  --dry-run=client -o yaml | kubectl apply -f -

# ECR token (valid 12 h) so that every node can pull images
kubectl -n rag create secret docker-registry ecr \
  --docker-server="$REGISTRY" --docker-username=AWS \
  --docker-password="$(aws ecr get-login-password --region "$REGION")" \
  --dry-run=client -o yaml | kubectl apply -f -

# PKI: cert-manager issues the TLS certificate of each service before the pods start
kubectl apply -f k8s/05-pki.yaml
kubectl -n rag wait --for=condition=Ready certificate --all --timeout=180s

# Traefik verifies the gateway certificate with the private CA (it expects the key "tls.ca")
tmp="$(mktemp -d)"
kubectl -n rag get secret rag-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > "$tmp/ca.crt"
kubectl -n rag create secret generic backend-ca --from-file=tls.ca="$tmp/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$tmp"

kubectl apply -f k8s/10-gateway.yaml -f k8s/11-python-services.yaml -f k8s/20-qdrant.yaml
kubectl apply -f k8s/40-ingress.yaml
kubectl apply -f k8s/30-network-policies.yaml

for sa in gateway ingestion-service rag-service; do
  kubectl -n rag patch serviceaccount "$sa" -p '{"imagePullSecrets":[{"name":"ecr"}]}'
  kubectl -n rag rollout restart deploy/"$sa"
done

kubectl -n rag get pods -o wide
