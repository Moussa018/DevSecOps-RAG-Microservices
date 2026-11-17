#!/usr/bin/env bash
# Execute SUR le noeud k3s par la CI via SSM : bash /opt/rag/deploy-on-node.sh <tag-image>
set -euo pipefail
TAG="${1:?usage: deploy-on-node.sh <tag>}"
source /etc/rag.env
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd /opt/rag

aws s3 sync "s3://$BUCKET/release/" /opt/rag/release --delete --region "$REGION"
cd release

# Les manifestes referencent des images locales : on les pointe vers ECR (tag immuable du commit)
for s in gateway ingestion-service rag-service; do
  sed -i "s#image: $s:latest#image: $REGISTRY/rag-secure/$s:$TAG#" k8s/10-gateway.yaml k8s/11-python-services.yaml
done

kubectl apply -f k8s/00-namespace.yaml

# Secret JWT lu depuis Secrets Manager (jamais stocke dans le depot)
kubectl -n rag create secret generic jwt-secret \
  --from-literal=secret="$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --region "$REGION" --query SecretString --output text)" \
  --dry-run=client -o yaml | kubectl apply -f -

# Configuration du LLM : Amazon Bedrock, authentification par le role IAM du noeud (aucune cle d'API)
kubectl -n rag create configmap rag-config \
  --from-literal=LLM_BACKEND=bedrock \
  --from-literal=AWS_REGION="$REGION" \
  --from-literal=AWS_DEFAULT_REGION="$REGION" \
  --from-literal=LLM_MODEL_ID="$LLM_MODEL_ID" \
  --from-literal=EMBED_MODEL_ID="$EMBED_MODEL_ID" \
  --dry-run=client -o yaml | kubectl apply -f -

# Jeton ECR (valable 12 h) pour tirer les images
kubectl -n rag create secret docker-registry ecr \
  --docker-server="$REGISTRY" --docker-username=AWS \
  --docker-password="$(aws ecr get-login-password --region "$REGION")" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/10-gateway.yaml -f k8s/11-python-services.yaml -f k8s/20-qdrant.yaml
kubectl apply -f k8s/istio/
kubectl apply -f k8s/30-network-policies.yaml

for sa in gateway ingestion-service rag-service; do
  kubectl -n rag patch serviceaccount "$sa" -p '{"imagePullSecrets":[{"name":"ecr"}]}'
  kubectl -n rag rollout restart deploy/"$sa"
done

kubectl -n rag get pods
