"""Acces au LLM et aux embeddings : Amazon Bedrock (par defaut) ou mode 'fake' pour tester sans AWS.

Authentification Bedrock : roles IAM (aucune cle d'API). Le trafic passe par un VPC endpoint prive.
"""
import hashlib
import json
import math
import os
import re

BACKEND = os.getenv("LLM_BACKEND", "bedrock")
REGION = os.getenv("AWS_REGION", "eu-west-3")
EMBED_MODEL_ID = os.getenv("EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")
LLM_MODEL_ID = os.getenv("LLM_MODEL_ID", "eu.anthropic.claude-haiku-4-5-20251001-v1:0")
DIM = 1024  # dimension des embeddings Titan v2 ; a changer = recreer la collection Qdrant

_client = None


def _runtime():
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config

        _client = boto3.client(
            "bedrock-runtime",
            region_name=REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=60),
        )
    return _client


def _fake_embed(text: str) -> list[float]:
    """Sac de mots hache : deux textes qui partagent des mots ont des vecteurs proches."""
    vec = [0.0] * DIM
    for word in re.findall(r"\w+", text.lower()):
        vec[int(hashlib.md5(word.encode()).hexdigest(), 16) % DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def embed(text: str) -> list[float]:
    if BACKEND == "fake":
        return _fake_embed(text)
    resp = _runtime().invoke_model(
        modelId=EMBED_MODEL_ID,
        body=json.dumps({"inputText": text, "dimensions": DIM, "normalize": True}),
        contentType="application/json",
        accept="application/json",
    )
    return json.loads(resp["body"].read())["embedding"]


def generate(system: str, prompt: str) -> str:
    if BACKEND == "fake":
        return "[mode test, sans LLM] Extraits les plus proches : " + prompt[:400]
    resp = _runtime().converse(
        modelId=LLM_MODEL_ID,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 512, "temperature": 0.2},
    )
    return resp["output"]["message"]["content"][0]["text"]
