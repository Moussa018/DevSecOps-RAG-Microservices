"""Embeddings (dans le service) et generation (API Anthropic).

- Embeddings : calcules localement, avec un modele integre a l'image au build. Aucun appel externe.
- Generation : API Anthropic, appelee uniquement par ce service. La cle vient de ANTHROPIC_API_KEY
  (Secret Kubernetes monte dans ce pod seulement). Le mode 'fake' permet de tester sans cle.
"""
import hashlib
import math
import os
import re
import threading

BACKEND = os.getenv("LLM_BACKEND", "anthropic")
LLM_MODEL_ID = os.getenv("LLM_MODEL_ID", "claude-haiku-5-5")
EMBED_MODEL = os.getenv("EMBED_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
MODEL_DIR = os.getenv("FASTEMBED_CACHE_PATH", "/models")
DIM = 384  # dimension du modele ; a changer = recreer la collection Qdrant. Meme modele dans ingestion ET rag.
MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "512"))  # borne le cout de chaque reponse

_model = None
_client = None
_lock = threading.Lock()


def _fake_embed(text: str) -> list[float]:
    """Sac de mots hache : deux textes qui partagent des mots ont des vecteurs proches."""
    vec = [0.0] * DIM
    for word in re.findall(r"\w+", text.lower()):
        vec[int(hashlib.md5(word.encode()).hexdigest(), 16) % DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _get_model():
    global _model
    with _lock:
        if _model is None:
            from fastembed import TextEmbedding

            _model = TextEmbedding(model_name=EMBED_MODEL, cache_dir=MODEL_DIR)
        return _model


def _get_client():
    global _client
    with _lock:
        if _client is None:
            import anthropic

            _client = anthropic.Anthropic(timeout=60.0, max_retries=2)  # lit ANTHROPIC_API_KEY
        return _client


def embed(text: str) -> list[float]:
    if BACKEND == "fake":
        return _fake_embed(text)
    return next(iter(_get_model().embed([text]))).tolist()


def generate(system: str, prompt: str) -> str:
    if BACKEND == "fake":
        return "[mode test, sans LLM] Extraits les plus proches : " + prompt[:400]
    resp = _get_client().messages.create(
        model=LLM_MODEL_ID,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
