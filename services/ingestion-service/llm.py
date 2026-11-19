"""Embeddings calcules DANS le service : aucun appel externe, aucun acces Internet requis.

Le modele est integre a l'image au build (voir Dockerfile). Le mode 'fake' permet de tester sans modele.
"""
import hashlib
import math
import os
import re
import threading

BACKEND = os.getenv("LLM_BACKEND", "anthropic")
EMBED_MODEL = os.getenv("EMBED_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
MODEL_DIR = os.getenv("FASTEMBED_CACHE_PATH", "/models")
DIM = 384  # dimension du modele ; a changer = recreer la collection Qdrant. Meme modele dans ingestion ET rag.

_model = None
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


def embed(text: str) -> list[float]:
    if BACKEND == "fake":
        return _fake_embed(text)
    return next(iter(_get_model().embed([text]))).tolist()
