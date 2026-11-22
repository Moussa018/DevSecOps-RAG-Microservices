"""Ingestion : nettoie (secrets/PII), decoupe, vectorise (modele local) et stocke avec ACL."""
import asyncio
import logging
import os
import re
import uuid

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

import llm
from auth import Principal, require
from svc_client import audit, mtls_client

log = logging.getLogger("ingestion")
QDRANT = os.getenv("QDRANT_URL", "https://qdrant:6333")
COLLECTION = "docs"
TLS_DIR = os.getenv("TLS_DIR", "/tls")


def qdrant_client(timeout: int = 60) -> httpx.AsyncClient:
    """Client TLS mutuel vers Qdrant."""
    return mtls_client(timeout)

MAX_CHUNKS = int(os.getenv("MAX_CHUNKS", "100"))  # borne le cout de l'API externe par document

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Donnees sensibles a masquer AVANT indexation ET avant tout envoi a l'API externe
REDACTIONS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[PRIVATE_KEY]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CARD]"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
]


# Controle de contenu (comme SecureDevOps : on rejette ce qui n'est pas du texte avant tout traitement)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def redact(text: str) -> tuple[str, int]:
    n = 0
    for rx, repl in REDACTIONS:
        text, k = rx.subn(repl, text)
        n += k
    return text, n


def chunk(text: str, size=800, overlap=100):
    i = 0
    while i < len(text):
        yield text[i:i + size]
        i += size - overlap


class Doc(BaseModel):
    title: str = Field(max_length=200)
    text: str = Field(max_length=200_000)
    allowed_groups: list[str] = Field(min_length=1, max_length=20)  # ACL obligatoire


@app.get("/healthz")
def health():
    return {"ok": True}


@app.post("/documents")
async def ingest(doc: Doc, p: Principal = Depends(require("ingestion-service", {"gateway"}))):
    # L'appelant ne peut partager qu'avec des groupes dont il est membre
    if "INGEST" not in p.roles:
        raise HTTPException(403, "role INGEST requis")
    if not set(doc.allowed_groups) <= set(p.groups):
        await audit("ingest.denied", p.user, reason="group_not_allowed")
        raise HTTPException(403, "groupe non autorise")
    if CONTROL.search(doc.text):
        raise HTTPException(400, "contenu binaire refuse")
    clean, redacted = redact(doc.text)
    parts = list(chunk(clean))
    if len(parts) > MAX_CHUNKS:
        raise HTTPException(413, "document trop volumineux")
    doc_id = str(uuid.uuid4())
    try:
        vectors = [await asyncio.to_thread(llm.embed, p) for p in parts]
    except Exception:
        log.exception("echec des embeddings")
        raise HTTPException(502, "service d'embeddings indisponible")
    points = [
        {"id": str(uuid.uuid4()), "vector": v,
         "payload": {"doc_id": doc_id, "title": doc.title, "chunk": n, "text": part,
                     "groups": doc.allowed_groups, "owner": p.user}}
        for n, (part, v) in enumerate(zip(parts, vectors))
    ]
    async with qdrant_client() as c:
        # idempotent : un 409 (collection deja creee) est ignore
        await c.put(f"{QDRANT}/collections/{COLLECTION}",
                    json={"vectors": {"size": llm.DIM, "distance": "Cosine"}})
        r = await c.put(f"{QDRANT}/collections/{COLLECTION}/points", json={"points": points})
        r.raise_for_status()
    await audit("ingest.ok", p.user, doc_id=doc_id, chunks=len(points), redactions=redacted)
    return {"doc_id": doc_id, "chunks": len(points), "redactions": redacted}
