"""audit-service : collecte les evenements de securite des autres services.

Ecriture : jeton de service (scope audit:write) emis a gateway, ingestion-service ou rag-service.
Lecture  : jeton echange par le gateway pour un utilisateur ayant le role ADMIN.
Chaque evenement est aussi ecrit en JSON sur stdout (collecte par le runtime). Les derniers evenements sont
gardes en memoire : en production, utiliser un stockage durable et append-only.
"""
import json
import logging
import time
from collections import deque

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from auth import Principal, require

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("audit")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
EVENTS: deque = deque(maxlen=1000)
WRITERS = {"gateway", "ingestion-service", "rag-service"}


class Event(BaseModel):
    event: str = Field(max_length=64, pattern=r"^[a-z_.]+$")
    user: str | None = Field(None, max_length=64)
    detail: dict = Field(default_factory=dict, max_length=20)


@app.get("/healthz")
def health():
    return {"ok": True}


@app.post("/events", status_code=202)
def write(e: Event, p: Principal = Depends(require("audit-service", WRITERS, scope="audit:write"))):
    if p.user is not None:
        raise HTTPException(403, "jeton de service requis")
    rec = {"ts": time.time(), "source": p.caller, **e.model_dump()}
    EVENTS.append(rec)
    log.info(json.dumps(rec, default=str))


@app.get("/events")
def read(limit: int = 100, p: Principal = Depends(require("audit-service", {"gateway"}))):
    if "ADMIN" not in p.roles:
        raise HTTPException(403, "role ADMIN requis")
    return {"events": list(EVENTS)[-max(1, min(limit, 500)):]}
