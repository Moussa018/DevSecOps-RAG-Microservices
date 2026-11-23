import asyncio
import logging
import os
import time

import httpx

log = logging.getLogger("svc_client")
TLS_DIR = os.getenv("TLS_DIR", "/tls")
UAA = os.getenv("UAA_URL", "https://uaa-service:8000")
AUDIT = os.getenv("AUDIT_URL", "https://audit-service:8000")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")

_cache: dict[str, tuple[str, float]] = {}
_lock = asyncio.Lock()


def mtls_client(timeout: int = 10) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=f"{TLS_DIR}/ca.crt",
                             cert=(f"{TLS_DIR}/tls.crt", f"{TLS_DIR}/tls.key"))


async def token_for(audience: str) -> str:
    async with _lock:
        tok, exp = _cache.get(audience, ("", 0.0))
        if tok and exp - 30 > time.time():
            return tok
        async with mtls_client() as c:
            r = await c.post(f"{UAA}/auth/token", json={
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "audience": audience})
            r.raise_for_status()
        body = r.json()
        _cache[audience] = (body["access_token"], time.time() + body["expires_in"])
        return body["access_token"]


async def audit(event: str, user: str | None, **detail) -> None:
    try:
        tok = await token_for("audit-service")
        async with mtls_client(5) as c:
            r = await c.post(f"{AUDIT}/events", headers={"Authorization": f"Bearer {tok}"},
                             json={"event": event, "user": user, "detail": detail})
            r.raise_for_status()
    except Exception:
        log.exception("echec de l'envoi de l'evenement d'audit %s", event)
