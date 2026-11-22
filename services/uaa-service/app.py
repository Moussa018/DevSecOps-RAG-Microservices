"""uaa-service : seule autorite qui signe des JWT (RS256).

- POST /auth/login     : utilisateur + mot de passe -> jeton utilisateur (aud=rag-gateway, 15 min)
- POST /auth/token     : un service (client_credentials) -> jeton de service pour UNE audience autorisee (5 min)
- POST /auth/exchange  : le gateway echange le jeton utilisateur contre un jeton pour UN service cible (2 min),
                         qui conserve l'identite de l'utilisateur et porte `act.sub` = gateway (RFC 8693)
La cle privee n'est montee que dans ce pod. Les autres services ne connaissent que la cle publique.
"""
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque

import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from auth import ISSUER, public_key

log = logging.getLogger("uaa")
logging.basicConfig(level=logging.INFO, format="%(message)s")

USER_TTL, SERVICE_TTL, EXCHANGE_TTL = 900, 300, 120
GATEWAY_AUD = "rag-gateway"
PRIVATE_KEY = open(os.getenv("JWT_PRIVATE_KEY", "/keys/private.pem")).read()
USERS: dict = json.load(open(os.getenv("USERS_FILE", "/config/users.json")))
CLIENTS: dict = json.load(open(os.getenv("CLIENTS_FILE", "/config/clients.json")))
# format USERS   : {"alice": {"password": "pbkdf2_sha256$<iter>$<salt hex>$<hash hex>", "roles": [...], "groups": [...]}}
# format CLIENTS : {"gateway": {"secret_sha256": "<hex>", "audiences": [...], "exchange": [...]}}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_fails: dict[str, deque] = defaultdict(deque)
_DUMMY = "pbkdf2_sha256$600000$00$" + "0" * 64


def sign(claims: dict, ttl: int) -> str:
    now = int(time.time())
    body = {"iss": ISSUER, "iat": now, "exp": now + ttl, "jti": str(uuid.uuid4()), **claims}
    return jwt.encode(body, PRIVATE_KEY, algorithm="RS256")


def check_password(stored: str, password: str) -> bool:
    try:
        _, it, salt, expected = stored.split("$")
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it)).hex()
    except ValueError:
        return False
    return hmac.compare_digest(h, expected)


def authenticate_client(client_id: str, secret: str) -> dict:
    c = CLIENTS.get(client_id)
    digest = hashlib.sha256(secret.encode()).hexdigest()
    # comparaison en temps constant, meme pour un client inconnu
    if not hmac.compare_digest(digest, (c or {}).get("secret_sha256", "0" * 64)) or c is None:
        log.warning(json.dumps({"event": "client_auth_failed", "client": client_id[:64]}))
        raise HTTPException(401, "client invalide")
    return c


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ClientToken(BaseModel):
    client_id: str = Field(max_length=64)
    client_secret: str = Field(max_length=128)
    audience: str = Field(max_length=64)


class Exchange(ClientToken):
    subject_token: str = Field(max_length=4096)


@app.get("/healthz")
def health():
    return {"ok": True}


@app.post("/auth/login")
def login(body: Login):
    key = body.username   # l'adresse source est celle du gateway : inutile pour distinguer les clients
    q, now = _fails[key], time.time()
    while q and q[0] < now - 60:
        q.popleft()
    if len(q) >= 5:  # 5 echecs par minute et par utilisateur (par replica)
        raise HTTPException(429, "trop de tentatives")
    u = USERS.get(body.username)
    ok = check_password((u or {}).get("password", _DUMMY), body.password) and u is not None
    if not ok:
        q.append(now)
        log.warning(json.dumps({"event": "login_failed", "user": body.username}))
        raise HTTPException(401, "identifiants invalides")
    log.info(json.dumps({"event": "login_ok", "user": body.username}))
    token = sign({"sub": body.username, "aud": GATEWAY_AUD, "typ": "user",
                  "roles": u["roles"], "groups": u["groups"]}, USER_TTL)
    return {"access_token": token, "token_type": "Bearer", "expires_in": USER_TTL}


@app.post("/auth/token")
def service_token(body: ClientToken):
    c = authenticate_client(body.client_id, body.client_secret)
    if body.audience not in c.get("audiences", []):
        raise HTTPException(403, "audience non autorisee pour ce client")
    scope = "audit:write" if body.audience == "audit-service" else "call"
    token = sign({"sub": body.client_id, "aud": body.audience, "typ": "service", "scope": scope}, SERVICE_TTL)
    return {"access_token": token, "token_type": "Bearer", "expires_in": SERVICE_TTL}


@app.post("/auth/exchange")
def exchange(body: Exchange):
    c = authenticate_client(body.client_id, body.client_secret)
    if body.audience not in c.get("exchange", []):
        raise HTTPException(403, "echange non autorise pour cette audience")
    try:
        u = jwt.decode(body.subject_token, public_key(), algorithms=["RS256"], audience=GATEWAY_AUD,
                       issuer=ISSUER, options={"require": ["exp", "iat", "sub"]}, leeway=5)
    except jwt.PyJWTError:
        raise HTTPException(401, "jeton utilisateur invalide")
    if u.get("typ") != "user":
        raise HTTPException(401, "jeton utilisateur invalide")
    token = sign({"sub": u["sub"], "aud": body.audience, "typ": "exchange", "act": {"sub": body.client_id},
                  "roles": u.get("roles", []), "groups": u.get("groups", [])},
                 min(EXCHANGE_TTL, max(1, int(u["exp"] - time.time()))))
    return {"access_token": token, "token_type": "Bearer", "expires_in": EXCHANGE_TTL}
