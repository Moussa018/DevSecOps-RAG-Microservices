import hashlib
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent / "services"


def _pbkdf2(pw: str) -> str:
    salt = os.urandom(8)
    return f"pbkdf2_sha256$1000${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 1000).hex()}"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (d / "private.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "public.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
    (d / "users.json").write_text(json.dumps({
        "alice": {"password": _pbkdf2("pw-alice"), "roles": ["INGEST", "QUERY"], "groups": ["finance"]},
        "root": {"password": _pbkdf2("pw-root"), "roles": ["ADMIN"], "groups": []}}))
    (d / "clients.json").write_text(json.dumps({
        "gateway": {"secret_sha256": sha("gw"), "audiences": ["audit-service"],
                    "exchange": ["rag-service", "ingestion-service", "audit-service"]},
        "rag-service": {"secret_sha256": sha("rag"), "audiences": ["audit-service"], "exchange": []},
        "intruder": {"secret_sha256": sha("x"), "audiences": ["audit-service"], "exchange": []}}))
    os.environ.update(JWT_PRIVATE_KEY=str(d / "private.pem"), JWT_PUBLIC_KEY=str(d / "public.pem"),
                      USERS_FILE=str(d / "users.json"), CLIENTS_FILE=str(d / "clients.json"))
    sys.path.insert(0, str(ROOT / "uaa-service"))
    uaa = _load("uaa_app", ROOT / "uaa-service" / "app.py")
    audit = _load("audit_app", ROOT / "audit-service" / "app.py")
    return TestClient(uaa.app), TestClient(audit.app), d, key


def login(uaa, user="alice", pw="pw-alice"):
    return uaa.post("/auth/login", json={"username": user, "password": pw})


def exchange(uaa, user_token, aud="rag-service", cid="gateway", secret="gw"):
    return uaa.post("/auth/exchange", json={"client_id": cid, "client_secret": secret,
                                            "audience": aud, "subject_token": user_token})


def test_login_ok_and_bad_password(env):
    uaa = env[0]
    assert login(uaa).status_code == 200
    assert login(uaa, pw="nope").status_code == 401
    assert login(uaa, user="ghost").status_code == 401


def test_login_rate_limited(env):
    uaa = env[0]
    codes = [login(uaa, user="brute", pw="bad").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_exchange_keeps_identity_and_audience(env):
    uaa = env[0]
    user_tok = login(uaa).json()["access_token"]
    r = exchange(uaa, user_tok)
    assert r.status_code == 200
    c = jwt.decode(r.json()["access_token"], (env[2] / "public.pem").read_text(), algorithms=["RS256"],
                   audience="rag-service")
    assert c["sub"] == "alice" and c["act"] == {"sub": "gateway"} and c["groups"] == ["finance"]


def test_exchange_refused_for_wrong_client_or_audience(env):
    uaa = env[0]
    user_tok = login(uaa).json()["access_token"]
    assert exchange(uaa, user_tok, cid="rag-service", secret="rag").status_code == 403
    assert exchange(uaa, user_tok, secret="wrong").status_code == 401
    assert exchange(uaa, user_tok, aud="uaa-service").status_code == 403
    assert exchange(uaa, "garbage").status_code == 401


def test_service_token_audience_restricted(env):
    uaa = env[0]
    ok = uaa.post("/auth/token", json={"client_id": "rag-service", "client_secret": "rag", "audience": "audit-service"})
    assert ok.status_code == 200
    bad = uaa.post("/auth/token", json={"client_id": "rag-service", "client_secret": "rag", "audience": "ingestion-service"})
    assert bad.status_code == 403


def test_audit_write_needs_service_token(env):
    uaa, audit = env[0], env[1]
    svc = uaa.post("/auth/token", json={"client_id": "rag-service", "client_secret": "rag",
                                        "audience": "audit-service"}).json()["access_token"]
    ev = {"event": "query.ok", "user": "alice", "detail": {"sources": 2}}
    assert audit.post("/events", json=ev).status_code == 401
    assert audit.post("/events", json=ev, headers={"Authorization": f"Bearer {svc}"}).status_code == 202
    intruder = uaa.post("/auth/token", json={"client_id": "intruder", "client_secret": "x",
                                             "audience": "audit-service"}).json()["access_token"]
    assert audit.post("/events", json=ev, headers={"Authorization": f"Bearer {intruder}"}).status_code == 403


def test_audit_read_needs_admin_exchange(env):
    uaa, audit = env[0], env[1]
    alice = exchange(uaa, login(uaa).json()["access_token"], aud="audit-service").json()["access_token"]
    assert audit.get("/events", headers={"Authorization": f"Bearer {alice}"}).status_code == 403
    root = exchange(uaa, login(uaa, "root", "pw-root").json()["access_token"], aud="audit-service").json()["access_token"]
    assert audit.get("/events", headers={"Authorization": f"Bearer {root}"}).status_code == 200


def test_token_for_other_audience_or_forged_is_rejected(env):
    uaa, audit, d, key = env
    rag_tok = exchange(uaa, login(uaa).json()["access_token"]).json()["access_token"]
    assert audit.get("/events", headers={"Authorization": f"Bearer {rag_tok}"}).status_code == 401
    now = int(time.time())
    forged = jwt.encode({"iss": "uaa-service", "iat": now, "exp": now + 60, "sub": "root", "aud": "audit-service",
                         "typ": "exchange", "act": {"sub": "gateway"}, "roles": ["ADMIN"]},
                        rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256")
    assert audit.get("/events", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    hs = jwt.encode({"iss": "uaa-service", "iat": now, "exp": now + 60, "sub": "root", "aud": "audit-service"},
                    "x" * 40, algorithm="HS256")
    assert audit.get("/events", headers={"Authorization": f"Bearer {hs}"}).status_code == 401
