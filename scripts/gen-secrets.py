#!/usr/bin/env python3
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

ITER = 600_000


def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], check=True, capture_output=True, text=True).stdout


def pbkdf2(pw: str) -> str:
    salt = os.urandom(16)
    return f"pbkdf2_sha256${ITER}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITER).hex()}"


def secret(name, **data):
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": "rag"},
            "type": "Opaque", "stringData": data}


with tempfile.TemporaryDirectory() as d:
    key = os.path.join(d, "k.pem")
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", key)
    private = open(key).read()
    public = openssl("pkey", "-in", key, "-pubout")

users = {"alice": (["INGEST", "QUERY"], ["finance"]),
         "bob": (["QUERY"], ["rh"]),
         "admin": (["ADMIN"], [])}
passwords = {u: secrets.token_urlsafe(16) for u in users}
users_json = {u: {"password": pbkdf2(passwords[u]), "roles": r, "groups": g} for u, (r, g) in users.items()}

client_secrets = {c: secrets.token_urlsafe(32) for c in ("gateway", "ingestion-service", "rag-service")}
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
clients_json = {
    "gateway": {"secret_sha256": sha(client_secrets["gateway"]), "audiences": [],
                "exchange": ["ingestion-service", "rag-service", "audit-service"]},
    "ingestion-service": {"secret_sha256": sha(client_secrets["ingestion-service"]), "audiences": ["audit-service"], "exchange": []},
    "rag-service": {"secret_sha256": sha(client_secrets["rag-service"]), "audiences": ["audit-service"], "exchange": []},
}

items = [
    secret("uaa-jwt-key", **{"private.pem": private}),
    {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "jwt-public", "namespace": "rag"},
     "data": {"public.pem": public}},
    secret("uaa-config", **{"users.json": json.dumps(users_json), "clients.json": json.dumps(clients_json)}),
] + [secret(f"{c}-client", secret=s) for c, s in client_secrets.items()]

with open(".demo-credentials", "w") as f:
    for u, p in passwords.items():
        f.write(f"{u}: {p}\n")
print("Mots de passe de demo ecrits dans .demo-credentials", file=sys.stderr)
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
