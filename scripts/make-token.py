#!/usr/bin/env python3
"""Genere un JWT HS256 de test.
Usage: JWT_SECRET=... python scripts/make-token.py [roles] [groups]
Ex:    python scripts/make-token.py INGEST,QUERY finance,rh
"""
import base64, hashlib, hmac, json, os, sys, time


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


secret = os.environ["JWT_SECRET"].encode()
roles = (sys.argv[1] if len(sys.argv) > 1 else "QUERY").split(",")
groups = (sys.argv[2] if len(sys.argv) > 2 else "finance").split(",")
now = int(time.time())
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b64(json.dumps({"sub": "alice", "roles": roles, "groups": groups, "iat": now, "exp": now + 3600}).encode())
sig = b64(hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest())
print(f"{head}.{body}.{sig}")
