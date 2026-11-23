import os
from dataclasses import dataclass, field

import jwt
from fastapi import Header, HTTPException

ISSUER = "uaa-service"
_PUBLIC_KEY = None


def public_key() -> str:
    global _PUBLIC_KEY
    if _PUBLIC_KEY is None:
        with open(os.getenv("JWT_PUBLIC_KEY", "/jwt/public.pem")) as f:
            _PUBLIC_KEY = f.read()
    return _PUBLIC_KEY


@dataclass
class Principal:
    caller: str
    user: str | None = None
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)


def verify(token: str, audience: str) -> dict:
    try:
        return jwt.decode(token, public_key(), algorithms=["RS256"], audience=audience, issuer=ISSUER,
                          options={"require": ["exp", "iat", "sub", "aud", "iss"]}, leeway=5)
    except jwt.PyJWTError:
        raise HTTPException(401, "jeton invalide", headers={"WWW-Authenticate": "Bearer"})


def require(audience: str, callers: set[str], scope: str | None = None):
    def dep(authorization: str = Header("")) -> Principal:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "jeton manquant", headers={"WWW-Authenticate": "Bearer"})
        c = verify(authorization[7:].strip(), audience)
        if c.get("typ") == "exchange":
            caller, user = (c.get("act") or {}).get("sub"), c["sub"]
        elif c.get("typ") == "service":
            caller, user = c["sub"], None
        else:
            raise HTTPException(401, "type de jeton refuse")
        if caller not in callers:
            raise HTTPException(403, "appelant non autorise")
        scopes = (c.get("scope") or "").split()
        if scope and scope not in scopes:
            raise HTTPException(403, "scope manquant")
        return Principal(caller, user, c.get("roles", []), c.get("groups", []), scopes)
    return dep
