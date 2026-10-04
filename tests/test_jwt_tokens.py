"""
Access tokens (PyJWT, HS256): a token is accepted only when it carries this
server's signature and has not expired. Unsigned ("alg": "none"), tampered,
foreign-key and expired tokens are all refused with 401.
"""
import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.security import create_access_token


def _check(token: str) -> HTTPException:
    with pytest.raises(HTTPException) as exc:
        get_current_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), None)
    return exc.value


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_token_round_trip_and_expiry_claim():
    token = create_access_token({"sub": "alice", "pwv": "x"})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == "alice" and payload["exp"] > datetime.now(timezone.utc).timestamp()


def test_unsigned_token_is_refused():
    token = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "admin"}) + "."
    assert _check(token).status_code == 401


def test_tampered_token_is_refused():
    token = create_access_token({"sub": "alice", "pwv": "x"})
    head, _, sig = token.split(".")
    forged = head + "." + _b64({"sub": "admin", "pwv": "x", "exp": 9999999999}) + "." + sig
    assert _check(forged).status_code == 401


def test_token_signed_with_another_key_is_refused():
    token = jwt.encode({"sub": "admin"}, "another-servers-key-another-servers-key", algorithm="HS256")
    assert _check(token).status_code == 401


def test_expired_token_is_refused_with_its_own_message():
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    token = jwt.encode({"sub": "alice", "exp": past}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    err = _check(token)
    assert err.status_code == 401 and "expired" in err.detail
