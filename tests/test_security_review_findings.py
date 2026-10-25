"""
Findings of the 2.1.2 security review (OWASP WSTG), each with the check that keeps it fixed.

- ATHZ-03: a non-administrator with user management could change the email of another account of
  the same role, then reset its password with the code emailed there - taking over permissions they
  do not hold. Since the code can also go by SMS (delivery policy), the mobile number likewise.
- ATHZ-02: asset dependencies, security status and the asset views needed only a sign-in, not the
  Asset List permission.
- BUSL-07 / denial of service: no limit on a request body; a JSON body is read whole into memory
  before any route runs, sign-in included.
- CLNT-01: a link in an imported end-of-life catalog was stored as given (javascript: included).
- A certificate upload was read whole, whatever its size.

No database needed: SQLite in memory for the user service.
"""
import asyncio
import json

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.core.database import Base
from app.core.security import get_password_hash
from app.middleware.body_limit import JSON_LIMIT, MULTIPART_LIMIT, BodySizeLimitMiddleware
from app.models import User, UserRole
from app.models.security_audit_log import AuditLog
from app.models.user_permission import ModuleEnum, UserPermission
from app.modules.eol import catalog as C
from app.modules.users.service import UserService
from app.schemas.user import UserUpdate


# ── ATHZ-03: email change of another account ─────────────────────────────

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [User.__table__, UserPermission.__table__, AuditLog.__table__]
    Base.metadata.create_all(bind=engine, tables=tables)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))


def _user(db, uid, name, role, perms):
    db.add(User(id=uid, username=name, email=f"{name}@example.com", hashed_password=get_password_hash("x-Passw0rd!"),
                role=role, is_active=True))
    for module, read, write in perms:
        db.add(UserPermission(user_id=uid, module=module, can_read=read, can_write=write, can_delete=False))
    db.commit()


def test_an_account_holding_more_cannot_have_its_email_changed(db):
    _user(db, 1, "helpdesk", UserRole.MANAGER, [(ModuleEnum.USER_MANAGEMENT, True, True)])
    _user(db, 2, "netops", UserRole.MANAGER, [(ModuleEnum.HARDENING, True, True)])
    _user(db, 3, "viewer", UserRole.USER, [])
    service = UserService(db)

    with pytest.raises(HTTPException) as exc:
        service.update_user(2, UserUpdate(email="attacker@example.com"), current_user_id=1)
    assert exc.value.status_code == 403 and "email" in exc.value.detail
    db.rollback()
    assert db.get(User, 2).email == "netops@example.com"

    # the rest of the account can still be edited, and an account holding nothing more takes a new email
    service.update_user(2, UserUpdate(language="fa"), current_user_id=1)
    assert service.update_user(3, UserUpdate(email="viewer2@example.com"), current_user_id=1).email == \
        "viewer2@example.com"
    # one's own email, as before
    assert service.update_user(1, UserUpdate(email="hd@example.com"), current_user_id=1).email == "hd@example.com"


def test_an_account_holding_more_cannot_have_its_mobile_number_changed(db):
    """The reset code can go by SMS (delivery policy), so the mobile number is guarded like the email."""
    _user(db, 1, "helpdesk", UserRole.MANAGER, [(ModuleEnum.USER_MANAGEMENT, True, True)])
    _user(db, 2, "netops", UserRole.MANAGER, [(ModuleEnum.HARDENING, True, True)])
    _user(db, 3, "viewer", UserRole.USER, [])
    service = UserService(db)

    with pytest.raises(HTTPException) as exc:
        service.update_user(2, UserUpdate(phone="09129999999"), current_user_id=1)
    assert exc.value.status_code == 403 and "mobile number" in exc.value.detail
    db.rollback()
    assert db.get(User, 2).phone is None
    with pytest.raises(HTTPException):
        service.update_user(2, UserUpdate(phone="09129999999", email="netops@example.com"), current_user_id=1)
    db.rollback()

    # the same number again is no change; an account holding nothing more, and one's own, as before
    service.update_user(2, UserUpdate(phone=""), current_user_id=1)
    assert service.update_user(3, UserUpdate(phone="09121111111"), current_user_id=1).phone == "09121111111"
    assert service.update_user(1, UserUpdate(phone="09122222222"), current_user_id=1).phone == "09122222222"


# ── ATHZ-02: asset data needs the Asset List permission ───────────────────

def test_asset_data_routes_need_the_asset_list_permission():
    from types import SimpleNamespace

    from app.modules.assets.router_with_auth import dependencies_router, security_router, views_router

    class NoRows:                                   # a database where the user holds no permission
        def query(self, *a):
            return self

        def filter(self, *a):
            return self

        def first(self):
            return None

    user = SimpleNamespace(id=7, role=UserRole.USER)

    def refusal(route: APIRoute):
        """What the route's permission check answers a user without permissions."""
        for d in route.dependant.dependencies:
            if getattr(d.call, "__qualname__", "").startswith("require_permission"):
                with pytest.raises(HTTPException) as exc:
                    d.call(current_user=user, db=NoRows())
                return exc.value.status_code, exc.value.detail
        return None

    reads = [r for router in (dependencies_router, security_router, views_router) for r in router.routes
             if isinstance(r, APIRoute) and "GET" in r.methods]
    assert len(reads) == 6
    assert {r.path: refusal(r) for r in reads} == {r.path: (403, "No permission for ASSET_LIST") for r in reads}


# ── request body limit ────────────────────────────────────────────────────

async def _echo(request: Request):
    return JSONResponse({"read": len(await request.body())})

_app = BodySizeLimitMiddleware(Starlette(routes=[Route("/auth/login", _echo, methods=["POST"])]))


def _post(path, chunks, headers=None):
    """One POST through the ASGI interface (starlette's TestClient needs httpx, not a dependency here);
    returns (status, body as JSON)."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "", "scheme": "http",
             "server": ("testserver", 80), "client": ("1.2.3.4", 1234),
             "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()]}
    queue = list(chunks)
    out = {"body": b""}

    async def receive():
        body = queue.pop(0) if queue else b""
        return {"type": "http.request", "body": body, "more_body": bool(queue)}

    async def send(message):
        if message["type"] == "http.response.start":
            out["status"] = message["status"]
        elif message["type"] == "http.response.body":
            out["body"] += message.get("body", b"")

    asyncio.run(_app(scope, receive, send))
    return out["status"], json.loads(out["body"])


def test_a_body_over_the_limit_is_refused():
    assert _post("/auth/login", [b"{}"], {"content-length": "2"}) == (200, {"read": 2})
    # declared too large: refused before a byte is read
    status, body = _post("/auth/login", [b"x"], {"content-length": str(JSON_LIMIT + 1)})
    assert status == 413 and "too large" in body["detail"]
    # chunked, no length: refused once the bytes read pass the limit
    mb = b"x" * (1024 * 1024)
    assert _post("/auth/login", [mb] * (JSON_LIMIT // len(mb) + 2))[0] == 413
    # multipart has the larger limit; a streamed upload keeps its own
    assert BodySizeLimitMiddleware.limit_for("/api/assets/import/excel", "multipart/form-data; boundary=x") \
        == MULTIPART_LIMIT
    assert BodySizeLimitMiddleware.limit_for("/api/system-backup/upload", "application/octet-stream") is None


# ── imported end-of-life links ────────────────────────────────────────────

def test_an_imported_catalog_keeps_only_web_links():
    def product(key, link):
        return {"key": key, "name": key, "link": link, "cycles": [{"cycle": "1", "security_until": "2099-01-01"}]}
    raw = json.dumps({"products": [product("a", "javascript:alert(1)"), product("b", "https://example.com/b"),
                                   product("c", "https://example.com/" + "c" * 400), product("d", {"x": 1})]})
    links = {p["key"]: p["link"] for p in C.parse_file(raw.encode())}
    assert links == {"a": None, "b": "https://example.com/b", "c": None, "d": None}


# ── certificate upload ────────────────────────────────────────────────────

def test_a_certificate_file_over_1_mb_is_refused():
    from app.modules.system_config.router import CERT_FILE_MAX, _read_small

    class Upload:
        def __init__(self, size):
            self.data = b"x" * size

        async def read(self, n=-1):
            return self.data if n < 0 else self.data[:n]

    assert len(asyncio.run(_read_small(Upload(2048)))) == 2048
    with pytest.raises(HTTPException) as exc:
        asyncio.run(_read_small(Upload(CERT_FILE_MAX + 1)))
    assert exc.value.status_code == 413
