"""
Tests for SecurityHeadersMiddleware (ASVS V14.4 - HTTP Security Headers).

Requests are driven straight through the ASGI interface, the same minimal
driver used by test_cors_policy.py - starlette's TestClient needs httpx,
which is not a dependency of this project.
"""

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI

from app.middleware.security_headers import SecurityHeadersMiddleware  # noqa: E402


def asgi_request(app, method: str, path: str, scheme: str = "http"):
    """Send one request through an ASGI app; return (status, response headers)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": scheme,
        "server": ("testserver", 80),
        "client": ("1.2.3.4", 1234),
        "headers": [],
    }
    captured = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
            captured["headers"] = {
                k.decode().lower(): v.decode() for k, v in message["headers"]
            }

    asyncio.run(app(scope, receive, send))
    return captured["status"], captured["headers"]


def build_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/users")
    def users():
        return {"users": []}

    @app.post("/auth/login")
    def login():
        return {"access_token": "t"}

    @app.get("/assets/index-abc123.js")
    def bundle():
        return {"not": "really js, just a stand-in route"}

    return app


class TestStaticHeadersAlwaysPresent:
    def test_nosniff(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert headers.get("x-content-type-options") == "nosniff"

    def test_frame_options_deny(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy_denies_sensors(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        policy = headers.get("permissions-policy", "")
        for sensor in ("geolocation=()", "microphone=()", "camera=()"):
            assert sensor in policy


class TestContentSecurityPolicy:
    def test_frame_ancestors_none(self):
        """Belt-and-suspenders with X-Frame-Options against clickjacking."""
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert "frame-ancestors 'none'" in headers.get("content-security-policy", "")

    def test_script_src_has_no_unsafe_inline_or_eval(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        csp = headers.get("content-security-policy", "")
        script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src"))
        assert "unsafe-inline" not in script_src
        assert "unsafe-eval" not in script_src

    def test_base_uri_restricted(self):
        """base-uri does NOT fall back to default-src - an injected <base href>
        would otherwise rewrite every relative URL on the page unchecked."""
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert "base-uri 'self'" in headers.get("content-security-policy", "")

    def test_form_action_restricted(self):
        """form-action does NOT fall back to default-src - an injected <form>
        could otherwise submit credentials to an attacker's origin."""
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert "form-action 'self'" in headers.get("content-security-policy", "")

    def test_object_src_none(self):
        _, headers = asgi_request(build_app(), "GET", "/health")
        assert "object-src 'none'" in headers.get("content-security-policy", "")


class TestHSTS:
    def test_present_over_https(self):
        _, headers = asgi_request(build_app(), "GET", "/health", scheme="https")
        assert "max-age=" in headers.get("strict-transport-security", "")
        assert "includeSubDomains" in headers.get("strict-transport-security", "")

    def test_absent_over_plain_http(self):
        """HSTS over an unencrypted request would be misleading (the header
        itself was never delivered with integrity) and breaks local dev."""
        _, headers = asgi_request(build_app(), "GET", "/health", scheme="http")
        assert "strict-transport-security" not in headers


class TestAntiCaching:
    """ASVS V14.4.2: sensitive API/auth responses must not be cached."""

    def test_api_path_is_not_cached(self):
        _, headers = asgi_request(build_app(), "GET", "/api/users")
        assert headers.get("cache-control") == "no-store"
        assert headers.get("pragma") == "no-cache"

    def test_auth_path_is_not_cached(self):
        _, headers = asgi_request(build_app(), "POST", "/auth/login")
        assert headers.get("cache-control") == "no-store"

    def test_non_api_path_is_left_alone(self):
        """Static/SPA assets are hashed and meant to be cached for performance
        - this middleware must not force no-store on them."""
        _, headers = asgi_request(build_app(), "GET", "/assets/index-abc123.js")
        assert "cache-control" not in headers


class TestRealApplicationWiring:
    """Assert against app.main itself so the shipped configuration cannot
    drift from what these tests prove about the middleware."""

    def test_security_headers_middleware_is_installed(self):
        import app.main
        assert any(
            mw.cls is SecurityHeadersMiddleware for mw in app.main.app.user_middleware
        )

    def test_real_app_sets_csp_and_no_store_on_an_api_path(self):
        import app.main
        _, headers = asgi_request(app.main.app, "GET", "/api/does-not-exist")
        assert "content-security-policy" in headers
        assert headers.get("cache-control") == "no-store"
