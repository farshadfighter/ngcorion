"""
Security regression tests for checklist item 2.1: CORS wildcard + credentials.

The app used to run `allow_origins=["*"]` together with `allow_credentials=True`.
Starlette answers that combination by reflecting the caller's *own* Origin back
with `Access-Control-Allow-Credentials: true`, so any website a logged-in
operator visited could drive this API as that operator.

These tests pin the replacement down:

1. a trusted configured origin is allowed,
2. an untrusted origin is granted nothing,
3. a wildcard with credentials fails closed (refused at startup),
4. multiple configured origins all work,
5. an authenticated (bearer-token) request from an allowed origin still works,
6. preflight OPTIONS behaves correctly for allowed and untrusted origins,
7. missing/empty configuration never degrades into "*".

Requests are driven straight through the ASGI interface — starlette's TestClient
needs httpx, which is not a dependency of this project.
"""

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import (  # noqa: E402
    CORSConfigurationError,
    _normalize_cors_origin,
    resolve_cors_origins,
    settings,
)

# Kept in lockstep with app/main.py; asserted against the real app below so the
# two cannot drift apart silently.
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
ALLOWED_HEADERS = ["Authorization", "Content-Type", "Accept", "X-Requested-With"]
EXPOSED_HEADERS = ["Content-Disposition"]

TRUSTED = "https://ngcorion.example.com"
SECOND_TRUSTED = "http://localhost:5173"
UNTRUSTED = "https://evil.example.net"


# --------------------------------------------------------------------------- #
#  Minimal ASGI driver                                                         #
# --------------------------------------------------------------------------- #

def asgi_request(app, method: str, path: str, headers: dict):
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
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("1.2.3.4", 1234),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
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


def build_app(origins):
    """A FastAPI app wired exactly the way app/main.py wires CORS."""
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=ALLOWED_METHODS,
        allow_headers=ALLOWED_HEADERS,
        expose_headers=EXPOSED_HEADERS,
    )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/auth/login")
    def login():
        return {"access_token": "t"}

    return app


def acao(headers):
    return headers.get("access-control-allow-origin")


# --------------------------------------------------------------------------- #
#  1 / 4 — trusted origins are allowed                                         #
# --------------------------------------------------------------------------- #

class TestTrustedOriginAllowed:
    def test_configured_origin_gets_cors_permission(self):
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "GET", "/health", {"origin": TRUSTED})
        assert status == 200
        assert acao(headers) == TRUSTED
        assert headers.get("access-control-allow-credentials") == "true"

    def test_response_echoes_the_exact_origin_never_a_wildcard(self):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": TRUSTED})
        assert acao(headers) != "*"

    def test_vary_origin_is_set_so_caches_do_not_leak_across_origins(self):
        """Without Vary: Origin a shared cache could serve one origin's
        CORS-approved response to another origin."""
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": TRUSTED})
        assert "origin" in headers.get("vary", "").lower()

    def test_download_filename_header_is_exposed(self):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": TRUSTED})
        assert "Content-Disposition" in headers.get("access-control-expose-headers", "")

    @pytest.mark.parametrize("origin", [TRUSTED, SECOND_TRUSTED])
    def test_multiple_configured_origins_all_work(self, origin):
        app = build_app([TRUSTED, SECOND_TRUSTED])
        status, headers = asgi_request(app, "GET", "/health", {"origin": origin})
        assert status == 200
        assert acao(headers) == origin

    def test_multiple_origins_do_not_leak_into_each_other(self):
        app = build_app([TRUSTED, SECOND_TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": UNTRUSTED})
        assert acao(headers) is None


# --------------------------------------------------------------------------- #
#  2 — untrusted origins get nothing                                           #
# --------------------------------------------------------------------------- #

class TestUntrustedOriginRejected:
    def test_untrusted_origin_receives_no_allow_origin_header(self):
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "GET", "/health", {"origin": UNTRUSTED})
        # The request itself is not blocked server-side (CORS is enforced in the
        # browser); what matters is that we never grant it permission.
        assert acao(headers) is None

    @pytest.mark.parametrize("origin", [
        "https://ngcorion.example.com.evil.net",   # suffix trick
        "https://evil.net?ngcorion.example.com",   # query trick
        "http://ngcorion.example.com",             # wrong scheme
        "https://ngcorion.example.com:8443",       # wrong port
        "null",                                    # sandboxed iframe / file://
    ])
    def test_lookalike_origins_are_not_granted_permission(self, origin):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": origin})
        assert acao(headers) is None

    def test_untrusted_origin_never_receives_a_wildcard_either(self):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {"origin": UNTRUSTED})
        assert acao(headers) != "*"


# --------------------------------------------------------------------------- #
#  3 / 7 — unsafe or absent configuration fails closed                         #
# --------------------------------------------------------------------------- #

class TestConfigurationFailsClosed:
    @pytest.fixture(autouse=True)
    def _restore(self):
        original = settings.BACKEND_CORS_ORIGINS
        yield
        settings.BACKEND_CORS_ORIGINS = original

    def test_wildcard_with_credentials_is_refused_at_startup(self):
        """The exact vulnerable combination this item exists to remove."""
        settings.BACKEND_CORS_ORIGINS = ["*"]
        with pytest.raises(CORSConfigurationError) as exc:
            resolve_cors_origins()
        assert "*" in str(exc.value)

    def test_wildcard_mixed_with_real_origins_is_still_refused(self):
        settings.BACKEND_CORS_ORIGINS = [TRUSTED, "*"]
        with pytest.raises(CORSConfigurationError):
            resolve_cors_origins()

    def test_missing_configuration_does_not_become_wildcard(self):
        """An unset value must mean 'no cross-origin access', never 'any'."""
        settings.BACKEND_CORS_ORIGINS = []
        assert resolve_cors_origins() == []

    def test_empty_string_configuration_does_not_become_wildcard(self):
        settings.BACKEND_CORS_ORIGINS = ""
        assert resolve_cors_origins() == []

    def test_default_setting_is_not_a_wildcard(self):
        """Guards against someone restoring "*" as the shipped default."""
        from app.core.config import Settings
        default = Settings.model_fields["BACKEND_CORS_ORIGINS"].default
        assert default in ("", [], None), default
        assert "*" not in (default or "")

    def test_comma_separated_env_value_does_not_crash_settings(self):
        """
        pydantic-settings JSON-decodes a List[str] field before our parsing
        runs, so typing this field as a list would make the documented
        comma-separated form raise SettingsError and refuse to boot.
        """
        from app.core.config import Settings
        annotation = Settings.model_fields["BACKEND_CORS_ORIGINS"].annotation
        assert annotation is str, (
            "BACKEND_CORS_ORIGINS must stay a plain string so comma-separated "
            f"values parse in cors_origins, got {annotation!r}"
        )

    def test_empty_allowlist_grants_nothing_to_any_origin(self):
        app = build_app([])
        for origin in (TRUSTED, UNTRUSTED, "http://localhost:5173"):
            _, headers = asgi_request(app, "GET", "/health", {"origin": origin})
            assert acao(headers) is None, origin

    def test_empty_allowlist_still_serves_same_origin_requests(self):
        """The production path: the bundled frontend sends no Origin header at
        all, so locking CORS down must not affect it."""
        app = build_app([])
        status, headers = asgi_request(app, "GET", "/health", {})
        assert status == 200
        assert acao(headers) is None

    @pytest.mark.parametrize("bad", [
        "*",
        "null",
        "https://*.example.com",
        "example.com",                       # no scheme
        "ftp://example.com",                 # not an http(s) origin
        "https://example.com/admin",         # path
        "https://user:pw@example.com",       # credentials
    ])
    def test_invalid_origins_are_refused_not_ignored(self, bad):
        settings.BACKEND_CORS_ORIGINS = [bad]
        with pytest.raises(CORSConfigurationError):
            resolve_cors_origins()

    def test_blank_entries_are_dropped_not_treated_as_an_origin(self):
        """A trailing comma ("https://a.example.com,") is an ordinary typo, so
        blank segments are ignored — but they must never widen the allowlist."""
        settings.BACKEND_CORS_ORIGINS = f"{TRUSTED}, ,"
        assert resolve_cors_origins() == [TRUSTED]

    def test_a_blank_origin_reaching_the_validator_is_still_refused(self):
        """Defence in depth: the parser filters blanks, and the validator
        refuses one anyway if it is ever called directly."""
        with pytest.raises(CORSConfigurationError):
            _normalize_cors_origin("")


# --------------------------------------------------------------------------- #
#  Normalisation                                                               #
# --------------------------------------------------------------------------- #

class TestOriginNormalisation:
    @pytest.mark.parametrize("raw,expected", [
        ("https://App.Example.com", "https://app.example.com"),
        ("https://app.example.com/", "https://app.example.com"),
        ("HTTPS://APP.EXAMPLE.COM/", "https://app.example.com"),
        ("http://localhost:5173", "http://localhost:5173"),
        ("https://example.com:8443", "https://example.com:8443"),
    ])
    def test_normalised_to_the_form_browsers_send(self, raw, expected):
        assert _normalize_cors_origin(raw) == expected

    def test_normalised_value_actually_matches_a_real_request(self):
        """Starlette compares origins by exact string equality, so a value that
        normalises wrongly would be a silently dead allowlist entry."""
        app = build_app([_normalize_cors_origin("HTTPS://App.Example.com/")])
        _, headers = asgi_request(app, "GET", "/health",
                                  {"origin": "https://app.example.com"})
        assert acao(headers) == "https://app.example.com"

    def test_duplicates_are_collapsed(self):
        original = settings.BACKEND_CORS_ORIGINS
        try:
            settings.BACKEND_CORS_ORIGINS = [TRUSTED, TRUSTED + "/", TRUSTED.upper()]
            assert resolve_cors_origins() == [TRUSTED]
        finally:
            settings.BACKEND_CORS_ORIGINS = original

    @pytest.mark.parametrize("raw,expected", [
        ('["https://a.example.com","https://b.example.com"]',
         ["https://a.example.com", "https://b.example.com"]),
        ("https://a.example.com, https://b.example.com",
         ["https://a.example.com", "https://b.example.com"]),
        ("https://a.example.com", ["https://a.example.com"]),
    ])
    def test_accepts_json_list_comma_separated_and_bare_string(self, raw, expected):
        original = settings.BACKEND_CORS_ORIGINS
        try:
            settings.BACKEND_CORS_ORIGINS = raw
            assert resolve_cors_origins() == expected
        finally:
            settings.BACKEND_CORS_ORIGINS = original


# --------------------------------------------------------------------------- #
#  5 — authenticated cross-origin requests still work                          #
# --------------------------------------------------------------------------- #

class TestAuthenticatedRequestsStillWork:
    def test_bearer_token_request_from_allowed_origin_is_permitted(self):
        """The frontend authenticates with `Authorization: Bearer <jwt>` from
        localStorage; that must keep working from a configured origin."""
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "GET", "/health", {
            "origin": TRUSTED,
            "authorization": "Bearer test.jwt.token",
        })
        assert status == 200
        assert acao(headers) == TRUSTED

    def test_login_post_from_allowed_origin_is_permitted(self):
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "POST", "/auth/login", {
            "origin": TRUSTED,
            "content-type": "application/json",
        })
        assert status == 200
        assert acao(headers) == TRUSTED

    def test_authorization_header_is_allowed_by_preflight(self):
        """Without Authorization in allow_headers the browser would refuse to
        send the bearer token at all."""
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "OPTIONS", "/health", {
            "origin": TRUSTED,
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization",
        })
        assert status == 200
        allowed = headers.get("access-control-allow-headers", "").lower()
        assert "authorization" in allowed

    def test_bearer_token_from_untrusted_origin_is_not_granted(self):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "GET", "/health", {
            "origin": UNTRUSTED,
            "authorization": "Bearer stolen.jwt.token",
        })
        assert acao(headers) is None


# --------------------------------------------------------------------------- #
#  6 — preflight                                                               #
# --------------------------------------------------------------------------- #

class TestPreflight:
    def test_allowed_origin_preflight_succeeds(self):
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "OPTIONS", "/health", {
            "origin": TRUSTED,
            "access-control-request-method": "GET",
        })
        assert status == 200
        assert acao(headers) == TRUSTED

    def test_preflight_advertises_exactly_the_configured_methods(self):
        app = build_app([TRUSTED])
        _, headers = asgi_request(app, "OPTIONS", "/health", {
            "origin": TRUSTED,
            "access-control-request-method": "POST",
        })
        advertised = {m.strip() for m in
                      headers.get("access-control-allow-methods", "").split(",")}
        assert advertised == set(ALLOWED_METHODS)
        assert "*" not in advertised

    def test_untrusted_origin_preflight_is_refused(self):
        app = build_app([TRUSTED])
        status, headers = asgi_request(app, "OPTIONS", "/health", {
            "origin": UNTRUSTED,
            "access-control-request-method": "GET",
        })
        assert status == 400
        assert acao(headers) is None

    def test_preflight_with_empty_allowlist_is_refused(self):
        app = build_app([])
        status, headers = asgi_request(app, "OPTIONS", "/health", {
            "origin": TRUSTED,
            "access-control-request-method": "GET",
        })
        assert status == 400
        assert acao(headers) is None

    def test_preflight_for_a_disallowed_method_is_refused(self):
        app = build_app([TRUSTED])
        status, _ = asgi_request(app, "OPTIONS", "/health", {
            "origin": TRUSTED,
            "access-control-request-method": "TRACE",
        })
        assert status == 400


# --------------------------------------------------------------------------- #
#  The real application object                                                 #
# --------------------------------------------------------------------------- #

class TestRealApplicationWiring:
    """
    Assert against app.main itself, so the shipped configuration cannot drift
    from what these tests prove about the middleware.
    """

    @pytest.fixture(scope="class")
    def cors_options(self):
        import app.main  # noqa: F401
        from fastapi.middleware.cors import CORSMiddleware as CM
        for mw in app.main.app.user_middleware:
            if mw.cls is CM:
                return dict(mw.kwargs)
        pytest.fail("CORSMiddleware is not installed on the application")

    def test_wildcard_origin_is_not_configured(self, cors_options):
        assert "*" not in cors_options["allow_origins"]

    def test_credentials_are_never_paired_with_a_wildcard(self, cors_options):
        """The precise vulnerability from the audit."""
        if cors_options.get("allow_credentials"):
            assert "*" not in cors_options["allow_origins"]

    def test_methods_and_headers_are_narrowed(self, cors_options):
        assert cors_options["allow_methods"] == ALLOWED_METHODS
        assert cors_options["allow_headers"] == ALLOWED_HEADERS
        assert cors_options["expose_headers"] == EXPOSED_HEADERS
        assert "*" not in cors_options["allow_methods"]
        assert "*" not in cors_options["allow_headers"]
        assert "*" not in cors_options["expose_headers"]

    def test_configured_origins_come_from_the_validated_resolver(self, cors_options):
        assert cors_options["allow_origins"] == resolve_cors_origins()

    def test_real_app_grants_nothing_to_an_untrusted_origin(self):
        """End to end against the actual app, through every middleware it has."""
        import app.main
        _, headers = asgi_request(app.main.app, "GET", "/health",
                                  {"origin": UNTRUSTED})
        assert acao(headers) is None

    def test_real_app_serves_same_origin_requests_normally(self):
        import app.main
        status, _ = asgi_request(app.main.app, "GET", "/health", {})
        assert status == 200
