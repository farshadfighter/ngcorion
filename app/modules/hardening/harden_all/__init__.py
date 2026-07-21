"""
Harden All — unified "fix every failed check in a session" flow.

Every device family already owns a proven hardening service. This package puts a
single contract in front of all of them so the UI talks to ONE endpoint pair with
ONE request/response shape, instead of branching on device family:

    GET  /api/hardening/harden-all/session/{session_id}/plan
    POST /api/hardening/harden-all/execute

The per-family services are not reimplemented here — they are adapted.
"""

from .router import router  # noqa: F401
