"""
Request body size limit.

Starlette reads a JSON or form body into memory whole before a route runs - before its sign-in check
too - so without a limit one request to /auth/login with a body of gigabytes fills the memory. A body
larger than the limit is refused with 413: at once when Content-Length says so, else as soon as the
bytes read pass it (a chunked body): the app is then told the client has gone, and what it answers
is dropped.

Multipart uploads (Excel import, report verification, certificates) get a larger limit; each route still
checks its own, smaller one. The uploads that stream their body and hold their own limit while reading
(a CVE package, an advisory archive, a system backup) are left to it.
"""
import json

JSON_LIMIT = 32 * 1024 * 1024
MULTIPART_LIMIT = 64 * 1024 * 1024
STREAMED = frozenset({
    "/api/cve/db/packages",
    "/api/cve/advisories/import",
    "/api/system-backup/upload",
})


class BodySizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    @staticmethod
    def limit_for(path: str, content_type: str):
        if path.rstrip("/") in STREAMED:
            return None
        return MULTIPART_LIMIT if content_type.startswith("multipart/") else JSON_LIMIT

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        limit = self.limit_for(scope.get("path", ""), headers.get("content-type", "").lower())
        if limit is None:
            return await self.app(scope, receive, send)
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return await self._refuse(send, limit)

        read = 0
        started = refused = False

        async def tracked_send(message):
            nonlocal started
            if refused:
                return                      # the 413 is sent; what the app answers after it is dropped
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        async def counted_receive():
            nonlocal read, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                read += len(message.get("body", b""))
                if read > limit and not started:
                    await self._refuse(send, limit)
                    refused = True
                    return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, counted_receive, tracked_send)
        except Exception:
            if not refused:
                raise

    @staticmethod
    async def _refuse(send, limit: int):
        body = json.dumps({"detail": f"Request body too large (max {limit // (1024 * 1024)} MB)"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
