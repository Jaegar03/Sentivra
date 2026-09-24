"""Request-body size limits enforced while the body is being received.

The upload endpoints used to call `await file.read()` and only then check
the size, by which point an oversized upload had already been parsed to disk
and loaded into memory. This ASGI middleware sits in front of the routes and
counts bytes as they arrive:

  * a declared Content-Length over the limit is refused with 413 before a
    single body byte is read;
  * a body with no Content-Length (chunked transfer) is cut off with 413 the
    moment it crosses the limit.

Upload routes get SENTIVRA_MAX_UPLOAD_BYTES (plus a little room for
multipart framing); every other route gets SENTIVRA_MAX_JSON_BYTES.
"""

from __future__ import annotations

import json

from app.core.config import get_settings

UPLOAD_PATHS = frozenset({
    "/api/v1/analyze/file",
    "/api/v1/network/analyze",
    "/api/v1/endpoint/osquery",
    "/api/v1/logs/analyze",
})
_MULTIPART_OVERHEAD = 64 * 1024


class BodySizeLimitMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    def _limit_for(self, path: str) -> int:
        s = get_settings()
        return s.max_upload_bytes + _MULTIPART_OVERHEAD if path in UPLOAD_PATHS else s.max_json_bytes

    @staticmethod
    async def _reject(send, limit: int) -> None:
        body = json.dumps({"detail": f"Request body exceeds the {limit}-byte limit"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self._limit_for(scope["path"])

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True  # unparseable length: refuse rather than guess
            if too_big:
                return await self._reject(send, limit)

        received = 0
        started = False
        exceeded = False

        # Raising from receive() doesn't work: FastAPI turns any error while
        # reading the body into a 400. Instead, answer 413 here, tell the app
        # the client went away, and drop whatever it tries to send after.
        async def limited_receive():
            nonlocal received, exceeded, started
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    if not started:
                        started = True
                        await self._reject(send, limit)
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message):
            nonlocal started
            if exceeded:
                return  # already answered with 413
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except Exception:
            if not exceeded:
                raise
