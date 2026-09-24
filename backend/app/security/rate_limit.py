"""In-process sliding-window rate limiter (ASGI middleware).

Demo-scope note: state is per-process, in memory — fine for the single
uvicorn process this phase runs as (docs/architecture.md §2). A future
multi-worker/distributed deployment moves this to Redis, behind the same
`RateLimiter` interface, without changing call sites.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self._limit = limit_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        hits = self._hits[key]
        while hits and hits[0] < window_start:
            hits.popleft()
        if len(hits) >= self._limit:
            return False
        hits.append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self._limiter = limiter or RateLimiter(get_settings().rate_limit_per_minute)

    async def dispatch(self, request: Request, call_next):
        client_key = request.client.host if request.client else "unknown"
        if not self._limiter.allow(client_key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
            )
        return await call_next(request)
