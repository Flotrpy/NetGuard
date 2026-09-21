"""HTTP middleware: request ids, access logging, secure headers and rate limiting."""

from __future__ import annotations

import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from netguard.config import get_settings
from netguard.core.ratelimit import RateLimiter
from netguard.logging import get_logger

log = get_logger("http")


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id and emit one structured access-log line per request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id", "")[:64] or uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "unhandled error",
                extra={"request_id": request_id, "path": request.url.path},
            )
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        response.headers["X-Request-ID"] = request_id
        log.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,  # never log query strings or bodies
                "status": response.status_code,
                "ms": round((time.perf_counter() - start) * 1000, 1),
            },
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        h.setdefault("Cross-Origin-Resource-Policy", "same-site")
        # API responses are JSON/files, never documents that should render scripts. The docs UI
        # (/api/docs) needs more, so the strict policy is applied to everything else.
        if not request.url.path.startswith("/api/docs") and request.url.path != "/api/openapi.json":
            h.setdefault(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
        if request.url.path.startswith("/api"):
            h.setdefault("Cache-Control", "no-store")
        if get_settings().cookie_secure:
            h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global per-client budget, with a much tighter budget on credential endpoints."""

    AUTH_PATHS = ("/api/auth/login", "/api/auth/register")

    def __init__(self, app) -> None:  # noqa: ANN001
        super().__init__(app)
        s = get_settings()
        self.general = RateLimiter(s.rate_limit_per_minute)
        self.auth = RateLimiter(s.auth_rate_limit_per_minute)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        ip = client_ip(request)
        path = request.url.path
        if request.method == "POST" and path in self.AUTH_PATHS:
            allowed, retry = self.auth.check(f"{ip}:{path}")
        else:
            allowed, retry = self.general.check(ip)
        if not allowed:
            log.warning("rate limited", extra={"ip": ip, "path": path})
            return JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": str(retry)},
            )
        return await call_next(request)
