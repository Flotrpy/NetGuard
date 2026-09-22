"""Local HTTP servers used to test the API scanner: one deliberately weak, one well configured."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1"},
    "servers": [{"url": "http://api.example.com"}],
    "components": {"securitySchemes": {
        "bearer": {"type": "http", "scheme": "bearer"},
        "basic": {"type": "http", "scheme": "basic"},
        "key": {"type": "apiKey", "in": "query", "name": "api_key"},
    }},
    "paths": {
        "/users/me": {"get": {"security": [{"bearer": []}], "summary": "current user"}},
        "/public/info": {"get": {"security": [], "summary": "public info"}},
        "/search": {"get": {"security": [{"bearer": []}], "parameters": [
            {"name": "q", "in": "query", "schema": {"type": "integer"}},
            {"name": "api_key", "in": "query", "schema": {"type": "string"}}]}},
        "/items": {"post": {"summary": "create item", "requestBody": {}}},
        "/items/{id}": {"delete": {"summary": "delete item", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}]}},
    },
}


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    log_calls: list[tuple[str, str]] = []

    def log_message(self, *a):  # silence
        pass

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, headers=None):
        h = {"Content-Type": "application/json", **(headers or {})}
        self._send(status, json.dumps(obj).encode(), h)

    def _record(self):
        type(self).log_calls.append((self.command, self.path.split("?")[0]))

    def do_POST(self):
        self._record()
        self._send(200)

    do_PUT = do_PATCH = do_DELETE = do_POST


class WeakHandler(_Base):
    log_calls: list = []

    def do_GET(self):
        self._record()
        path = self.path.split("?")[0]
        base = {"Server": "Werkzeug/2.0.1 Python/3.9.7", "X-Powered-By": "Express 4.17.1"}
        origin = self.headers.get("Origin")
        if origin:
            base.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
        if path == "/openapi.json":
            return self._json(200, SPEC, base)
        if path == "/users/me":
            return self._json(200, {"user": "admin"}, base)  # BUG: auth not enforced
        if path == "/public/info":
            return self._json(200, {"v": 1}, base)
        if path == "/search":
            if "'" in self.path or "%27" in self.path:
                return self._send(500, b"Traceback (most recent call last):\n  File app.py, line 3", base)
            return self._json(200, {"results": []}, base)
        if path == "/":
            return self._json(200, {"ok": True}, {**base, "Set-Cookie": "sid=abc123; Path=/"})
        return self._send(404, b"Traceback (most recent call last):\n  KeyError", base)

    def do_OPTIONS(self):
        self._record()
        self._send(204, b"", {"Allow": "GET, POST, OPTIONS, TRACE"})


class GoodHandler(_Base):
    log_calls: list = []
    hits = 0

    def do_GET(self):
        self._record()
        type(self).hits += 1
        path = self.path.split("?")[0]
        sec = {"X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000"}
        if type(self).hits > 8:
            return self._json(429, {"error": "slow down"}, {**sec, "Retry-After": "5", "X-RateLimit-Limit": "8"})
        if path == "/openapi.json":
            return self._json(200, {**SPEC, "servers": [{"url": "https://api.example.com"}],
                                    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                                    "paths": {k: v for k, v in SPEC["paths"].items() if k in ("/users/me", "/search")}}, sec)
        if path in ("/users/me", "/search"):
            if self.headers.get("Authorization") != "Bearer good-token":
                return self._json(401, {"error": "unauthorized"}, sec)
            if path == "/search" and "?" in self.path and not self.path.split("=")[-1].lstrip("-").isdigit():
                return self._json(400, {"error": "invalid q"}, sec)
            return self._json(200, {"ok": True}, sec)
        if path == "/":
            return self._json(200, {"ok": True}, sec)
        return self._json(404, {"error": "not found"}, sec)

    def do_OPTIONS(self):
        self._record()
        self._send(204, b"", {"Allow": "GET, OPTIONS"})


class Api:
    def __init__(self, handler, cert: tuple[str, str] | None = None):
        handler.log_calls = []
        self.handler = handler
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if cert else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    @property
    def methods(self) -> set[str]:
        return {m for m, _ in self.handler.log_calls}

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
