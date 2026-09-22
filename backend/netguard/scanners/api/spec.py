"""OpenAPI / Swagger parsing for API security testing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
SENSITIVE_PARAMS = ("password", "passwd", "secret", "token", "apikey", "api_key", "access_token",
                    "auth", "session", "key")


class SpecError(ValueError):
    pass


@dataclass
class Param:
    name: str
    location: str  # query | path | header | cookie
    type: str = "string"
    required: bool = False


@dataclass
class Operation:
    method: str
    path: str
    summary: str = ""
    params: list[Param] = field(default_factory=list)
    security: list[dict[str, list[str]]] | None = None  # None = not declared anywhere
    has_request_body: bool = False

    @property
    def requires_auth(self) -> bool:
        return bool(self.security)


@dataclass
class ApiSpec:
    version: str = ""
    title: str = ""
    servers: list[str] = field(default_factory=list)
    security_schemes: dict[str, dict[str, Any]] = field(default_factory=dict)
    global_security: list[dict[str, list[str]]] | None = None
    operations: list[Operation] = field(default_factory=list)


def parse_spec(text: str) -> ApiSpec:
    if len(text) > 5_000_000:
        raise SpecError("Specification is too large")
    try:
        doc = json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise SpecError("Could not parse the specification (invalid JSON/YAML)") from exc
    if (
        not isinstance(doc, dict)
        or not ("openapi" in doc or "swagger" in doc)
        or not isinstance(doc.get("paths"), dict)
    ):
        raise SpecError("Not an OpenAPI/Swagger document")
    spec = ApiSpec(version=str(doc.get("openapi") or doc.get("swagger")),
                   title=str((doc.get("info") or {}).get("title", "")))
    if "servers" in doc:
        spec.servers = [str(s.get("url", "")) for s in doc.get("servers") or [] if isinstance(s, dict)]
    elif doc.get("host"):
        spec.servers = [f"{s}://{doc['host']}{doc.get('basePath', '')}" for s in doc.get("schemes", ["https"])]
    spec.security_schemes = dict(
        (doc.get("components") or {}).get("securitySchemes") or doc.get("securityDefinitions") or {})
    spec.global_security = doc.get("security")
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict) or not str(path).startswith("/"):
            continue
        shared = [_param(p, doc) for p in item.get("parameters") or []]
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = [*shared, *[_param(p, doc) for p in op.get("parameters") or []]]
            sec = op["security"] if "security" in op else spec.global_security
            spec.operations.append(Operation(
                method=method.upper(), path=str(path), summary=str(op.get("summary", ""))[:120],
                params=[p for p in params if p is not None],
                security=[s for s in (sec or []) if s] if sec is not None else None,
                has_request_body="requestBody" in op or any(
                    isinstance(p, dict) and p.get("in") == "body" for p in op.get("parameters") or []),
            ))
    return spec


def _param(p: Any, doc: dict[str, Any]) -> Param | None:
    if isinstance(p, dict) and "$ref" in p:  # resolve simple local refs
        node: Any = doc
        for part in str(p["$ref"]).lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        p = node
    if not isinstance(p, dict) or "name" not in p or "in" not in p:
        return None
    schema = p.get("schema") if isinstance(p.get("schema"), dict) else p
    return Param(str(p["name"]), str(p["in"]), str(schema.get("type", "string")),
                 bool(p.get("required")))


def fill_path(path: str, params: list[Param]) -> str:
    """Replace {placeholders} with harmless sample values."""
    out = path
    for p in params:
        if p.location == "path":
            out = out.replace("{" + p.name + "}", "1" if p.type in ("integer", "number") else "test")
    import re

    return re.sub(r"\{[^}]+\}", "1", out)
