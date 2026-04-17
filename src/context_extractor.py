"""
Request context extraction for context-aware payload generation and evaluation.

This module defines a **single, tool-agnostic contract** (:class:`RequestContext`)
between exporter fixtures, the generative pipeline, the contextual bandit
(:mod:`adaptive_controller`), validators, and evaluation logs. Downstream code
reasons about parameters, encodings, and insertion points without importing
Burp APIs.

**Design rationale (thesis):** Exporters vary in field naming and nesting; the
extractor maps those variants onto one stable structure so experiments remain
**comparable across arms A–D**. Identifiers and tag ordering are **deterministic**
where possible (sorted parameters, sorted ``extension_blobs`` keys, derived
``request_id`` from a canonical hash when absent) so repeated runs and
ablation studies do not depend on arbitrary ordering.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlparse, urlunparse


class ParameterLocation(str, Enum):
    """
    Coarse placement of an injectable field (query, body, JSON, etc.).

    Used by context-aware scoring and soft validation hints; it is not a full
    protocol model of HTTP.
    """

    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_RAW = "body_raw"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"
    UNKNOWN = "unknown"


# Normalized token -> enum (lowercase keys). Covers common lab / tool spellings.
_LOCATION_SYNONYMS: dict[str, ParameterLocation] = {
    "query": ParameterLocation.QUERY,
    "querystring": ParameterLocation.QUERY,
    "query_string": ParameterLocation.QUERY,
    "q": ParameterLocation.QUERY,
    "url": ParameterLocation.QUERY,
    "uri": ParameterLocation.QUERY,
    "body": ParameterLocation.BODY_FORM,
    "body_form": ParameterLocation.BODY_FORM,
    "form": ParameterLocation.BODY_FORM,
    "post": ParameterLocation.BODY_FORM,
    "wwwform": ParameterLocation.BODY_FORM,
    # Normalized from "x-www-form-urlencoded" (hyphens → underscores)
    "x_www_form_urlencoded": ParameterLocation.BODY_FORM,
    "body_raw": ParameterLocation.BODY_RAW,
    "raw": ParameterLocation.BODY_RAW,
    "rawbody": ParameterLocation.BODY_RAW,
    "header": ParameterLocation.HEADER,
    "headers": ParameterLocation.HEADER,
    "cookie": ParameterLocation.COOKIE,
    "cookies": ParameterLocation.COOKIE,
    "json": ParameterLocation.JSON,
    "json_body": ParameterLocation.JSON,
    "unknown": ParameterLocation.UNKNOWN,
    "": ParameterLocation.UNKNOWN,
}


def _map_parameter_location(token: str) -> ParameterLocation:
    """Map a location string from a fixture to :class:`ParameterLocation`; never raises."""
    key = (token or "").strip().lower().replace(" ", "_").replace("-", "_")
    if key in _LOCATION_SYNONYMS:
        return _LOCATION_SYNONYMS[key]
    try:
        return ParameterLocation(key)
    except ValueError:
        return ParameterLocation.UNKNOWN


def _first_present(d: Mapping[str, Any], *keys: str) -> Any:
    """Return the first key that exists in ``d`` (even if value is None)."""
    for k in keys:
        if k in d:
            return d[k]
    return None


def _str_or_none(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _stable_request_id(raw: Mapping[str, Any], url: str, method: str) -> str:
    """
    Deterministic id when exporters omit ``request_id``.

    Hash canonical JSON of a small subset so identical logical requests collide
    by design (useful for deduping fixtures), not random UUIDs.
    """
    basis = json.dumps(
        {"method": method, "url": url, "path": _str_or_none(_first_present(raw, "path", "uri_path"))},
        sort_keys=True,
        separators=(",", ":"),
    )
    h = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"derived_{h}"


def _coalesce_url(raw: Mapping[str, Any]) -> str:
    """
    Prefer explicit ``url`` / ``requestUrl``; else build from host/port/protocol/path
    when lab tools split the line (Burp-style-ish exports).
    """
    direct = _str_or_none(_first_present(raw, "url", "requestUrl", "request_url", "full_url"))
    if direct is not None:
        return direct

    path = _str_or_none(_first_present(raw, "path", "uri_path")) or "/"
    host = _str_or_none(_first_present(raw, "host", "hostname", "domain"))
    if not host:
        return path if path.startswith("/") else f"/{path}"

    proto = _str_or_none(_first_present(raw, "protocol", "scheme")) or "http"
    proto = proto.rstrip(":").lower()
    if proto not in ("http", "https"):
        proto = "http"

    port_val = _first_present(raw, "port")
    port: int | None = None
    if port_val is not None and str(port_val).strip() != "":
        try:
            port = int(port_val)
        except (TypeError, ValueError):
            port = None

    default_port = 443 if proto == "https" else 80
    if port is None or port == default_port:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    return urlunparse((proto, netloc, path if path.startswith("/") else f"/{path}", "", "", ""))


@dataclass(frozen=True)
class ParameterMeta:
    """
    Metadata for one request parameter or injectable field.

    Attributes:
        name: Parameter or field name when known (e.g. \"id\", \"q\").
        location: Where the value appears in the message.
        declared_type: Optional hint from message structure (e.g. \"int\", \"string\").
        encoding_notes: Optional labels such as url-encoded, base64, etc.
    """

    name: str
    location: ParameterLocation
    declared_type: str | None = None
    encoding_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequestContext:
    """
    Normalized request context for generation, validation, and evaluation.

    This is the main contract between the extractor and later modules
    (representation, generator, ranker, bandit). Keep it serializable
    (JSON-friendly) for offline experiment logs.

    Attributes:
        request_id: Stable identifier for pairing trials across experiment groups.
        method: HTTP method in upper case.
        url: Full URL or reconstructed absolute URL.
        path: Path component without query string.
        parameter_tags: Parameters and their metadata relevant to fuzzing.
        content_type: Raw Content-Type header value if present.
        raw_excerpt: Optional short excerpt for debugging (not for blind replay).
        extension_blobs: Optional vendor-specific fields (e.g. Burp insertionPointType).
    """

    request_id: str
    method: str
    url: str
    path: str
    parameter_tags: tuple[ParameterMeta, ...] = ()
    content_type: str | None = None
    raw_excerpt: str | None = None
    extension_blobs: Mapping[str, Any] = field(default_factory=dict)


class RequestContextExtractor:
    """
    Builds a :class:`RequestContext` from structured request data (offline / lab).

    **Input schema (conceptual)**

    All top-level keys are optional except that you should supply enough to identify
    the request (typically ``url`` or ``host``+``path``, and often ``method``). Missing
    pieces fall back to safe defaults (see :meth:`extract`).

    * **Identity / line**
        - ``request_id`` / ``requestId``: stable string; if absent, a **deterministic**
          ``derived_<sha256>`` id is computed from method, url, and optional path.
        - ``method`` / ``http_method`` / ``verb``: normalized to upper case; default
          ``UNKNOWN``.
        - ``url`` / ``requestUrl`` / ``request_url`` / ``full_url``: absolute URL.
          If absent, ``protocol``/``scheme``, ``host``/``hostname``, ``port``, and
          ``path``/``uri_path`` are combined (Burp-like split fields).
        - ``path`` / ``uri_path``: optional override of the URL path component.

    * **Metadata**
        - ``content_type`` / ``contentType`` / ``mimeType``
        - ``raw_excerpt`` / ``rawExcerpt``: short debug text only (not a full replay).
        - ``extension_blobs`` / ``extensionBlobs`` / ``burp_metadata``: nested mapping
          copied as plain ``dict`` with **keys sorted** for deterministic logs.

    * **parameters** / **params** / **parameter_tags**
        List of objects, each mapping (aliases in parentheses):
        - ``name`` (``param_name``, ``key``)
        - ``location`` (``loc``, ``where``) → :class:`ParameterLocation` via synonyms
        - ``declared_type`` (``declaredType``)
        - ``encoding_notes`` (``encodingNotes``): string or list of strings

    **Determinism:** ``parameter_tags`` are sorted by
    ``(name, location, declared_type, encoding_notes)``. ``extension_blobs`` key order
    is sorted lexicographically by string key.

    **JSON-friendly output:** :class:`RequestContext` uses tuples and plain dicts;
    serialize with ``dataclasses.asdict`` or a small encoder; keep ``extension_blobs``
    values JSON-serializable in your exporter.
    """

    def extract(self, raw_request: Mapping[str, Any]) -> RequestContext:
        """
        Parse ``raw_request`` into a :class:`RequestContext`.

        Never raises for missing keys: uses ``UNKNOWN`` / derived defaults instead.
        """
        url = _coalesce_url(raw_request)
        method_raw = _first_present(raw_request, "method", "http_method", "verb")
        method = (_str_or_none(method_raw) or "UNKNOWN").strip().upper()

        rid = _str_or_none(_first_present(raw_request, "request_id", "requestId"))
        request_id = rid if rid is not None else _stable_request_id(raw_request, url, method)

        path_override = _str_or_none(_first_present(raw_request, "path", "uri_path"))
        parsed = urlparse(url)
        if path_override is not None:
            path = path_override if path_override.startswith("/") else f"/{path_override}"
        else:
            if parsed.scheme and parsed.netloc:
                path = parsed.path if parsed.path else "/"
            else:
                # Relative URL string (e.g. "/app") — whole string is the path.
                path = url if url.startswith("/") else (parsed.path or "/")

        content_type = _str_or_none(
            _first_present(raw_request, "content_type", "contentType", "mimeType")
        )
        raw_excerpt = _str_or_none(
            _first_present(raw_request, "raw_excerpt", "rawExcerpt")
        )

        ext_raw = _first_present(raw_request, "extension_blobs", "extensionBlobs", "burp_metadata")
        if isinstance(ext_raw, Mapping):
            # Deterministic key order for stable JSON dumps and diffs.
            extension_blobs = {str(k): ext_raw[k] for k in sorted(ext_raw.keys(), key=str)}
        else:
            extension_blobs = {}

        params_in = _first_present(raw_request, "parameters", "params", "parameter_tags")
        if params_in is None:
            params_in = []
        tags: list[ParameterMeta] = []
        if isinstance(params_in, list):
            for p in params_in:
                if not isinstance(p, Mapping):
                    continue
                name = _str_or_none(_first_present(p, "name", "param_name", "key")) or "unknown"
                loc_tok = _first_present(p, "location", "loc", "where")
                loc = _map_parameter_location(str(loc_tok) if loc_tok is not None else "")

                dt_raw = _first_present(p, "declared_type", "declaredType")
                dt = _str_or_none(dt_raw)

                enc = _first_present(p, "encoding_notes", "encodingNotes")
                enc_t: tuple[str, ...] = ()
                if isinstance(enc, (list, tuple)):
                    enc_t = tuple(str(x) for x in enc)
                elif isinstance(enc, str) and enc.strip():
                    enc_t = (enc.strip(),)

                tags.append(
                    ParameterMeta(
                        name=name,
                        location=loc,
                        declared_type=dt,
                        encoding_notes=enc_t,
                    )
                )

        tags.sort(key=lambda t: (t.name, t.location.value, t.declared_type or "", t.encoding_notes))

        return RequestContext(
            request_id=request_id,
            method=method,
            url=url,
            path=path,
            parameter_tags=tuple(tags),
            content_type=content_type,
            raw_excerpt=raw_excerpt,
            extension_blobs=extension_blobs,
        )

    def extract_many(self, raw_requests: list[Mapping[str, Any]]) -> list[RequestContext]:
        """Convenience batch wrapper around :meth:`extract`."""
        return [self.extract(r) for r in raw_requests]


if __name__ == "__main__":
    # Minimal self-checks (run: python -m src.context_extractor)
    _ex = RequestContextExtractor()

    _full = _ex.extract(
        {
            "request_id": "r1",
            "method": "get",
            "url": "http://lab.local/app/search?q=1",
            "content_type": "application/x-www-form-urlencoded",
            "parameters": [
                {
                    "name": "q",
                    "location": "QueryString",
                    "declared_type": "string",
                    "encoding_notes": ["url-encoded"],
                }
            ],
            "extension_blobs": {"b": 2, "a": 1},
        }
    )
    assert _full.request_id == "r1"
    assert _full.method == "GET"
    assert _full.path == "/app/search"
    assert _full.parameter_tags[0].location == ParameterLocation.QUERY
    assert list(_full.extension_blobs.keys()) == ["a", "b"]

    _split = _ex.extract(
        {
            "method": "POST",
            "host": "lab.local",
            "port": 8080,
            "protocol": "http",
            "path": "/login",
            "parameters": [{"name": "user", "location": "body", "declaredType": "string"}],
        }
    )
    assert _split.url == "http://lab.local:8080/login"
    assert _split.request_id.startswith("derived_")

    _minimal = _ex.extract({})
    assert _minimal.method == "UNKNOWN"
    assert _minimal.path == "/"

    print("context_extractor self-tests: ok")


# -----------------------------------------------------------------------------
# Representation / generator / ranker / bandit live in other modules.
# -----------------------------------------------------------------------------
