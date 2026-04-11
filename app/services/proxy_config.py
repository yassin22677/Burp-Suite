"""Centralized outbound proxy configuration (Burp interception)."""

from __future__ import annotations

import os

BURP_PROXY_URL = os.environ.get("BURP_PROXY_URL", "http://127.0.0.1:8080").strip()
REQUEST_PROXIES = {"http": BURP_PROXY_URL, "https": BURP_PROXY_URL}
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("HTTP_REQUEST_TIMEOUT", "30"))
