"""Signed tokens and request signatures. HMAC-SHA256 everywhere, compared in constant time."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


class InvalidToken(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def args_hash(action: str, args: dict[str, Any]) -> str:
    """What an approval binds to: the action and its exact arguments."""
    return hashlib.sha256(canonical({"action": action, "args": args})).hexdigest()


def sign(key: bytes, purpose: str, payload: dict[str, Any], ttl_seconds: int) -> str:
    body = dict(payload, purpose=purpose, exp=int(time.time()) + ttl_seconds)
    raw = canonical(body)
    sig = hmac.new(key, raw, hashlib.sha256).digest()
    return f"{_b64(raw)}.{_b64(sig)}"


def verify(key: bytes, purpose: str, token: str) -> dict[str, Any]:
    try:
        raw_b64, sig_b64 = token.split(".")
        raw, sig = _unb64(raw_b64), _unb64(sig_b64)
    except ValueError:
        raise InvalidToken("malformed") from None
    if not hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).digest(), sig):
        raise InvalidToken("bad signature")
    body: dict[str, Any] = json.loads(raw)
    if body.get("purpose") != purpose:
        raise InvalidToken("wrong purpose")
    if int(body.get("exp", 0)) < time.time():
        raise InvalidToken("expired")
    return body


def slack_signature_ok(secret: str, timestamp: str, body: bytes, signature: str, tolerance: int = 300) -> bool:
    """Slack's v0 scheme: HMAC of `v0:{timestamp}:{body}`, refused when older than five minutes (replay)."""
    try:
        if abs(time.time() - int(timestamp)) > tolerance:
            return False
    except ValueError:
        return False
    expected = "v0=" + hmac.new(secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def webhook_signature(key: bytes, timestamp: int, body: bytes) -> str:
    return "t={},v1={}".format(timestamp, hmac.new(key, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest())


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
