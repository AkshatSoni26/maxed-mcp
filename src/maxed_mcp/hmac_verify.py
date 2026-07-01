"""Constant-time webhook HMAC verification for the MCP server.

This mirrors the schemes implemented by the sibling ``webhook-hmac-verifier``
Go library so an agent can decide whether an inbound webhook is authentic
before acting on it:

* ``stripe``  -- the ``t=<unix>,v1=<hex>[,v1=<hex>...]`` header; the signed
  payload is ``"<timestamp>.<body>"`` and the timestamp must be within a
  tolerance of now (any ``v1`` candidate may match, which supports secret
  rotation);
* ``hex``     -- a bare hex-encoded SHA-256 HMAC of the raw body (for example
  QuickBooks Online), with an optional prefix stripped first;
* ``base64``  -- a base64-encoded SHA-256 HMAC of the raw body (for example
  Bill.com receivers), accepting standard and URL-safe, padded or unpadded.

Comparison is constant-time (``hmac.compare_digest``). ``webhook-hmac-verifier``
is the canonical implementation; this is the pure-Python equivalent the server
uses. Standard library only, no third-party dependencies.
"""

from __future__ import annotations

import base64 as _b64
import binascii
import hashlib
import hmac
import time
from typing import Dict, Optional

DEFAULT_TOLERANCE_SECONDS = 300  # 5 minutes, matching the Go default.

# Stable failure reasons, mirroring webhook-hmac-verifier's sentinel errors.
REASON_OK = "ok"
REASON_EMPTY_SECRET = "empty_secret"
REASON_NO_SIGNATURE = "missing_signature"
REASON_MALFORMED = "malformed_signature"
REASON_MISMATCH = "signature_mismatch"
REASON_TIMESTAMP = "timestamp_outside_tolerance"
REASON_UNKNOWN_SCHEME = "unknown_scheme"

_SCHEMES = ("stripe", "hex", "base64")


def _result(valid: bool, reason: str, **extra) -> Dict[str, object]:
    out: Dict[str, object] = {"ok": True, "valid": valid, "reason": reason}
    out.update(extra)
    return out


def _compute(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()


def _decode_base64(sig: str) -> Optional[bytes]:
    for decoder in (
        lambda s: _b64.b64decode(s, validate=True),
        lambda s: _b64.b64decode(s + "=" * (-len(s) % 4), validate=True),
        lambda s: _b64.urlsafe_b64decode(s),
        lambda s: _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
    ):
        try:
            raw = decoder(sig)
            if raw:
                return raw
        except (binascii.Error, ValueError):
            continue
    return None


def verify(
    scheme: str,
    secret: str,
    body: str,
    signature: str,
    *,
    prefix: str = "",
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    timestamp: Optional[int] = None,
) -> Dict[str, object]:
    """Verify a webhook signature. Returns a verdict dict, never raises.

    ``timestamp`` pins "now" (unix seconds) for the stripe scheme; leave it
    unset to use the wall clock. The verdict's ``valid`` flag is the answer;
    ``reason`` names the failure mode when ``valid`` is false.
    """
    scheme = (scheme or "").lower()
    if scheme not in _SCHEMES:
        return {
            "ok": False,
            "valid": False,
            "reason": REASON_UNKNOWN_SCHEME,
            "error": {
                "code": REASON_UNKNOWN_SCHEME,
                "message": f"unknown scheme {scheme!r}; choose from {list(_SCHEMES)}",
            },
        }

    secret_b = secret.encode("utf-8") if secret is not None else b""
    body_b = body.encode("utf-8") if body is not None else b""

    if not secret_b:
        return _result(False, REASON_EMPTY_SECRET, scheme=scheme)
    sig = (signature or "").strip()
    if not sig:
        return _result(False, REASON_NO_SIGNATURE, scheme=scheme)

    if scheme == "stripe":
        return _verify_stripe(secret_b, body_b, sig, tolerance_seconds, timestamp)
    return _verify_single(scheme, secret_b, body_b, sig, prefix)


def _verify_stripe(
    secret: bytes,
    body: bytes,
    header: str,
    tolerance_seconds: int,
    timestamp: Optional[int],
) -> Dict[str, object]:
    if tolerance_seconds <= 0:
        tolerance_seconds = DEFAULT_TOLERANCE_SECONDS
    ts_str = ""
    candidates = []
    for part in header.split(","):
        kv = part.strip().split("=", 1)
        if len(kv) != 2:
            continue
        key, value = kv[0], kv[1]
        if key == "t":
            ts_str = value
        elif key == "v1":
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                continue
            if raw:
                candidates.append(raw)
    if not ts_str or not candidates:
        return _result(False, REASON_MALFORMED, scheme="stripe")
    try:
        ts_unix = int(ts_str)
    except ValueError:
        return _result(False, REASON_MALFORMED, scheme="stripe")

    now = int(timestamp) if timestamp is not None else int(time.time())
    age = abs(now - ts_unix)
    if age > tolerance_seconds:
        return _result(
            False,
            REASON_TIMESTAMP,
            scheme="stripe",
            age_seconds=age,
            tolerance_seconds=tolerance_seconds,
        )

    signed = f"{ts_str}.".encode("utf-8") + body
    expected = _compute(secret, signed)
    for cand in candidates:
        if hmac.compare_digest(expected, cand):
            return _result(True, REASON_OK, scheme="stripe", age_seconds=age)
    return _result(False, REASON_MISMATCH, scheme="stripe")


def _verify_single(
    scheme: str, secret: bytes, body: bytes, signature: str, prefix: str
) -> Dict[str, object]:
    sig = signature
    if prefix:
        if not sig.startswith(prefix):
            return _result(False, REASON_MALFORMED, scheme=scheme)
        sig = sig[len(prefix):]
    if scheme == "hex":
        try:
            provided = bytes.fromhex(sig)
        except ValueError:
            provided = None
    else:  # base64
        provided = _decode_base64(sig)
    if not provided:
        return _result(False, REASON_MALFORMED, scheme=scheme)
    expected = _compute(secret, body)
    if hmac.compare_digest(expected, provided):
        return _result(True, REASON_OK, scheme=scheme)
    return _result(False, REASON_MISMATCH, scheme=scheme)


def sign(scheme: str, secret: str, body: str, timestamp: Optional[int] = None) -> str:
    """Produce a valid signature for a body (handy for tests and examples).

    Not part of verification; provided so callers can generate a known-good
    signature to exercise :func:`verify`.
    """
    scheme = (scheme or "").lower()
    secret_b = secret.encode("utf-8")
    body_b = body.encode("utf-8")
    if scheme == "stripe":
        ts = int(timestamp) if timestamp is not None else int(time.time())
        mac = _compute(secret_b, f"{ts}.".encode("utf-8") + body_b).hex()
        return f"t={ts},v1={mac}"
    if scheme == "hex":
        return _compute(secret_b, body_b).hex()
    if scheme == "base64":
        return _b64.b64encode(_compute(secret_b, body_b)).decode("ascii")
    raise ValueError(f"unknown scheme {scheme!r}")
