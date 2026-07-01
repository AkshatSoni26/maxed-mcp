"""Webhook HMAC verification mirrors webhook-hmac-verifier's schemes."""

from maxed_mcp import hmac_verify as hv


def test_stripe_roundtrip_valid():
    sig = hv.sign("stripe", "whsec", "body", timestamp=1000)
    r = hv.verify("stripe", "whsec", "body", sig, timestamp=1000)
    assert r["valid"] is True
    assert r["reason"] == "ok"


def test_stripe_tampered_body_mismatch():
    sig = hv.sign("stripe", "whsec", "body", timestamp=1000)
    r = hv.verify("stripe", "whsec", "TAMPERED", sig, timestamp=1000)
    assert r["valid"] is False
    assert r["reason"] == "signature_mismatch"


def test_stripe_stale_timestamp_rejected():
    sig = hv.sign("stripe", "whsec", "body", timestamp=1000)
    r = hv.verify("stripe", "whsec", "body", sig, timestamp=100000, tolerance_seconds=300)
    assert r["valid"] is False
    assert r["reason"] == "timestamp_outside_tolerance"


def test_stripe_multiple_v1_candidates_any_matches():
    good = hv.sign("stripe", "whsec", "body", timestamp=1000).split("v1=")[1]
    header = f"t=1000,v1=deadbeef,v1={good}"
    r = hv.verify("stripe", "whsec", "body", header, timestamp=1000)
    assert r["valid"] is True


def test_hex_scheme():
    sig = hv.sign("hex", "secret", "body123")
    assert hv.verify("hex", "secret", "body123", sig)["valid"] is True
    assert hv.verify("hex", "secret", "body123", "00" + sig[2:])["valid"] is False


def test_base64_scheme_and_prefix():
    sig = hv.sign("base64", "secret", "payload")
    assert hv.verify("base64", "secret", "payload", sig)["valid"] is True
    assert hv.verify("base64", "secret", "payload", "sha256=" + sig, prefix="sha256=")["valid"] is True
    assert hv.verify("base64", "secret", "payload", sig, prefix="sha256=")["reason"] == "malformed_signature"


def test_empty_secret_and_missing_signature():
    assert hv.verify("hex", "", "body", "abcd")["reason"] == "empty_secret"
    assert hv.verify("hex", "secret", "body", "")["reason"] == "missing_signature"


def test_unknown_scheme():
    r = hv.verify("nope", "secret", "body", "abcd")
    assert r["ok"] is False
    assert r["reason"] == "unknown_scheme"


def test_malformed_hex():
    assert hv.verify("hex", "secret", "body", "not-hex!")["reason"] == "malformed_signature"
