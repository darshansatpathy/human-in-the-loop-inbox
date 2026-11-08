from __future__ import annotations

import time

import pytest
from conftest import ROOT

from hitl import security
from hitl.policy import Policy, Rule

POL = Policy.load(ROOT / "policy.yaml")


@pytest.mark.parametrize(
    ("action", "risk", "args", "rule", "decision"),
    [
        ("read_invoice", "low", {}, "read-only", "auto_approve"),
        ("delete_bucket", "high", {"environment": "production"}, "never-delete-production", "auto_deny"),
        ("delete_bucket", "high", {"environment": "staging"}, "default", "review"),
        ("issue_refund", "medium", {"amount": 20}, "small-refunds", "auto_approve"),
        ("issue_refund", "medium", {"amount": 5000}, "large-refunds", "review"),
        ("issue_refund", "medium", {"amount": 300}, "refunds", "review"),
        ("issue_refund", "medium", {"amount": "lots"}, "refunds", "review"),
        ("send_email", "low", {}, "default", "review"),
        ("send_email", "high", {}, "outbound-email", "review"),
        ("restart_cluster", "critical", {}, "critical", "review"),
    ],
)
def test_rules(action, risk, args, rule, decision):
    r = POL.decide("bot", action, risk, args)
    assert (r.name, r.decision) == (rule, decision)


def test_unknown_policy_keys_are_refused():
    with pytest.raises(ValueError):
        Rule.model_validate({"name": "x", "approvers_typo": ["a"]})
    with pytest.raises(ValueError):
        Policy.model_validate({"rules": [{"name": "x", "match": {"args": {"amount": {"greater": 5}}}}]})


def test_signed_tokens():
    key = b"k" * 32
    t = security.sign(key, "grant", {"a": 1}, 60)
    assert security.verify(key, "grant", t)["a"] == 1
    for bad, why in [(t, "wrong purpose"), (t[:-2] + "xx", "bad signature"), ("nope", "malformed")]:
        with pytest.raises(security.InvalidToken, match=why):
            security.verify(key, "email" if why == "wrong purpose" else "grant", bad)
    with pytest.raises(security.InvalidToken, match="expired"):
        security.verify(key, "grant", security.sign(key, "grant", {}, -1))
    with pytest.raises(security.InvalidToken, match="bad signature"):
        security.verify(b"x" * 32, "grant", t)


def test_args_hash_is_canonical():
    assert security.args_hash("a", {"x": 1, "y": [1, 2]}) == security.args_hash("a", {"y": [1, 2], "x": 1})
    assert security.args_hash("a", {"x": 1}) != security.args_hash("a", {"x": 2})
    assert security.args_hash("a", {"x": 1}) != security.args_hash("b", {"x": 1})


def test_slack_signatures():
    import hashlib
    import hmac

    ts = str(int(time.time()))
    body = b"payload=%7B%7D"
    sig = "v0=" + hmac.new(b"sec", f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    assert security.slack_signature_ok("sec", ts, body, sig)
    assert not security.slack_signature_ok("sec", ts, body + b"x", sig)
    old = str(int(time.time()) - 600)
    old_sig = "v0=" + hmac.new(b"sec", f"v0:{old}:".encode() + body, hashlib.sha256).hexdigest()
    assert not security.slack_signature_ok("sec", old, body, old_sig)
    assert not security.slack_signature_ok("sec", "nan", body, sig)
