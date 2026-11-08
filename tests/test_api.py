from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest
from conftest import KEY, ROOT
from fastapi.testclient import TestClient
from pydantic import SecretStr

from hitl import security
from hitl.api import create_app
from hitl.config import Settings


@pytest.fixture
def api(database_url):
    s = Settings(
        database_url=database_url,
        signing_key=SecretStr(KEY.decode()),
        public_url="http://inbox.test",
        policy_file=ROOT / "policy.yaml",
        slack_signing_secret=SecretStr("slack-secret"),
    )
    app = create_app(s, background=False)
    with TestClient(app) as c:
        inbox = app.state.inbox
        c.agent = {"Authorization": "Bearer " + c.portal.call(inbox.add_agent, "refund-bot")}
        c.cy = {
            "Authorization": "Bearer "
            + c.portal.call(inbox.add_reviewer, "cy@example.com", "Cy", ["support-leads"], "cy@example.com", "U_CY")
        }
        c.ana_token = c.portal.call(inbox.add_reviewer, "ana@example.com", "Ana", ["finance"], "ana@example.com", "U_ANA")
        c.inbox = inbox
        yield c
        c.portal.call(_truncate, inbox)


async def _truncate(inbox):
    async with inbox.db.tx() as cur:
        await cur.execute("truncate votes, grants, outbox, slack_messages, requests cascade")


def submit(c, amount=300, **kw):
    body = {
        "action": "issue_refund",
        "args": {"order": "A-1", "amount": amount},
        "risk": "medium",
        "summary": "Refund a double charge",
    } | kw
    return c.post("/v1/requests", json=body, headers=c.agent)


def test_auth(api):
    assert api.post("/v1/requests", json={}).status_code == 401
    assert api.get("/v1/inbox", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert api.get("/v1/inbox", headers=api.agent).status_code == 401  # an agent key is not a reviewer token


def test_submit_review_wait_and_execute(api):
    r = submit(api)
    assert r.status_code == 201 and r.json()["status"] == "pending"
    rid = r.json()["id"]
    assert [x["id"] for x in api.get("/v1/inbox", headers=api.cy).json()] == [rid]
    v = api.post(f"/v1/requests/{rid}/votes", json={"decision": "approve", "seen_args_hash": r.json()["args_hash"]}, headers=api.cy)
    assert v.status_code == 200 and v.json()["status"] == "approved"
    waited = api.get(f"/v1/requests/{rid}/wait?timeout=1", headers=api.agent).json()
    grant = waited["grant"]
    ok = api.post(
        "/v1/grants/consume",
        json={"grant": grant, "action": "issue_refund", "args": {"order": "A-1", "amount": 300}, "executor": "payments"},
    )
    assert ok.status_code == 200
    again = api.post("/v1/grants/consume", json={"grant": grant, "action": "issue_refund", "args": {"order": "A-1", "amount": 300}})
    assert again.status_code == 409
    assert api.get(f"/v1/requests/{rid}", headers=api.agent).json()["status"] == "executed"


def test_auto_decisions_return_200(api):
    r = submit(api, amount=10)
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_validation_and_errors(api):
    assert submit(api, action="Bad Action").status_code == 422
    rid = submit(api).json()["id"]
    assert (
        api.post(
            f"/v1/requests/{rid}/votes", json={"decision": "approve"}, headers={"Authorization": "Bearer " + api.ana_token}
        ).status_code
        == 200
    )
    assert api.post(f"/v1/requests/{rid}/votes", json={"decision": "approve"}, headers=api.cy).status_code == 409
    assert api.get("/v1/requests/not-a-uuid", headers=api.agent).status_code == 404
    assert api.post("/v1/grants/consume", json={"grant": "x.y", "action": "a", "args": {}}).status_code == 403


def test_email_link_get_does_not_decide_post_does(api):
    r = submit(api).json()
    token = security.sign(KEY, "email", {"rid": r["id"], "rev": "cy@example.com", "h": r["args_hash"], "d": "approve"}, 3600)
    page = api.get(f"/email/{token}")
    assert page.status_code == 200 and '<form method="post">' in page.text
    assert api.get(f"/v1/requests/{r['id']}", headers=api.agent).json()["status"] == "pending"  # a link scanner changed nothing
    done = api.post(f"/email/{token}")
    assert done.status_code == 200 and "approved" in done.text
    assert "already approved" in api.get(f"/email/{token}").text
    assert api.get(f"/email/{token[:-3]}abc").status_code == 403


def _slack(api, user, action_id, value, *, secret="slack-secret", ts=None):
    body = urlencode({"payload": json.dumps({"user": {"id": user}, "actions": [{"action_id": action_id, "value": value}]})}).encode()
    ts = str(ts or int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return api.post(
        "/slack/interactions",
        content=body,
        headers={"x-slack-request-timestamp": ts, "x-slack-signature": sig, "content-type": "application/x-www-form-urlencoded"},
    )


def test_slack_button(api):
    r = submit(api).json()
    value = f"{r['id']}|{r['args_hash']}"
    assert _slack(api, "U_CY", "approve", value, secret="wrong").status_code == 401
    assert _slack(api, "U_CY", "approve", value, ts=int(time.time()) - 900).status_code == 401
    assert "not set up" in _slack(api, "U_NOBODY", "approve", value).json()["text"]
    ok = _slack(api, "U_CY", "approve", value).json()
    assert "Status: approved" in ok["text"]
    dup = _slack(api, "U_CY", "approve", value).json()  # Slack retries deliveries
    assert "Not recorded" in dup["text"]


def test_audit_and_ops(api):
    submit(api)
    out = api.get("/v1/audit/verify", headers=api.cy).json()
    assert out["intact"] and out["events"] >= 1
    assert api.get("/healthz").json() == {"status": "ok"}
    assert api.get("/readyz").status_code == 200
    assert "hitl_requests_total" in api.get("/metrics").text
