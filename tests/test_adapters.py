from __future__ import annotations

import json
import socket

import httpx
import pytest
from aiosmtpd.controller import Controller
from conftest import KEY, reviewer

from hitl import security
from hitl.adapters import Dispatcher, Slack, slack_blocks


class FakeSlack:
    def __init__(self, fail_first: int = 0):
        self.calls: list[tuple[str, dict]] = []
        self.fail_first = fail_first

    def transport(self) -> httpx.MockTransport:
        def handle(req: httpx.Request) -> httpx.Response:
            method = req.url.path.rsplit("/", 1)[-1]
            body = json.loads(req.content)
            self.calls.append((method, body))
            if self.fail_first > 0:
                self.fail_first -= 1
                return httpx.Response(503)
            assert req.headers["authorization"] == "Bearer xoxb-test"
            return httpx.Response(200, json={"ok": True, "channel": "C123", "ts": "1700000000.000100"})

        return httpx.MockTransport(handle)


class Mailbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        return "250 OK"


@pytest.fixture
def smtp():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    box = Mailbox()
    c = Controller(box, hostname="127.0.0.1", port=port)
    c.start()
    yield ("127.0.0.1", port), box
    c.stop()


async def test_slack_message_then_update_after_decision(inbox):
    fake = FakeSlack()
    d = Dispatcher(inbox, slack=Slack("xoxb-test", "https://slack.test/api", httpx.AsyncClient(transport=fake.transport())))
    v = await inbox.submit("refund-bot", "issue_refund", {"order": "A-7", "amount": 300}, risk="medium", summary="Customer double charged")
    assert (await d.run_once())["sent"] == 1
    method, body = fake.calls[0]
    assert method == "chat.postMessage" and body["channel"] == "#refund-approvals"
    buttons = body["blocks"][-1]["elements"]
    assert [b["action_id"] for b in buttons] == ["approve", "reject"] and buttons[0]["value"] == f"{v['id']}|{v['args_hash']}"
    await inbox.vote(v["id"], await reviewer(inbox, "cy@example.com"), "approve", via="slack")
    assert (await d.run_once())["sent"] == 1
    method, body = fake.calls[1]
    assert method == "chat.update" and body["ts"] == "1700000000.000100"
    assert "APPROVED" in json.dumps(body["blocks"]) and body["blocks"][-1]["type"] == "section"


async def test_outbox_retries_with_backoff_then_dead_letters(inbox):
    fake = FakeSlack(fail_first=100)
    d = Dispatcher(inbox, slack=Slack("xoxb-test", "https://slack.test/api", httpx.AsyncClient(transport=fake.transport())))
    await inbox.submit("refund-bot", "issue_refund", {"order": "A-8", "amount": 300}, risk="medium", summary="x")
    assert (await d.run_once())["retry"] == 1
    async with inbox.db.tx() as cur:
        await cur.execute("select attempts, next_at > now() as later, last_error from outbox")
        row = await cur.fetchone()
    assert row["attempts"] == 1 and row["later"] and "503" in row["last_error"]
    assert (await d.run_once())["sent"] == 0  # not due yet
    for _ in range(7):
        async with inbox.db.tx() as cur:
            await cur.execute("update outbox set next_at = now()")
        await d.run_once()
    async with inbox.db.tx() as cur:
        await cur.execute("select attempts, dead_at is not null as dead from outbox")
        row = await cur.fetchone()
    assert row["attempts"] == 8 and row["dead"]


async def test_email_links_carry_signed_single_purpose_tokens(inbox, smtp):
    addr, box = smtp
    d = Dispatcher(inbox, smtp=addr, sender="approvals@inbox.test")
    v = await inbox.submit(
        "refund-bot", "issue_refund", {"order": "A-9", "amount": 5000}, risk="medium", summary="Big refund", on_behalf_of="ana@example.com"
    )
    await d.run_once()
    rcpts = sorted(r for m in box.messages for r in m.rcpt_tos)
    assert rcpts == ["ben@example.com"]  # finance, minus the person it is on behalf of
    import email
    from email import policy

    body = email.message_from_bytes(box.messages[0].content, policy=policy.default).get_content()
    links = [line.split(": ", 1)[1].strip() for line in body.splitlines() if line.startswith(("Approve:", "Reject:"))]
    claims = [security.verify(KEY, "email", link.rsplit("/", 1)[1]) for link in links]
    assert [c["d"] for c in claims] == ["approve", "reject"] and all(c["rid"] == v["id"] and c["rev"] == "ben@example.com" for c in claims)


async def test_signed_webhook_on_decision(inbox):
    seen = []

    def handle(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(204)

    d = Dispatcher(inbox, http=httpx.AsyncClient(transport=httpx.MockTransport(handle)))
    v = await inbox.submit(
        "refund-bot", "issue_refund", {"order": "A-10", "amount": 10}, risk="low", summary="small", callback_url="https://agent.test/hook"
    )
    await d.run_once()
    assert len(seen) == 1
    req = seen[0]
    sig = req.headers["x-hitl-signature"]
    ts = int(sig.split(",")[0][2:])
    assert sig == security.webhook_signature(KEY, ts, req.content)
    payload = json.loads(req.content)
    assert payload["request"]["id"] == v["id"] and payload["request"]["status"] == "approved" and payload["request"]["grant"]


def test_blocks_for_a_decided_request_have_no_buttons():
    view = {
        "id": "1",
        "agent": "a",
        "action": "x",
        "args": {},
        "args_hash": "h",
        "summary": "s",
        "risk": "low",
        "rule": "r",
        "required_approvals": 1,
        "approver_groups": ["g"],
        "expires_at": "2026-01-01T00:00:00",
        "on_behalf_of": None,
        "status": "rejected",
        "votes": [],
        "reason": "no",
    }
    assert all(b["type"] != "actions" for b in slack_blocks(view))
