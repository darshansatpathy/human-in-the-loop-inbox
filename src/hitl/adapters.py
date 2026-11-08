"""Delivery to people and agents: Slack messages with buttons, emails with signed links, signed webhooks.

All of it goes through the outbox: a row written in the same transaction as the decision, delivered by
the dispatcher with retries and backoff, so a Slack outage delays a notification but never loses it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import smtplib
import time
from email.message import EmailMessage
from typing import Any

import httpx
from psycopg.types.json import Jsonb

from hitl import security
from hitl.service import Inbox

log = logging.getLogger("hitl.outbox")
MAX_ATTEMPTS = 8


class Slack:
    def __init__(self, token: str, base_url: str = "https://slack.com/api", client: httpx.AsyncClient | None = None):
        self.token, self.base = token, base_url.rstrip("/")
        self.client = client or httpx.AsyncClient(timeout=10)

    async def call(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        r = await self.client.post(f"{self.base}/{method}", json=body, headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        if not data.get("ok"):
            raise RuntimeError(f"slack {method}: {data.get('error')}")
        return data


def slack_blocks(view: dict[str, Any], *, escalation: bool = False) -> list[dict[str, Any]]:
    args = json.dumps(view["args"], indent=2, ensure_ascii=False)[:2500]
    head = ("Escalated: " if escalation else "") + f"{view['agent']} wants to run {view['action']}"
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": head[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": view["summary"][:2900]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{args}```"}},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Risk *{view['risk']}* · rule `{view['rule']}` · needs {view['required_approvals']} of {', '.join(view['approver_groups'])}"
                    + f" · expires {view['expires_at'][:16].replace('T', ' ')} UTC"
                    + (f" · for {view['on_behalf_of']}" if view["on_behalf_of"] else ""),
                }
            ],
        },
    ]
    if view["status"] == "pending":
        value = f"{view['id']}|{view['args_hash']}"
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "approve",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "value": value,
                    },
                    {
                        "type": "button",
                        "action_id": "reject",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "value": value,
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Reject this action?"},
                            "confirm": {"type": "plain_text", "text": "Reject"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                            "text": {"type": "plain_text", "text": "The agent will be told it may not proceed."},
                        },
                    },
                ],
            }
        )
    else:
        who = ", ".join(f"{v['reviewer']} ({v['decision']})" for v in view["votes"]) or "policy"
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{view['status'].upper()}*: {view['reason'] or ''} · {who}"}}
        )
    return blocks


def email_message(inbox: Inbox, view: dict[str, Any], reviewer: str, to: str, sender: str, *, escalation: bool) -> EmailMessage:
    def link(decision: str) -> str:
        token = security.sign(
            inbox.s.signing_key,
            "email",
            {"rid": view["id"], "rev": reviewer, "h": view["args_hash"], "d": decision},
            inbox.s.email_link_ttl_seconds,
        )
        return f"{inbox.s.public_url}/email/{token}"

    msg = EmailMessage()
    msg["Subject"] = ("[Escalated] " if escalation else "") + f"Approve {view['action']} for {view['agent']}?"
    msg["From"], msg["To"] = sender, to
    args = json.dumps(view["args"], indent=2, ensure_ascii=False)
    msg.set_content(
        f"{view['summary']}\n\nAction: {view['action']}\nArguments:\n{args}\n\nRisk: {view['risk']}. Expires {view['expires_at']}.\n\n"
        f"Approve: {link('approve')}\nReject:  {link('reject')}\n\nEach link opens a confirmation page; nothing happens until you confirm."
    )
    return msg


class Dispatcher:
    def __init__(
        self,
        inbox: Inbox,
        *,
        slack: Slack | None = None,
        smtp: tuple[str, int] | None = None,
        sender: str = "approvals@example.com",
        http: httpx.AsyncClient | None = None,
    ):
        self.inbox, self.slack, self.smtp, self.sender = inbox, slack, smtp, sender
        self.http = http or httpx.AsyncClient(timeout=10)

    async def run_once(self, limit: int = 50) -> dict[str, int]:
        """Deliver what is due. Rows are claimed with SKIP LOCKED, so several dispatchers can run side by side."""
        stats = {"sent": 0, "retry": 0, "dead": 0}
        async with self.inbox.db.tx() as cur:
            await cur.execute(
                "select * from outbox where done_at is null and dead_at is null and next_at <= now() order by id limit %s for update skip locked",
                (limit,),
            )
            rows = await cur.fetchall()
            for row in rows:
                try:
                    async with cur.connection.transaction():  # a savepoint: a failed delivery leaves the batch usable
                        await self._deliver(cur, row)
                    await cur.execute("update outbox set done_at = now(), attempts = attempts + 1 where id = %s", (row["id"],))
                    stats["sent"] += 1
                except Exception as e:  # noqa: BLE001 - any failure is retried, then dead-lettered
                    attempts = row["attempts"] + 1
                    if attempts >= MAX_ATTEMPTS:
                        await cur.execute(
                            "update outbox set attempts = %s, dead_at = now(), last_error = %s where id = %s",
                            (attempts, str(e)[:500], row["id"]),
                        )
                        stats["dead"] += 1
                    else:
                        delay = min(3600, 5 * 2**attempts) * (0.5 + random.random() / 2)
                        await cur.execute(
                            "update outbox set attempts = %s, next_at = now() + make_interval(secs => %s), last_error = %s where id = %s",
                            (attempts, delay, str(e)[:500], row["id"]),
                        )
                        stats["retry"] += 1
                    log.warning("delivery failed", extra={"kind": row["kind"], "attempt": attempts, "error": str(e)[:200]})
        return stats

    async def run_forever(self, interval: float = 1.0) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                log.exception("dispatcher pass failed")
            await asyncio.sleep(interval)

    async def _deliver(self, cur: Any, row: dict[str, Any]) -> None:
        p = row["payload"]
        view = await self.inbox.get(str(row["request_id"]))
        if row["kind"] == "slack":
            if self.slack is None:
                raise RuntimeError("slack is not configured")
            data = await self.slack.call(
                "chat.postMessage",
                {
                    "channel": p["channel"],
                    "text": f"Approval needed: {view['action']}",
                    "blocks": slack_blocks(view, escalation=p.get("escalation", False)),
                },
            )
            await cur.execute(
                "insert into slack_messages (request_id, channel, ts) values (%s, %s, %s) on conflict (request_id, channel) do update set ts = excluded.ts",
                (row["request_id"], data["channel"], data["ts"]),
            )
        elif row["kind"] == "slack_update":
            if self.slack is None:
                raise RuntimeError("slack is not configured")
            await cur.execute(
                "select channel, ts from slack_messages where request_id = %s and channel = %s", (row["request_id"], p["channel"])
            )
            m = await cur.fetchone()
            if m:
                await self.slack.call(
                    "chat.update",
                    {"channel": m["channel"], "ts": m["ts"], "text": f"{view['status']}: {view['action']}", "blocks": slack_blocks(view)},
                )
        elif row["kind"] == "email":
            if self.smtp is None:
                raise RuntimeError("smtp is not configured")
            msg = email_message(self.inbox, view, p["reviewer"], p["to"], self.sender, escalation=p.get("escalation", False))
            host, port = self.smtp
            await asyncio.to_thread(_send, host, port, msg)
        elif row["kind"] == "webhook":
            body = json.dumps({"event": "request.decided", "request": view}, default=str).encode()
            ts = int(time.time())
            r = await self.http.post(
                p["url"],
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-hitl-signature": security.webhook_signature(self.inbox.s.signing_key, ts, body),
                },
            )
            r.raise_for_status()


def _send(host: str, port: int, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=10) as s:
        s.send_message(msg)


__all__ = ["Dispatcher", "Jsonb", "Slack", "email_message", "slack_blocks"]
