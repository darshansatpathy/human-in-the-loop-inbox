"""The approval workflow.

A request is pending until enough approvers from the rule's groups approve the *current* arguments,
anyone rejects it, it expires, or the agent cancels it. Approval issues a single-use grant bound to the
action and the exact arguments; the tool executor consumes the grant before acting, so an agent cannot
run something other than what a person approved, or run it twice.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from hitl import security
from hitl.db import Database
from hitl.policy import Policy

CHANNEL = "hitl_decided"
GENESIS = "0" * 64
TERMINAL = {"approved", "rejected", "expired", "cancelled", "executed"}


class Conflict(Exception):
    """The request cannot change that way (already decided, expired, duplicate vote...)."""


class Forbidden(Exception):
    """This reviewer may not act on this request."""


class NotFound(Exception):
    pass


@dataclass
class Settings:
    signing_key: bytes
    public_url: str = "http://127.0.0.1:8000"
    grant_ttl_seconds: int = 900
    email_link_ttl_seconds: int = 24 * 3600


async def append_event(cur: psycopg.AsyncCursor[dict[str, Any]], request_id: Any, type_: str, actor: str, data: dict[str, Any]) -> None:
    """Append to the hash chain. A transaction-scoped advisory lock serialises appends, so the chain never forks."""
    await cur.execute("select pg_advisory_xact_lock(7240001)")
    await cur.execute("select hash from events order by seq desc limit 1")
    row = await cur.fetchone()
    prev = row["hash"] if row else GENESIS
    at = dt.datetime.now(dt.UTC)
    digest = hashlib.sha256(
        prev.encode()
        + security.canonical({"r": str(request_id) if request_id else None, "t": type_, "a": actor, "d": data, "at": at.isoformat()})
    ).hexdigest()
    await cur.execute(
        "insert into events (request_id, type, actor, data, at, prev_hash, hash) values (%s, %s, %s, %s, %s, %s, %s)",
        (request_id, type_, actor, Jsonb(data), at, prev, digest),
    )


async def verify_chain(cur: psycopg.AsyncCursor[dict[str, Any]]) -> tuple[bool, int, int | None]:
    """Recompute every hash. Returns (intact, events checked, first bad sequence number)."""
    await cur.execute("select seq, request_id, type, actor, data, at, prev_hash, hash from events order by seq")
    prev, n = GENESIS, 0
    for r in await cur.fetchall():
        n += 1
        at = r["at"].astimezone(dt.UTC).isoformat()
        rid = str(r["request_id"]) if r["request_id"] else None
        expect = hashlib.sha256(
            prev.encode() + security.canonical({"r": rid, "t": r["type"], "a": r["actor"], "d": r["data"], "at": at})
        ).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != expect:
            return False, n, int(r["seq"])
        prev = r["hash"]
    return True, n, None


class Inbox:
    def __init__(self, db: Database, policy: Policy, settings: Settings):
        self.db, self.policy, self.s = db, policy, settings

    # --- identities ---

    async def add_agent(self, name: str) -> str:
        key = "ak_" + secrets.token_urlsafe(32)
        async with self.db.tx() as cur:
            await cur.execute(
                "insert into agents (name, key_hash) values (%s, %s) on conflict (name) do update set key_hash = excluded.key_hash",
                (name, security.hash_secret(key)),
            )
        return key

    async def add_reviewer(self, rid: str, name: str, groups: list[str], email: str | None = None, slack_user: str | None = None) -> str:
        token = "rt_" + secrets.token_urlsafe(32)
        async with self.db.tx() as cur:
            await cur.execute(
                """insert into reviewers (id, name, email, slack_user, groups, token_hash) values (%s, %s, %s, %s, %s, %s)
                   on conflict (id) do update set name = excluded.name, email = excluded.email, slack_user = excluded.slack_user,
                     groups = excluded.groups, token_hash = excluded.token_hash, active = true""",
                (rid, name, email, slack_user, groups, security.hash_secret(token)),
            )
        return token

    async def agent_for(self, key: str) -> str | None:
        async with self.db.tx() as cur:
            await cur.execute("select name from agents where key_hash = %s", (security.hash_secret(key),))
            row = await cur.fetchone()
        return row["name"] if row else None

    async def reviewer_for(
        self, *, token: str | None = None, slack_user: str | None = None, rid: str | None = None
    ) -> dict[str, Any] | None:
        col, val = ("token_hash", security.hash_secret(token)) if token else ("slack_user", slack_user) if slack_user else ("id", rid)
        async with self.db.tx() as cur:
            await cur.execute(f"select id, name, email, slack_user, groups from reviewers where active and {col} = %s", (val,))
            return await cur.fetchone()

    # --- agent side ---

    async def submit(
        self,
        agent: str,
        action: str,
        args: dict[str, Any],
        *,
        risk: str,
        summary: str,
        context: dict[str, Any] | None = None,
        on_behalf_of: str | None = None,
        idempotency_key: str | None = None,
        callback_url: str | None = None,
    ) -> dict[str, Any]:
        h = security.args_hash(action, args)
        async with self.db.tx() as cur:
            if idempotency_key:
                await cur.execute("select * from requests where agent = %s and idempotency_key = %s", (agent, idempotency_key))
                existing = await cur.fetchone()
                if existing:
                    if existing["args_hash"] != h and not existing["decided_at"]:
                        raise Conflict("idempotency key reused with different arguments")
                    return await self._view(cur, existing)
            rule = self.policy.decide(agent, action, risk, args)
            now = dt.datetime.now(dt.UTC)
            status = {"auto_approve": "approved", "auto_deny": "rejected", "review": "pending"}[rule.decision]
            await cur.execute(
                """insert into requests (agent, action, args, args_hash, risk, summary, context, on_behalf_of, status, rule, required_approvals,
                     approver_groups, allow_edits, idempotency_key, callback_url, notify, escalate_at, escalate_to, expires_at, decided_at, decision_reason)
                   values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) returning *""",
                (
                    agent,
                    action,
                    Jsonb(args),
                    h,
                    risk,
                    summary,
                    Jsonb(context or {}),
                    on_behalf_of,
                    status,
                    rule.name,
                    rule.approvals,
                    rule.approvers,
                    rule.allow_edits,
                    idempotency_key,
                    callback_url,
                    rule.notify,
                    now + dt.timedelta(minutes=rule.escalate_after_minutes) if rule.escalate_after_minutes else None,
                    rule.escalate_to,
                    now + dt.timedelta(minutes=rule.ttl_minutes),
                    now if status != "pending" else None,
                    rule.reason or (f"policy rule {rule.name}" if status != "pending" else None),
                ),
            )
            req = await cur.fetchone()
            assert req is not None
            await append_event(
                cur,
                req["id"],
                "submitted",
                f"agent:{agent}",
                {"action": action, "args_hash": h, "risk": risk, "rule": rule.name, "status": status},
            )
            if status == "pending":
                await self._notify_reviewers(cur, req, escalation=False)
            else:
                await self._decided(cur, req)
            return await self._view(cur, req)

    async def get(self, request_id: str, agent: str | None = None) -> dict[str, Any]:
        async with self.db.tx() as cur:
            try:
                await cur.execute("select * from requests where id = %s", (request_id,))
            except psycopg.errors.InvalidTextRepresentation:
                raise NotFound(request_id) from None
            req = await cur.fetchone()
            if req is None or (agent and req["agent"] != agent):
                raise NotFound(request_id)
            if req["status"] == "pending" and req["expires_at"] <= dt.datetime.now(dt.UTC):
                req = await self._expire(cur, req)
            return await self._view(cur, req)

    async def wait(self, request_id: str, agent: str, timeout: float) -> dict[str, Any]:
        """Long poll: returns when the request is decided or the timeout passes. Uses LISTEN/NOTIFY, not polling."""
        view = await self.get(request_id, agent)
        if view["status"] != "pending":
            return view
        deadline = asyncio.get_running_loop().time() + timeout
        async with await psycopg.AsyncConnection.connect(self.db.url, autocommit=True) as conn:
            await conn.execute(f"listen {CHANNEL}")
            view = await self.get(request_id, agent)  # re-check after LISTEN, so a decision in between is not missed
            while view["status"] == "pending":
                left = deadline - asyncio.get_running_loop().time()
                if left <= 0:
                    break
                async for n in conn.notifies(timeout=min(left, view_remaining(view)), stop_after=1):
                    if n.payload != str(request_id):
                        continue
                view = await self.get(request_id, agent)
        return view

    async def cancel(self, request_id: str, agent: str) -> dict[str, Any]:
        async with self.db.tx() as cur:
            req = await self._lock(cur, request_id)
            if req["agent"] != agent:
                raise NotFound(request_id)
            if req["status"] != "pending":
                raise Conflict(f"request is {req['status']}")
            await cur.execute(
                "update requests set status = 'cancelled', decided_at = now(), decision_reason = 'cancelled by agent' where id = %s returning *",
                (request_id,),
            )
            req = await _one(cur)
            await append_event(cur, request_id, "cancelled", f"agent:{agent}", {})
            await self._decided(cur, req)
            return await self._view(cur, req)

    async def consume_grant(self, token: str, action: str, args: dict[str, Any], executor: str) -> dict[str, Any]:
        """Called by the tool executor right before it acts. Refuses a forged, expired, reused or mismatched grant."""
        body = security.verify(self.s.signing_key, "grant", token)
        if body["action"] != action or body["h"] != security.args_hash(action, args):
            raise Forbidden("grant does not cover this action and these arguments")
        async with self.db.tx() as cur:
            await cur.execute(
                "update grants set used_at = now() where jti = %s and used_at is null and expires_at > now() returning request_id",
                (body["jti"],),
            )
            row = await cur.fetchone()
            if row is None:
                raise Conflict("grant already used or expired")
            await cur.execute("update requests set status = 'executed' where id = %s and status = 'approved'", (row["request_id"],))
            await append_event(cur, row["request_id"], "executed", f"executor:{executor}", {"jti": body["jti"]})
        return {"request_id": str(row["request_id"]), "ok": True}

    # --- reviewer side ---

    async def inbox(self, reviewer: dict[str, Any]) -> list[dict[str, Any]]:
        async with self.db.tx() as cur:
            await cur.execute(
                """select r.* from requests r where r.status = 'pending' and r.expires_at > now()
                   and (r.approver_groups && %(g)s or (r.escalated_at is not null and r.escalate_to && %(g)s))
                   and not exists (select 1 from votes v where v.request_id = r.id and v.reviewer = %(id)s)
                   order by r.expires_at""",
                {"g": reviewer["groups"], "id": reviewer["id"]},
            )
            return [await self._view(cur, r) for r in await cur.fetchall()]

    async def vote(
        self,
        request_id: str,
        reviewer: dict[str, Any],
        decision: str,
        *,
        comment: str = "",
        args: dict[str, Any] | None = None,
        via: str = "api",
        seen_hash: str | None = None,
    ) -> dict[str, Any]:
        """Record a decision. `seen_hash` is the args hash the reviewer was shown; if it changed since, the vote is refused."""
        async with self.db.tx() as cur:
            req = await self._lock(cur, request_id)
            if req["status"] == "pending" and req["expires_at"] <= dt.datetime.now(dt.UTC):
                await self._expire(cur, req)
                raise Conflict("request expired")
            if req["status"] != "pending":
                raise Conflict(f"request is already {req['status']}")
            groups = set(req["approver_groups"]) | (set(req["escalate_to"]) if req["escalated_at"] else set())
            if not groups & set(reviewer["groups"]):
                raise Forbidden("not in an approver group for this request")
            if reviewer["id"] == req["on_behalf_of"]:
                raise Forbidden("cannot approve a request made on your own behalf")
            if seen_hash and seen_hash != req["args_hash"]:
                raise Conflict("the arguments changed since you looked; review again")
            current = req["args_hash"]
            await cur.execute("select args_hash from votes where request_id = %s and reviewer = %s", (request_id, reviewer["id"]))
            prior = await cur.fetchone()
            if prior and prior["args_hash"] == current:
                raise Conflict("you already voted on this request")
            if prior:  # they approved arguments that have since been edited; their new vote replaces it (the event log keeps both)
                await cur.execute("delete from votes where request_id = %s and reviewer = %s", (request_id, reviewer["id"]))
            if args is not None and decision == "approve":
                if not req["allow_edits"]:
                    raise Forbidden("this rule does not allow editing the arguments")
                new_hash = security.args_hash(req["action"], args)
                if new_hash != current:
                    await cur.execute("update requests set args = %s, args_hash = %s where id = %s", (Jsonb(args), new_hash, request_id))
                    await append_event(cur, request_id, "edited", f"reviewer:{reviewer['id']}", {"from": current, "to": new_hash})
                    current = new_hash
            await cur.execute(
                "insert into votes (request_id, reviewer, decision, args_hash, comment, via) values (%s, %s, %s, %s, %s, %s)",
                (request_id, reviewer["id"], decision, current, comment, via),
            )
            await append_event(
                cur, request_id, "voted", f"reviewer:{reviewer['id']}", {"decision": decision, "args_hash": current, "via": via}
            )
            if decision == "reject":
                await cur.execute(
                    "update requests set status = 'rejected', decided_at = now(), decision_reason = %s where id = %s returning *",
                    (f"rejected by {reviewer['name']}" + (f": {comment}" if comment else ""), request_id),
                )
            else:
                await cur.execute(
                    "select count(*) as n from votes where request_id = %s and decision = 'approve' and args_hash = %s",
                    (request_id, current),
                )
                n = (await cur.fetchone())["n"]  # type: ignore[index]
                if n >= req["required_approvals"]:
                    await cur.execute(
                        "update requests set status = 'approved', decided_at = now(), decision_reason = %s where id = %s returning *",
                        (f"approved by {n} of {req['required_approvals']}", request_id),
                    )
                else:
                    await cur.execute("select * from requests where id = %s", (request_id,))
            req = await _one(cur)
            if req["status"] != "pending":
                await self._decided(cur, req)
            return await self._view(cur, req)

    # --- background ---

    async def sweep(self) -> dict[str, int]:
        """Expire overdue requests and escalate slow ones."""
        out = {"expired": 0, "escalated": 0}
        async with self.db.tx() as cur:
            await cur.execute("select * from requests where status = 'pending' and expires_at <= now() for update skip locked")
            for req in await cur.fetchall():
                await self._expire(cur, req)
                out["expired"] += 1
            await cur.execute(
                """update requests set escalated_at = now() where status = 'pending' and escalated_at is null
                   and escalate_at is not null and escalate_at <= now() returning *"""
            )
            for req in await cur.fetchall():
                await append_event(cur, req["id"], "escalated", "system", {"to": req["escalate_to"]})
                await self._notify_reviewers(cur, req, escalation=True)
                out["escalated"] += 1
        return out

    # --- internals ---

    async def _lock(self, cur: psycopg.AsyncCursor[dict[str, Any]], request_id: str) -> dict[str, Any]:
        try:
            await cur.execute("select * from requests where id = %s for update", (request_id,))
        except psycopg.errors.InvalidTextRepresentation:
            raise NotFound(request_id) from None
        req = await cur.fetchone()
        if req is None:
            raise NotFound(request_id)
        return req

    async def _expire(self, cur: psycopg.AsyncCursor[dict[str, Any]], req: dict[str, Any]) -> dict[str, Any]:
        await cur.execute(
            "update requests set status = 'expired', decided_at = now(), decision_reason = 'no decision before expiry' where id = %s and status = 'pending' returning *",
            (req["id"],),
        )
        row = await cur.fetchone()
        if row is None:
            await cur.execute("select * from requests where id = %s", (req["id"],))
            return await cur.fetchone()  # type: ignore[return-value]
        await append_event(cur, req["id"], "expired", "system", {})
        await self._decided(cur, row)
        return row

    async def _decided(self, cur: psycopg.AsyncCursor[dict[str, Any]], req: dict[str, Any]) -> None:
        if req["status"] == "approved":
            jti = secrets.token_urlsafe(16)
            await cur.execute(
                "insert into grants (jti, request_id, action, args_hash, expires_at) values (%s, %s, %s, %s, now() + make_interval(secs => %s))",
                (jti, req["id"], req["action"], req["args_hash"], self.s.grant_ttl_seconds),
            )
        await cur.execute("select pg_notify(%s, %s)", (CHANNEL, str(req["id"])))
        if req["callback_url"]:
            await cur.execute(
                "insert into outbox (kind, request_id, payload) values ('webhook', %s, %s)",
                (req["id"], Jsonb({"url": req["callback_url"]})),
            )
        await cur.execute("select channel from slack_messages where request_id = %s", (req["id"],))
        for m in await cur.fetchall():
            await cur.execute(
                "insert into outbox (kind, request_id, payload) values ('slack_update', %s, %s)",
                (req["id"], Jsonb({"channel": m["channel"]})),
            )

    async def _notify_reviewers(self, cur: psycopg.AsyncCursor[dict[str, Any]], req: dict[str, Any], *, escalation: bool) -> None:
        groups = req["escalate_to"] if escalation else req["approver_groups"]
        for target in req["notify"]:
            kind, _, dest = target.partition(":")
            if kind == "slack":
                await cur.execute(
                    "insert into outbox (kind, request_id, payload) values ('slack', %s, %s)",
                    (req["id"], Jsonb({"channel": dest, "escalation": escalation})),
                )
            elif kind == "email":
                await cur.execute(
                    "select id, email from reviewers where active and email is not null and groups && %s",
                    (list(groups) if escalation else [dest],),
                )
                for r in await cur.fetchall():
                    if r["id"] == req["on_behalf_of"]:
                        continue
                    await cur.execute(
                        "insert into outbox (kind, request_id, payload) values ('email', %s, %s)",
                        (req["id"], Jsonb({"reviewer": r["id"], "to": r["email"], "escalation": escalation})),
                    )

    async def _view(self, cur: psycopg.AsyncCursor[dict[str, Any]], req: dict[str, Any]) -> dict[str, Any]:
        await cur.execute(
            "select reviewer, decision, args_hash, comment, via, at from votes where request_id = %s order by at", (req["id"],)
        )
        votes = await cur.fetchall()
        view = {
            "id": str(req["id"]),
            "agent": req["agent"],
            "action": req["action"],
            "args": req["args"],
            "args_hash": req["args_hash"],
            "risk": req["risk"],
            "summary": req["summary"],
            "context": req["context"],
            "on_behalf_of": req["on_behalf_of"],
            "status": req["status"],
            "rule": req["rule"],
            "required_approvals": req["required_approvals"],
            "approvals": sum(1 for v in votes if v["decision"] == "approve" and v["args_hash"] == req["args_hash"]),
            "approver_groups": req["approver_groups"],
            "escalated": req["escalated_at"] is not None,
            "votes": [{**v, "at": v["at"].isoformat()} for v in votes],
            "created_at": req["created_at"].isoformat(),
            "expires_at": req["expires_at"].isoformat(),
            "decided_at": req["decided_at"].isoformat() if req["decided_at"] else None,
            "reason": req["decision_reason"],
        }
        if req["status"] == "approved":
            await cur.execute(
                "select jti, expires_at, used_at from grants where request_id = %s order by expires_at desc limit 1", (req["id"],)
            )
            g = await cur.fetchone()
            if g and g["used_at"] is None:
                ttl = max(1, int((g["expires_at"] - dt.datetime.now(dt.UTC)).total_seconds()))
                view["grant"] = security.sign(
                    self.s.signing_key, "grant", {"jti": g["jti"], "rid": view["id"], "action": req["action"], "h": req["args_hash"]}, ttl
                )
                view["grant_expires_at"] = g["expires_at"].isoformat()
        return view


async def _one(cur: psycopg.AsyncCursor[dict[str, Any]]) -> dict[str, Any]:
    row = await cur.fetchone()
    assert row is not None
    return row


def view_remaining(view: dict[str, Any]) -> float:
    left = (dt.datetime.fromisoformat(view["expires_at"]) - dt.datetime.now(dt.UTC)).total_seconds()
    return max(0.05, left + 0.05)


_ = dict_row  # re-exported for adapters
