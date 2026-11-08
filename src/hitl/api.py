"""HTTP API: agents submit and wait; reviewers decide through the API, the web inbox, Slack or email."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import html
import json
import logging
from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import AnyHttpUrl, BaseModel, Field

from hitl import __version__, metrics, security
from hitl.adapters import Dispatcher, Slack
from hitl.config import Settings
from hitl.db import Database
from hitl.policy import Policy
from hitl.service import Conflict, Forbidden, Inbox, NotFound
from hitl.service import Settings as InboxSettings

log = logging.getLogger("hitl")


class SubmitIn(BaseModel):
    action: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.]*$")]
    args: dict[str, Any]
    risk: Literal["low", "medium", "high", "critical"] = "medium"
    summary: Annotated[str, Field(min_length=1, max_length=2000, description="What the agent wants to do and why, for the reviewer")]
    context: dict[str, Any] = Field(default_factory=dict)
    on_behalf_of: str | None = Field(None, max_length=200)
    idempotency_key: Annotated[str | None, Field(min_length=8, max_length=128)] = None
    callback_url: AnyHttpUrl | None = None


class GrantIn(BaseModel):
    grant: str
    action: str
    args: dict[str, Any]
    executor: str = Field("unknown", max_length=100)


class VoteIn(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field("", max_length=1000)
    args: dict[str, Any] | None = Field(None, description="Approve with these arguments instead")
    seen_args_hash: str | None = Field(None, description="The args_hash you reviewed; the vote is refused if it changed")


def create_app(settings: Settings | None = None, *, slack: Slack | None = None, background: bool = True) -> FastAPI:
    s = settings or Settings()
    db = Database(s.database_url)
    inbox = Inbox(
        db, Policy.load(s.policy_file), InboxSettings(s.signing_key.get_secret_value().encode(), s.public_url, s.grant_ttl_seconds)
    )
    if slack is None and s.slack_bot_token:
        slack = Slack(s.slack_bot_token.get_secret_value(), s.slack_api_url)
    dispatcher = Dispatcher(inbox, slack=slack, smtp=(s.smtp_host, s.smtp_port) if s.smtp_host else None, sender=s.email_from)

    async def sweeper() -> None:
        while True:
            await asyncio.sleep(s.sweep_interval_seconds)
            try:
                out = await inbox.sweep()
                metrics.DECIDED.labels("expired").inc(out["expired"])
            except Exception:
                log.exception("sweep failed")

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await db.open()
        tasks = (
            [asyncio.create_task(sweeper()), asyncio.create_task(dispatcher.run_forever(s.dispatch_interval_seconds))] if background else []
        )
        yield
        for t in tasks:
            t.cancel()
        await db.close()

    app = FastAPI(title="human-in-the-loop-inbox", version=__version__, lifespan=lifespan)
    app.state.inbox, app.state.dispatcher = inbox, dispatcher

    def bearer(authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing token", headers={"WWW-Authenticate": "Bearer"})
        return authorization[7:].strip()

    async def agent_dep(authorization: Annotated[str | None, Header()] = None) -> str:
        name = await inbox.agent_for(bearer(authorization))
        if name is None:
            raise HTTPException(401, "invalid agent key", headers={"WWW-Authenticate": "Bearer"})
        return name

    async def reviewer_dep(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
        r = await inbox.reviewer_for(token=bearer(authorization))
        if r is None:
            raise HTTPException(401, "invalid reviewer token", headers={"WWW-Authenticate": "Bearer"})
        return r

    AGENT = Depends(agent_dep)
    REVIEWER = Depends(reviewer_dep)

    def errors(e: Exception) -> HTTPException:
        code = {NotFound: 404, Conflict: 409, Forbidden: 403, security.InvalidToken: 403}.get(type(e), 500)
        return HTTPException(code, str(e) or type(e).__name__)

    # --- agents ---

    @app.post("/v1/requests", status_code=201)
    async def submit(body: SubmitIn, response: Response, agent: str = AGENT) -> dict[str, Any]:
        try:
            view = await inbox.submit(
                agent,
                body.action,
                body.args,
                risk=body.risk,
                summary=body.summary,
                context=body.context,
                on_behalf_of=body.on_behalf_of,
                idempotency_key=body.idempotency_key,
                callback_url=str(body.callback_url) if body.callback_url else None,
            )
        except Conflict as e:
            raise errors(e) from None
        metrics.SUBMITTED.labels(view["rule"], view["status"]).inc()
        if view["status"] != "pending":
            response.status_code = 200
        return view

    @app.get("/v1/requests/{request_id}")
    async def get_request(request_id: str, agent: str = AGENT) -> dict[str, Any]:
        try:
            return await inbox.get(request_id, agent)
        except (NotFound, ValueError):
            raise HTTPException(404, "not found") from None

    @app.get("/v1/requests/{request_id}/wait")
    async def wait(request_id: str, timeout: Annotated[float, Query(gt=0, le=60)] = 30, agent: str = AGENT) -> dict[str, Any]:
        try:
            return await inbox.wait(request_id, agent, timeout)
        except (NotFound, ValueError):
            raise HTTPException(404, "not found") from None

    @app.post("/v1/requests/{request_id}/cancel")
    async def cancel(request_id: str, agent: str = AGENT) -> dict[str, Any]:
        try:
            return await inbox.cancel(request_id, agent)
        except (NotFound, Conflict) as e:
            raise errors(e) from None

    @app.post("/v1/grants/consume")
    async def consume(body: GrantIn) -> dict[str, Any]:
        """For the tool executor (not the agent): check and burn the grant right before acting."""
        try:
            out = await inbox.consume_grant(body.grant, body.action, body.args, body.executor)
        except (security.InvalidToken, Forbidden, Conflict) as e:
            metrics.GRANTS.labels(type(e).__name__).inc()
            raise errors(e) from None
        metrics.GRANTS.labels("ok").inc()
        return out

    # --- reviewers ---

    @app.get("/v1/inbox")
    async def my_inbox(reviewer: dict[str, Any] = REVIEWER) -> list[dict[str, Any]]:
        return await inbox.inbox(reviewer)

    @app.post("/v1/requests/{request_id}/votes")
    async def vote(request_id: str, body: VoteIn, reviewer: dict[str, Any] = REVIEWER) -> dict[str, Any]:
        try:
            view = await inbox.vote(
                request_id, reviewer, body.decision, comment=body.comment, args=body.args, via="api", seen_hash=body.seen_args_hash
            )
        except (NotFound, Conflict, Forbidden) as e:
            raise errors(e) from None
        _count(body.decision, "api", view)
        return view

    def _count(decision: str, via: str, view: dict[str, Any]) -> None:
        metrics.VOTES.labels(via, decision).inc()
        if view["status"] != "pending":
            metrics.DECIDED.labels(view["status"]).inc()
            created = dt.datetime.fromisoformat(view["created_at"])
            metrics.TIME_TO_DECISION.observe((dt.datetime.now(dt.UTC) - created).total_seconds())

    # --- email links: GET shows a page, only POST decides (mail scanners follow links) ---

    def email_claims(token: str) -> dict[str, Any]:
        try:
            return security.verify(inbox.s.signing_key, "email", token)
        except security.InvalidToken as e:
            raise HTTPException(403, f"link not valid: {e}") from None

    @app.get("/email/{token}", response_class=HTMLResponse)
    async def email_page(token: str) -> str:
        c = email_claims(token)
        try:
            view = await inbox.get(c["rid"])
        except NotFound:
            raise HTTPException(404, "not found") from None
        args = html.escape(json.dumps(view["args"], indent=2, ensure_ascii=False))
        verb = "Approve" if c["d"] == "approve" else "Reject"
        state = "" if view["status"] == "pending" else f"<p><strong>This request is already {html.escape(view['status'])}.</strong></p>"
        changed = (
            ""
            if view["args_hash"] == c["h"]
            else "<p><strong>The arguments changed since this email was sent; review it in the inbox.</strong></p>"
        )
        button = "" if state or changed else f'<form method="post"><button type="submit">{verb}</button></form>'
        return (
            f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>{verb} {html.escape(view['action'])}</title>"
            f"<style>body{{font:16px system-ui;max-width:40rem;margin:2rem auto;padding:0 1rem}}pre{{background:#f4f4f4;padding:1rem;overflow:auto}}"
            f"button{{font-size:1rem;padding:.6rem 1.2rem}}</style>"
            f"<h1>{verb} {html.escape(view['action'])}?</h1><p>{html.escape(view['summary'])}</p><pre>{args}</pre>"
            f"<p>Requested by {html.escape(view['agent'])}, risk {html.escape(view['risk'])}.</p>{state}{changed}{button}"
        )

    @app.post("/email/{token}", response_class=HTMLResponse)
    async def email_decide(token: str) -> str:
        c = email_claims(token)
        reviewer = await inbox.reviewer_for(rid=c["rev"])
        if reviewer is None:
            raise HTTPException(403, "reviewer not active")
        try:
            view = await inbox.vote(c["rid"], reviewer, c["d"], via="email", seen_hash=c["h"])
        except (NotFound, Conflict, Forbidden) as e:
            raise errors(e) from None
        _count(c["d"], "email", view)
        return f"<!doctype html><meta charset=utf-8><title>Recorded</title><p>Recorded. The request is now <strong>{html.escape(view['status'])}</strong>.</p>"

    # --- Slack interactivity ---

    @app.post("/slack/interactions")
    async def slack_interaction(request: Request) -> Response:
        if not s.slack_signing_secret:
            raise HTTPException(404, "slack is not configured")
        raw = await request.body()
        ok = security.slack_signature_ok(
            s.slack_signing_secret.get_secret_value(),
            request.headers.get("x-slack-request-timestamp", ""),
            raw,
            request.headers.get("x-slack-signature", ""),
        )
        if not ok:
            raise HTTPException(401, "bad signature")
        payload = json.loads(parse_qs(raw.decode())["payload"][0])
        action = payload["actions"][0]
        rid, seen = action["value"].split("|")
        reviewer = await inbox.reviewer_for(slack_user=payload["user"]["id"])
        if reviewer is None:
            return JSONResponse({"response_type": "ephemeral", "text": "You are not set up as a reviewer."})
        try:
            view = await inbox.vote(rid, reviewer, action["action_id"], via="slack", seen_hash=seen)
        except (NotFound, Conflict, Forbidden) as e:
            return JSONResponse({"response_type": "ephemeral", "replace_original": False, "text": f"Not recorded: {e}"})
        _count(action["action_id"], "slack", view)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "replace_original": False,
                "text": f"Recorded your {action['action_id']}. Status: {view['status']}.",
            }
        )

    # --- operations ---

    @app.get("/v1/audit/verify")
    async def audit_verify(_: dict[str, Any] = REVIEWER) -> dict[str, Any]:
        from hitl.service import verify_chain

        async with db.tx() as cur:
            ok, n, bad = await verify_chain(cur)
        return {"intact": ok, "events": n, "first_bad_seq": bad}

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        try:
            async with db.tx() as cur:
                await cur.execute("select 1")
            return Response("ready")
        except Exception:  # noqa: BLE001 - any failure means not ready
            return Response("database unavailable", status_code=503)

    @app.get("/metrics", include_in_schema=False)
    async def prom() -> Response:
        return Response(generate_latest(metrics.REGISTRY), media_type=CONTENT_TYPE_LATEST)

    return app
