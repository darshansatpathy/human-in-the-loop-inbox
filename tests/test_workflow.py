from __future__ import annotations

import asyncio
import datetime as dt

import pytest
from conftest import reviewer

from hitl import security
from hitl.service import Conflict, Forbidden, NotFound, verify_chain


async def refund(inbox, amount, **kw):
    return await inbox.submit(
        "refund-bot", "issue_refund", {"order": "A-1001", "amount": amount}, risk="medium", summary=f"Refund {amount}", **kw
    )


async def test_auto_approve_issues_a_grant_that_works_once(inbox):
    v = await refund(inbox, 20)
    assert v["status"] == "approved" and v["rule"] == "small-refunds" and v["grant"]
    ok = await inbox.consume_grant(v["grant"], "issue_refund", {"order": "A-1001", "amount": 20}, "payments")
    assert ok["ok"]
    with pytest.raises(Conflict, match="already used"):
        await inbox.consume_grant(v["grant"], "issue_refund", {"order": "A-1001", "amount": 20}, "payments")
    assert (await inbox.get(v["id"]))["status"] == "executed"


async def test_grant_is_bound_to_the_exact_arguments(inbox):
    v = await refund(inbox, 20)
    with pytest.raises(Forbidden):
        await inbox.consume_grant(v["grant"], "issue_refund", {"order": "A-1001", "amount": 2000}, "payments")
    with pytest.raises(Forbidden):
        await inbox.consume_grant(v["grant"], "delete_account", {"order": "A-1001", "amount": 20}, "payments")
    with pytest.raises(security.InvalidToken):
        await inbox.consume_grant(
            security.sign(b"attacker-key-attacker-key-000000", "grant", {"jti": "x", "action": "issue_refund", "h": "h"}, 60),
            "issue_refund",
            {},
            "x",
        )


async def test_auto_deny(inbox):
    v = await inbox.submit("ops-bot", "delete_bucket", {"environment": "production", "bucket": "logs"}, risk="high", summary="clean up")
    assert v["status"] == "rejected" and "change ticket" in v["reason"] and "grant" not in v


async def test_two_person_rule_with_separation_of_duties(inbox):
    v = await refund(inbox, 5000, on_behalf_of="ana@example.com")
    assert v["status"] == "pending" and v["required_approvals"] == 2
    ana, ben, cy = [await reviewer(inbox, r) for r in ("ana@example.com", "ben@example.com", "cy@example.com")]
    with pytest.raises(Forbidden, match="own behalf"):
        await inbox.vote(v["id"], ana, "approve")
    with pytest.raises(Forbidden, match="approver group"):
        await inbox.vote(v["id"], cy, "approve")
    v = await inbox.vote(v["id"], ben, "approve")
    assert v["status"] == "pending" and v["approvals"] == 1
    with pytest.raises(Conflict, match="already voted"):
        await inbox.vote(v["id"], ben, "approve")


async def test_quorum_approves_and_any_reject_vetoes(inbox):
    v = await refund(inbox, 5000)
    ana, ben = await reviewer(inbox, "ana@example.com"), await reviewer(inbox, "ben@example.com")
    await inbox.vote(v["id"], ana, "approve")
    v2 = await inbox.vote(v["id"], ben, "approve", comment="checked the order")
    assert v2["status"] == "approved" and v2["grant"] and v2["reason"] == "approved by 2 of 2"
    with pytest.raises(Conflict, match="already approved"):
        await inbox.vote(v["id"], await reviewer(inbox, "dee@example.com"), "reject")
    w = await refund(inbox, 4000)
    await inbox.vote(w["id"], ana, "approve")
    w2 = await inbox.vote(w["id"], ben, "reject", comment="duplicate refund")
    assert w2["status"] == "rejected" and "duplicate refund" in w2["reason"]


async def test_edit_resets_the_quorum_to_the_new_arguments(inbox):
    v = await refund(inbox, 5000)
    ana, ben = await reviewer(inbox, "ana@example.com"), await reviewer(inbox, "ben@example.com")
    await inbox.vote(v["id"], ana, "approve")
    edited = await inbox.vote(v["id"], ben, "approve", args={"order": "A-1001", "amount": 4500})
    assert edited["status"] == "pending" and edited["approvals"] == 1 and edited["args"]["amount"] == 4500
    # Ana approved 5000, not 4500: her old vote no longer counts, and a vote on what she saw before is refused.
    with pytest.raises(Conflict, match="changed since you looked"):
        await inbox.vote(v["id"], ana, "approve", seen_hash=v["args_hash"])
    done = await inbox.vote(v["id"], ana, "approve", seen_hash=edited["args_hash"])
    assert done["status"] == "approved" and done["args"]["amount"] == 4500
    ok = await inbox.consume_grant(done["grant"], "issue_refund", {"order": "A-1001", "amount": 4500}, "payments")
    assert ok["ok"]


async def test_critical_rule_forbids_edits(inbox):
    v = await inbox.submit("ops-bot", "restart_cluster", {"cluster": "eu-1"}, risk="critical", summary="restart")
    with pytest.raises(Forbidden, match="editing"):
        await inbox.vote(v["id"], await reviewer(inbox, "eve@example.com"), "approve", args={"cluster": "us-1"})


async def test_expiry_and_escalation(inbox):
    v = await inbox.submit("ops-bot", "restart_cluster", {"cluster": "eu-1"}, risk="critical", summary="restart")
    async with inbox.db.tx() as cur:
        await cur.execute("update requests set escalate_at = now() - interval '1 second' where id = %s", (v["id"],))
    assert (await inbox.sweep())["escalated"] == 1
    assert (await inbox.get(v["id"]))["escalated"]
    w = await refund(inbox, 300)
    async with inbox.db.tx() as cur:
        await cur.execute("update requests set expires_at = now() - interval '1 second' where id = %s", (w["id"],))
    with pytest.raises(Conflict, match="expired"):
        await inbox.vote(w["id"], await reviewer(inbox, "cy@example.com"), "approve")
    assert (await inbox.get(w["id"]))["status"] == "expired"


async def test_idempotent_submit(inbox):
    a = await refund(inbox, 300, idempotency_key="refund-A-1001-try")
    b = await refund(inbox, 300, idempotency_key="refund-A-1001-try")
    assert a["id"] == b["id"]
    with pytest.raises(Conflict, match="different arguments"):
        await refund(inbox, 999, idempotency_key="refund-A-1001-try")


async def test_cancel_and_ownership(inbox):
    v = await refund(inbox, 300)
    with pytest.raises(NotFound):
        await inbox.get(v["id"], "ops-bot")
    with pytest.raises(NotFound):
        await inbox.cancel(v["id"], "ops-bot")
    assert (await inbox.cancel(v["id"], "refund-bot"))["status"] == "cancelled"
    with pytest.raises(Conflict):
        await inbox.cancel(v["id"], "refund-bot")


async def test_wait_returns_as_soon_as_someone_decides(inbox):
    v = await refund(inbox, 300)
    cy = await reviewer(inbox, "cy@example.com")

    async def decide_later():
        await asyncio.sleep(0.4)
        await inbox.vote(v["id"], cy, "approve")

    t0 = asyncio.get_running_loop().time()
    task = asyncio.create_task(decide_later())
    out = await inbox.wait(v["id"], "refund-bot", timeout=10)
    elapsed = asyncio.get_running_loop().time() - t0
    await task
    assert out["status"] == "approved" and 0.3 < elapsed < 3
    still = await inbox.wait((await refund(inbox, 301))["id"], "refund-bot", timeout=0.3)
    assert still["status"] == "pending"


async def test_concurrent_votes_count_once_each(inbox):
    v = await refund(inbox, 5000)
    ana, ben = [await reviewer(inbox, r) for r in ("ana@example.com", "ben@example.com")]
    results = await asyncio.gather(
        inbox.vote(v["id"], ana, "approve"),
        inbox.vote(v["id"], ben, "approve"),
        inbox.vote(v["id"], ana, "approve"),
        return_exceptions=True,
    )
    assert sum(isinstance(r, Conflict) for r in results) == 1
    final = await inbox.get(v["id"])
    assert final["status"] == "approved" and len(final["votes"]) == 2
    async with inbox.db.tx() as cur:
        await cur.execute("select count(*) as n from grants where request_id = %s", (v["id"],))
        assert (await cur.fetchone())["n"] == 1


async def test_inbox_lists_what_i_can_act_on(inbox):
    await refund(inbox, 300)
    await refund(inbox, 5000)
    cy = await reviewer(inbox, "cy@example.com")
    ana = await reviewer(inbox, "ana@example.com")
    assert [v["rule"] for v in await inbox.inbox(cy)] == ["refunds"]
    assert sorted(v["rule"] for v in await inbox.inbox(ana)) == ["large-refunds", "refunds"]


async def test_audit_chain_is_intact_and_tamper_evident(inbox):
    v = await refund(inbox, 5000)
    await inbox.vote(v["id"], await reviewer(inbox, "ana@example.com"), "approve")
    async with inbox.db.tx() as cur:
        ok, n, bad = await verify_chain(cur)
    assert ok and n >= 2 and bad is None
    async with inbox.db.tx() as cur:
        with pytest.raises(Exception, match="append-only"):
            await cur.execute("update events set actor = 'someone-else' where request_id = %s", (v["id"],))
    # An attacker with table-owner rights disables the trigger and edits a row: the chain shows it.
    async with inbox.db.tx() as cur:
        await cur.execute("alter table events disable trigger events_no_update")
        await cur.execute(
            "update events set data = data || '{\"decision\": \"reject\"}' where type = 'voted' and request_id = %s", (v["id"],)
        )
        await cur.execute("alter table events enable trigger events_no_update")
        ok, _, bad = await verify_chain(cur)
        assert not ok and bad is not None
        await cur.execute("alter table events disable trigger events_no_update")
        await cur.execute("delete from events")
        await cur.execute("alter table events enable trigger events_no_update")
    _ = dt
