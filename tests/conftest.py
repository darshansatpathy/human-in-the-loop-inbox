from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import psycopg
import pytest

from hitl import db as dbm
from hitl.policy import Policy
from hitl.service import Inbox, Settings

ADMIN = os.environ.get("HITL_TEST_ADMIN_URL", "postgresql://postgres@localhost:5432/postgres")
ROOT = Path(__file__).resolve().parents[1]
KEY = b"test-signing-key-0123456789abcdef"


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    name = f"hitl_test_{uuid.uuid4().hex[:8]}"
    try:
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute(f"create database {name}")
    except psycopg.OperationalError as e:
        pytest.skip(f"no PostgreSQL at HITL_TEST_ADMIN_URL: {e}")
    url = psycopg.conninfo.make_conninfo(ADMIN, dbname=name)
    dbm.migrate(url)
    yield url
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute(f"drop database {name} with (force)")


@pytest.fixture
async def inbox(database_url: str) -> AsyncIterator[Inbox]:
    d = dbm.Database(database_url, min_size=1, max_size=6)
    await d.open()
    i = Inbox(d, Policy.load(ROOT / "policy.yaml"), Settings(KEY, "http://inbox.test"))
    await i.add_agent("refund-bot")
    await i.add_agent("ops-bot")
    i.reviewers = {  # type: ignore[attr-defined]
        rid: await i.add_reviewer(rid, name, groups, email, slack)
        for rid, name, groups, email, slack in [
            ("ana@example.com", "Ana", ["finance"], "ana@example.com", "U_ANA"),
            ("ben@example.com", "Ben", ["finance"], "ben@example.com", "U_BEN"),
            ("cy@example.com", "Cy", ["support-leads"], "cy@example.com", "U_CY"),
            ("dee@example.com", "Dee", ["finance-leads"], "dee@example.com", None),
            ("eve@example.com", "Eve", ["default", "oncall"], None, None),
            ("fay@example.com", "Fay", ["oncall"], None, None),
        ]
    }
    yield i
    async with d.tx() as cur:
        await cur.execute("truncate votes, grants, outbox, slack_messages, requests cascade")
    await d.close()


async def reviewer(inbox: Inbox, rid: str) -> dict:
    r = await inbox.reviewer_for(rid=rid)
    assert r is not None
    return r
