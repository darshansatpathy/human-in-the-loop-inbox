"""`hitl`: migrate, register agents and reviewers, check the policy, verify the audit log, serve."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypeVar

from hitl import __version__
from hitl.config import Settings

T = TypeVar("T")


async def _with_inbox(fn: Callable[[Any], Awaitable[T]]) -> T:
    from hitl.db import Database
    from hitl.policy import Policy
    from hitl.service import Inbox
    from hitl.service import Settings as S

    s = Settings()
    db = Database(s.database_url, min_size=1, max_size=2)
    await db.open()
    try:
        return await fn(
            Inbox(
                db, Policy.load(s.policy_file) if s.policy_file.exists() else Policy(rules=[]), S(s.signing_key.get_secret_value().encode())
            )
        )
    finally:
        await db.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hitl", description=__doc__)
    p.add_argument("--version", action="version", version=f"hitl {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    a = sub.add_parser("add-agent", help="register an agent and print its key (shown once)")
    a.add_argument("name")
    r = sub.add_parser("add-reviewer", help="register a reviewer and print their API token (shown once)")
    r.add_argument("id")
    r.add_argument("--name", required=True)
    r.add_argument("--groups", required=True, help="comma-separated")
    r.add_argument("--email")
    r.add_argument("--slack-user")
    c = sub.add_parser("check-policy", help="validate the policy file and show which rule a request would hit")
    c.add_argument("--file", default="policy.yaml")
    c.add_argument("--action")
    c.add_argument("--risk", default="medium")
    c.add_argument("--agent", default="any")
    c.add_argument("--args", default="{}")
    sub.add_parser("verify-audit", help="recompute the event hash chain; exit 1 if it was altered")
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        from hitl.db import migrate

        migrate(Settings().database_url)
        print("schema up to date")
    elif args.cmd == "add-agent":
        print(asyncio.run(_with_inbox(lambda i: i.add_agent(args.name))))
    elif args.cmd == "add-reviewer":
        groups = [g.strip() for g in args.groups.split(",") if g.strip()]
        print(asyncio.run(_with_inbox(lambda i: i.add_reviewer(args.id, args.name, groups, args.email, args.slack_user))))
    elif args.cmd == "check-policy":
        from hitl.policy import Policy

        pol = Policy.load(Path(args.file))
        print(f"{args.file}: {len(pol.rules)} rules, valid")
        if args.action:
            rule = pol.decide(args.agent, args.action, args.risk, json.loads(args.args))
            print(json.dumps({"rule": rule.name, "decision": rule.decision, "approvals": rule.approvals, "approvers": rule.approvers}))
    elif args.cmd == "verify-audit":
        from hitl.service import verify_chain

        async def check(i: Any) -> tuple[bool, int, int | None]:
            async with i.db.tx() as cur:
                return await verify_chain(cur)

        ok, n, bad = asyncio.run(_with_inbox(check))
        print(f"{n} events, " + ("chain intact" if ok else f"chain broken at event {bad}"))
        return 0 if ok else 1
    elif args.cmd == "serve":
        import uvicorn

        from hitl.api import create_app

        uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning", server_header=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
