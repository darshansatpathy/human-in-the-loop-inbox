# 1. Approval produces a single-use grant bound to the exact arguments

Status: accepted

## Context

An approval that only says "yes" can be misused by the agent that asked for it: it can run the action with different arguments, run it twice, or run a different action. The agent is the party under review, so it cannot also be the party that enforces the decision.

## Decision

- Approval issues a grant: an HMAC-signed token naming the request, the action and a SHA-256 of the canonical JSON of the arguments, with a 15-minute expiry and a unique id.
- The tool executor, not the agent, calls `POST /v1/grants/consume` with the grant, the action and the arguments it is about to use. The service checks the signature, the action, the hash and the expiry, and marks the grant used in the same statement (`update ... where used_at is null`). A second call fails.
- Auto-approved requests get grants too, so the executor's check is the same for every action.

## Consequences

The executor must be wired to check grants. That is the point of control: an agent that skips the inbox gets nothing the executor will accept.
