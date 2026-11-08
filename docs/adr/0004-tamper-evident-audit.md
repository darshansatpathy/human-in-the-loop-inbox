# 4. A hash-chained, append-only audit log

Status: accepted

## Context

After an incident, the first question is who approved what, when, through which channel, and whether the record can be trusted.

## Decision

- Every state change appends an event: submitted, voted (with the arguments hash the reviewer saw and the channel), edited, escalated, expired, cancelled, executed.
- A trigger refuses `update` and `delete` on the events table.
- Each event's hash covers the previous event's hash and its own content. A transaction-scoped advisory lock serialises appends so the chain never forks. `hitl verify-audit` and `GET /v1/audit/verify` recompute the chain and report the first altered event.

## Consequences

Serialised appends cap event throughput; `docs/performance.md` measures it. Someone with superuser rights can still rewrite the whole chain from the altered event onward; exporting the latest hash to another system (a log store, a ticket) on a schedule closes that gap.
