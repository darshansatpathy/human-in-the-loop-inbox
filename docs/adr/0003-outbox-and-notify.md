# 3. Transactional outbox for notifications; LISTEN/NOTIFY for waiting agents

Status: accepted

## Context

A decision must reach people (Slack, email) and agents (webhooks, waiting requests). Sending inside the request handler loses messages when Slack is down and sends messages for decisions that later roll back.

## Decision

- Every notification is a row in `outbox`, written in the same transaction as the state change. A dispatcher claims due rows with `for update skip locked` (several can run), delivers each inside a savepoint, and on failure retries with exponential backoff and jitter, up to 8 attempts, then marks the row dead with the last error.
- Slack messages are updated in place when the request is decided, so the buttons disappear.
- Agents can long-poll `GET /v1/requests/{id}/wait`. The service issues `pg_notify` on every decision; waiters `LISTEN` and re-check after subscribing, so a decision between the first check and the subscription is not missed.
- Webhooks carry `x-hitl-signature: t=...,v1=HMAC(timestamp.body)`.

## Consequences

Delivery is at least once: a crash after sending and before marking done resends. Slack updates and webhook consumers must tolerate repeats; the request id makes that easy.
