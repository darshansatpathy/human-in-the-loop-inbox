# Changelog

## 0.1.0

- Approval requests from agents with idempotency keys, declared risk, context and the person acted for.
- Policy file: ordered rules on action, agent, risk and arguments; auto-approve, auto-deny, or N approvers from groups with expiry, escalation, notifications and edit control.
- Quorum voting with separation of duties, veto on reject, edits that reset approvals, and stale-view protection.
- Single-use grants bound to the action and exact arguments, consumed by the executor.
- Slack messages with buttons (signed interactions, message updated on decision), email with signed links behind a confirmation page, signed webhooks; all through a transactional outbox with retries and dead-lettering.
- Long polling with LISTEN/NOTIFY.
- Hash-chained, append-only audit log with verification.
- FastAPI service, CLI, container, Compose stack with Mailpit, load test.
