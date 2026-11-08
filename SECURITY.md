# Security policy

Report a vulnerability privately through [GitHub security advisories](https://github.com/darshansatpathy/human-in-the-loop-inbox/security/advisories/new). Please do not open a public issue. You can expect a first reply within five working days.

## In scope

- An action being executed without a valid, unused grant for its exact arguments.
- A vote counted from someone outside the rule's groups, from the person the request is on behalf of, twice from one person, or after expiry.
- Forging or replaying email links, Slack interactions, grants or webhook signatures.
- Changing the audit log without `verify-audit` detecting it.

## Operating notes

Set `HITL_SIGNING_KEY` to at least 32 random bytes and keep it secret; it signs grants, email links and webhooks. Agent keys and reviewer tokens are stored as SHA-256 hashes and shown once.

## Supported versions

The latest release receives fixes.
