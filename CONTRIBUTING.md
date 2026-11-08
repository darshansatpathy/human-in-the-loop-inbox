# Contributing

You need PostgreSQL 16 or 17. `make db` starts one in Docker and prints the variable to export.

```bash
python -m venv .venv && . .venv/bin/activate
make install
export HITL_TEST_ADMIN_URL=postgresql://postgres:postgres@localhost:5432/postgres
make check
```

Tests run against a throwaway database, a local SMTP server (aiosmtpd) and mocked Slack and webhook endpoints.

## Changing the workflow

Each guarantee in `docs/guarantees.md` has a test. If you change behaviour, change or add the test and the row. Never weaken a guarantee silently.

## Changing the policy format

Keep unknown keys an error. Add cases to `tests/test_policy_and_security.py::test_rules`.

## Commits

Small, focused commits with messages in the imperative. Update `CHANGELOG.md` for anything a user would notice.
