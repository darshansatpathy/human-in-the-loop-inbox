from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry()
SUBMITTED = Counter("hitl_requests_total", "Requests by rule and initial outcome", ["rule", "status"], registry=REGISTRY)
DECIDED = Counter("hitl_decisions_total", "Decisions by outcome", ["status"], registry=REGISTRY)
VOTES = Counter("hitl_votes_total", "Votes by channel and decision", ["via", "decision"], registry=REGISTRY)
GRANTS = Counter("hitl_grant_checks_total", "Grant checks by outcome", ["outcome"], registry=REGISTRY)
TIME_TO_DECISION = Histogram(
    "hitl_time_to_decision_seconds",
    "From submission to a human decision",
    buckets=(10, 30, 60, 120, 300, 600, 1800, 3600, 7200),
    registry=REGISTRY,
)
