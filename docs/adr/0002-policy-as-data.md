# 2. Policy as a reviewed file: first match wins

Status: accepted

## Context

Which actions need a human is a business decision that changes more often than code, and must be reviewable by people who do not read Python.

## Decision

- `policy.yaml` holds ordered rules. Each matches on the action (glob), agent (glob), declared risk, and conditions on arguments (`gt`, `lte`, `eq`, `in`, `exists`...). The first match decides: auto-approve, auto-deny, or review by N approvers from groups, with an expiry, an optional escalation, notification targets and whether edits are allowed.
- Unknown keys are errors, so `aprovals: 2` fails loudly instead of meaning 1.
- `hitl check-policy --action ... --args ...` shows which rule a request would hit; CI validates the shipped file.
- The agent declares a risk, but the policy can require review regardless of it by matching on action and arguments.

## Consequences

Rules are evaluated in order, so a broad rule placed early shadows narrower ones. The check command makes that visible.
