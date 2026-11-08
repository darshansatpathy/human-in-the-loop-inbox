# Guarantees and the tests that hold them

Each property below is checked by a test that would fail if it broke.

| Guarantee | Test |
|---|---|
| An approval is bound to the action and its exact arguments; a grant for 20 cannot pay out 2,000, or run another action | `test_workflow.py::test_grant_is_bound_to_the_exact_arguments` |
| A grant works once; a replay is refused | `test_workflow.py::test_auto_approve_issues_a_grant_that_works_once`, `test_api.py::test_submit_review_wait_and_execute` |
| A grant signed with another key is refused | `test_workflow.py::test_grant_is_bound_to_the_exact_arguments` |
| The person an agent acts for cannot approve it | `test_workflow.py::test_two_person_rule_with_separation_of_duties` |
| Only the rule's approver groups (or escalation groups, once escalated) can vote | same, and `test_expiry_and_escalation` |
| Two-person rules need two different people; one reviewer voting twice counts once | `test_quorum_approves_and_any_reject_vetoes`, `test_concurrent_votes_count_once_each` |
| Votes that race are serialised; exactly one grant is issued | `test_concurrent_votes_count_once_each` |
| Any rejection vetoes | `test_quorum_approves_and_any_reject_vetoes` |
| Editing the arguments invalidates approvals given for the old ones, and a vote on a stale view is refused | `test_edit_resets_the_quorum_to_the_new_arguments` |
| Rules can forbid edits | `test_critical_rule_forbids_edits` |
| Nothing is approved after it expires | `test_expiry_and_escalation` |
| A retried submission with the same idempotency key returns the same request; with different arguments it is refused | `test_idempotent_submit` |
| An agent sees and cancels only its own requests | `test_cancel_and_ownership` |
| A long-polling agent wakes as soon as a decision lands (LISTEN/NOTIFY) | `test_wait_returns_as_soon_as_someone_decides` |
| Opening an email link changes nothing; only the confirmation POST decides (mail scanners prefetch links) | `test_api.py::test_email_link_get_does_not_decide_post_does` |
| Slack requests with a bad or old signature are refused; a retried delivery does not double-vote | `test_api.py::test_slack_button` |
| Email links are signed, for one reviewer, one request, one decision and the arguments they saw | `test_adapters.py::test_email_links_carry_signed_single_purpose_tokens` |
| The person a request is on behalf of is not emailed to approve it | same |
| Notifications survive outages: retried with backoff, then dead-lettered after 8 attempts | `test_outbox_retries_with_backoff_then_dead_letters` |
| Webhooks are signed over the timestamp and body | `test_signed_webhook_on_decision` |
| The audit log refuses updates and deletes, and an edit made by bypassing that is detected by the hash chain | `test_audit_chain_is_intact_and_tamper_evident` |
| Policy files with unknown keys are refused, so a typo cannot silently weaken a rule | `test_policy_and_security.py::test_unknown_policy_keys_are_refused` |
