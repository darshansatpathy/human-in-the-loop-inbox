-- Idempotent schema for the approval inbox.
create extension if not exists pgcrypto;

create table if not exists agents (
  name text primary key,
  key_hash text unique not null,
  created_at timestamptz not null default now()
);

create table if not exists reviewers (
  id text primary key,                     -- a stable person id, e.g. an email address
  name text not null,
  email text,
  slack_user text unique,                  -- Slack user id, for interactive approvals
  groups text[] not null default '{}',
  token_hash text unique,
  active boolean not null default true
);

create table if not exists requests (
  id uuid primary key default gen_random_uuid(),
  agent text not null references agents(name),
  action text not null,
  args jsonb not null,
  args_hash text not null,                 -- the arguments currently proposed (changes when a reviewer edits)
  risk text not null,
  summary text not null,
  context jsonb not null default '{}',
  on_behalf_of text,                       -- the person the agent acts for; they may not approve it
  status text not null check (status in ('pending', 'approved', 'rejected', 'expired', 'cancelled', 'executed')),
  rule text not null,
  required_approvals int not null,
  approver_groups text[] not null,
  allow_edits boolean not null,
  idempotency_key text,
  callback_url text,
  notify text[] not null default '{}',
  escalate_at timestamptz,
  escalate_to text[] not null default '{}',
  escalated_at timestamptz,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_at timestamptz,
  decision_reason text,
  unique (agent, idempotency_key)
);
create index if not exists requests_pending on requests (expires_at) where status = 'pending';

create table if not exists votes (
  request_id uuid not null references requests(id),
  reviewer text not null references reviewers(id),
  decision text not null check (decision in ('approve', 'reject')),
  args_hash text not null,                 -- what this reviewer saw and approved
  comment text not null default '',
  via text not null,                       -- api, web, slack, email
  at timestamptz not null default now(),
  primary key (request_id, reviewer)
);

create table if not exists grants (
  jti text primary key,
  request_id uuid not null references requests(id),
  action text not null,
  args_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz
);

-- Tamper-evident log: each event's hash covers the previous one.
create table if not exists events (
  seq bigserial primary key,
  request_id uuid,
  type text not null,
  actor text not null,
  data jsonb not null default '{}',
  at timestamptz not null default now(),
  prev_hash text not null,
  hash text not null
);

create table if not exists outbox (
  id bigserial primary key,
  kind text not null check (kind in ('slack', 'slack_update', 'email', 'webhook')),
  request_id uuid,
  payload jsonb not null,
  attempts int not null default 0,
  next_at timestamptz not null default now(),
  done_at timestamptz,
  dead_at timestamptz,
  last_error text
);
create index if not exists outbox_due on outbox (next_at) where done_at is null and dead_at is null;

create table if not exists slack_messages (
  request_id uuid not null references requests(id),
  channel text not null,
  ts text not null,
  primary key (request_id, channel)
);

-- Append-only: the application role may insert events but never change or remove them.
create or replace function events_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'events are append-only';
end $$;
drop trigger if exists events_no_update on events;
create trigger events_no_update before update or delete on events for each row execute function events_append_only();
