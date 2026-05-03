alter table public.vibeshield_scan_reports
  add column if not exists job_id text;

alter table public.vibeshield_scan_reports
  add column if not exists events_available boolean not null default false;

create table if not exists public.vibeshield_scan_jobs (
  id text primary key,
  report_id text not null,
  owner_hash text,
  created_at timestamptz not null,
  updated_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  status text not null check (status in ('queued', 'running', 'completed', 'failed')),
  source_label text not null,
  analysis_mode text not null check (analysis_mode in ('rules', 'normal', 'max')),
  attempts integer not null default 0 check (attempts >= 0),
  error text,
  job jsonb not null
);

alter table public.vibeshield_scan_jobs
  add column if not exists owner_hash text;

alter table public.vibeshield_scan_jobs
  add column if not exists started_at timestamptz;

alter table public.vibeshield_scan_jobs
  add column if not exists completed_at timestamptz;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_scan_jobs_owner_hash_shape'
      and conrelid = 'public.vibeshield_scan_jobs'::regclass
  ) then
    alter table public.vibeshield_scan_jobs
      add constraint vibeshield_scan_jobs_owner_hash_shape
      check (owner_hash is null or owner_hash ~ '^[a-f0-9]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_scan_jobs_job_object'
      and conrelid = 'public.vibeshield_scan_jobs'::regclass
  ) then
    alter table public.vibeshield_scan_jobs
      add constraint vibeshield_scan_jobs_job_object
      check (jsonb_typeof(job) = 'object');
  end if;
end
$$;

alter table public.vibeshield_scan_jobs enable row level security;
alter table public.vibeshield_scan_jobs force row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'vibeshield_scan_jobs'
      and policyname = 'vibeshield_scan_jobs_deny_client_access'
  ) then
    create policy vibeshield_scan_jobs_deny_client_access
      on public.vibeshield_scan_jobs
      for all
      to anon, authenticated
      using (false)
      with check (false);
  end if;
end
$$;

revoke all on table public.vibeshield_scan_jobs from anon;
revoke all on table public.vibeshield_scan_jobs from authenticated;
grant select, insert, update, delete on table public.vibeshield_scan_jobs to service_role;

create index if not exists vibeshield_scan_jobs_status_created_at_idx
  on public.vibeshield_scan_jobs (status, created_at asc);

create index if not exists vibeshield_scan_jobs_report_id_idx
  on public.vibeshield_scan_jobs (report_id);

create index if not exists vibeshield_scan_jobs_owner_hash_created_at_idx
  on public.vibeshield_scan_jobs (owner_hash, created_at desc);

comment on table public.vibeshield_scan_jobs is
  'Durable Badger scan job queue. Client roles are denied by RLS; route handlers and workers use the Supabase service role only.';

create table if not exists public.vibeshield_repo_baselines (
  id text primary key,
  created_at timestamptz not null,
  updated_at timestamptz not null default now(),
  owner_hash text,
  source_label text not null,
  baseline jsonb not null
);

alter table public.vibeshield_repo_baselines
  add column if not exists owner_hash text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_repo_baselines_owner_hash_shape'
      and conrelid = 'public.vibeshield_repo_baselines'::regclass
  ) then
    alter table public.vibeshield_repo_baselines
      add constraint vibeshield_repo_baselines_owner_hash_shape
      check (owner_hash is null or owner_hash ~ '^[a-f0-9]{64}$');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_repo_baselines_baseline_object'
      and conrelid = 'public.vibeshield_repo_baselines'::regclass
  ) then
    alter table public.vibeshield_repo_baselines
      add constraint vibeshield_repo_baselines_baseline_object
      check (jsonb_typeof(baseline) = 'object');
  end if;
end
$$;

alter table public.vibeshield_repo_baselines enable row level security;
alter table public.vibeshield_repo_baselines force row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'vibeshield_repo_baselines'
      and policyname = 'vibeshield_repo_baselines_deny_client_access'
  ) then
    create policy vibeshield_repo_baselines_deny_client_access
      on public.vibeshield_repo_baselines
      for all
      to anon, authenticated
      using (false)
      with check (false);
  end if;
end
$$;

revoke all on table public.vibeshield_repo_baselines from anon;
revoke all on table public.vibeshield_repo_baselines from authenticated;
grant select, insert, update, delete on table public.vibeshield_repo_baselines to service_role;

create index if not exists vibeshield_repo_baselines_owner_hash_source_idx
  on public.vibeshield_repo_baselines (owner_hash, source_label);

create index if not exists vibeshield_repo_baselines_updated_at_idx
  on public.vibeshield_repo_baselines (updated_at desc);

comment on table public.vibeshield_repo_baselines is
  'Per-repository finding baselines. Baselines store stable fingerprints, not repository secrets.';

create table if not exists public.vibeshield_scan_events (
  id text primary key,
  report_id text not null,
  job_id text,
  created_at timestamptz not null,
  label text not null,
  status text not null check (status in ('complete', 'running', 'failed')),
  metadata jsonb not null default '{}'::jsonb,
  event jsonb not null
);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_scan_events_metadata_object'
      and conrelid = 'public.vibeshield_scan_events'::regclass
  ) then
    alter table public.vibeshield_scan_events
      add constraint vibeshield_scan_events_metadata_object
      check (jsonb_typeof(metadata) = 'object');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_scan_events_event_object'
      and conrelid = 'public.vibeshield_scan_events'::regclass
  ) then
    alter table public.vibeshield_scan_events
      add constraint vibeshield_scan_events_event_object
      check (jsonb_typeof(event) = 'object');
  end if;
end
$$;

alter table public.vibeshield_scan_events enable row level security;
alter table public.vibeshield_scan_events force row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'vibeshield_scan_events'
      and policyname = 'vibeshield_scan_events_deny_client_access'
  ) then
    create policy vibeshield_scan_events_deny_client_access
      on public.vibeshield_scan_events
      for all
      to anon, authenticated
      using (false)
      with check (false);
  end if;
end
$$;

revoke all on table public.vibeshield_scan_events from anon;
revoke all on table public.vibeshield_scan_events from authenticated;
grant select, insert, update, delete on table public.vibeshield_scan_events to service_role;

create index if not exists vibeshield_scan_events_report_created_at_idx
  on public.vibeshield_scan_events (report_id, created_at asc);

create index if not exists vibeshield_scan_events_job_created_at_idx
  on public.vibeshield_scan_events (job_id, created_at asc);

comment on table public.vibeshield_scan_events is
  'Structured Badger scan lifecycle events. Events must be written server-side only.';
