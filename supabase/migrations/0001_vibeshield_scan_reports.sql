create table if not exists public.vibeshield_scan_reports (
  id text primary key,
  created_at timestamptz not null,
  updated_at timestamptz not null default now(),
  owner_hash text,
  project_name text not null,
  source_type text not null check (source_type in ('github')),
  source_label text not null,
  status text not null check (status in ('queued', 'running', 'completed', 'failed')),
  risk_score integer not null check (risk_score >= 0 and risk_score <= 100),
  report jsonb not null
);

alter table public.vibeshield_scan_reports
  add column if not exists owner_hash text;

alter table public.vibeshield_scan_reports enable row level security;

revoke all on table public.vibeshield_scan_reports from anon;
revoke all on table public.vibeshield_scan_reports from authenticated;

create index if not exists vibeshield_scan_reports_created_at_idx
  on public.vibeshield_scan_reports (created_at desc);

create index if not exists vibeshield_scan_reports_owner_hash_created_at_idx
  on public.vibeshield_scan_reports (owner_hash, created_at desc);

create index if not exists vibeshield_scan_reports_risk_score_idx
  on public.vibeshield_scan_reports (risk_score desc);

create index if not exists vibeshield_scan_reports_source_type_idx
  on public.vibeshield_scan_reports (source_type);

comment on table public.vibeshield_scan_reports is
  'VibeShield MVP scan reports. RLS is enabled and no public policies are defined; Next.js route handlers access it with the Supabase service role key only.';

create table if not exists public.vibeshield_scan_usage (
  subject_hash text not null,
  window_start date not null,
  scan_count integer not null default 0 check (scan_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (subject_hash, window_start)
);

alter table public.vibeshield_scan_usage enable row level security;

revoke all on table public.vibeshield_scan_usage from anon;
revoke all on table public.vibeshield_scan_usage from authenticated;

create index if not exists vibeshield_scan_usage_updated_at_idx
  on public.vibeshield_scan_usage (updated_at desc);

create or replace function public.vibeshield_consume_scan_quota(
  p_subject_hash text,
  p_window_start date,
  p_limit integer
)
returns table (
  allowed boolean,
  remaining integer,
  scan_count integer
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scan_count integer;
begin
  if p_subject_hash is null or length(p_subject_hash) < 16 then
    raise exception 'invalid subject hash';
  end if;

  if p_limit is null or p_limit < 1 or p_limit > 1000 then
    raise exception 'invalid quota limit';
  end if;

  insert into public.vibeshield_scan_usage as target (
    subject_hash,
    window_start,
    scan_count,
    updated_at
  )
  values (
    p_subject_hash,
    p_window_start,
    1,
    now()
  )
  on conflict (subject_hash, window_start)
  do update
    set scan_count = target.scan_count + 1,
        updated_at = now()
    where target.scan_count < p_limit
  returning target.scan_count into v_scan_count;

  if v_scan_count is null then
    select quota.scan_count
      into v_scan_count
      from public.vibeshield_scan_usage as quota
      where quota.subject_hash = p_subject_hash
        and quota.window_start = p_window_start;

    return query select false, 0, coalesce(v_scan_count, p_limit);
    return;
  end if;

  return query select true, greatest(p_limit - v_scan_count, 0), v_scan_count;
end;
$$;

revoke all on function public.vibeshield_consume_scan_quota(text, date, integer) from public;
revoke all on function public.vibeshield_consume_scan_quota(text, date, integer) from anon;
revoke all on function public.vibeshield_consume_scan_quota(text, date, integer) from authenticated;
grant execute on function public.vibeshield_consume_scan_quota(text, date, integer) to service_role;

comment on table public.vibeshield_scan_usage is
  'Per-user scan quota counters. Subjects are salted hashes, not raw IP addresses or emails.';
