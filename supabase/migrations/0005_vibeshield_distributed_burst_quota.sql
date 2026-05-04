create table if not exists public.vibeshield_burst_usage (
  subject_hash text not null,
  action text not null check (action in ('scan', 'explain', 'pull_request')),
  window_start timestamptz not null,
  request_count integer not null default 0 check (request_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (subject_hash, action, window_start)
);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'vibeshield_burst_usage_subject_hash_shape'
      and conrelid = 'public.vibeshield_burst_usage'::regclass
  ) then
    alter table public.vibeshield_burst_usage
      add constraint vibeshield_burst_usage_subject_hash_shape
      check (subject_hash ~ '^[a-f0-9]{64}$');
  end if;
end
$$;

alter table public.vibeshield_burst_usage enable row level security;
alter table public.vibeshield_burst_usage force row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'vibeshield_burst_usage'
      and policyname = 'vibeshield_burst_usage_deny_client_access'
  ) then
    create policy vibeshield_burst_usage_deny_client_access
      on public.vibeshield_burst_usage
      for all
      to anon, authenticated
      using (false)
      with check (false);
  end if;
end
$$;

revoke all on table public.vibeshield_burst_usage from public;
revoke all on table public.vibeshield_burst_usage from anon;
revoke all on table public.vibeshield_burst_usage from authenticated;
grant select, insert, update, delete on table public.vibeshield_burst_usage to service_role;

create index if not exists vibeshield_burst_usage_updated_at_idx
  on public.vibeshield_burst_usage (updated_at desc);

create or replace function public.vibeshield_consume_burst_quota(
  p_subject_hash text,
  p_action text,
  p_window_start timestamptz,
  p_limit integer,
  p_cost integer default 1
)
returns table (
  allowed boolean,
  remaining integer,
  request_count integer
)
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_request_count integer;
  v_cost integer;
begin
  if p_subject_hash is null or p_subject_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid subject hash';
  end if;

  if p_action not in ('scan', 'explain', 'pull_request') then
    raise exception 'invalid burst action';
  end if;

  if p_window_start is null then
    raise exception 'invalid burst window';
  end if;

  if p_limit is null or p_limit < 1 or p_limit > 1000 then
    raise exception 'invalid burst limit';
  end if;

  v_cost := greatest(1, least(coalesce(p_cost, 1), 10));

  insert into public.vibeshield_burst_usage as target (
    subject_hash,
    action,
    window_start,
    request_count,
    updated_at
  )
  values (
    p_subject_hash,
    p_action,
    p_window_start,
    v_cost,
    now()
  )
  on conflict (subject_hash, action, window_start)
  do update
    set request_count = target.request_count + v_cost,
        updated_at = now()
    where target.request_count + v_cost <= p_limit
  returning target.request_count into v_request_count;

  if v_request_count is null then
    select quota.request_count
      into v_request_count
      from public.vibeshield_burst_usage as quota
      where quota.subject_hash = p_subject_hash
        and quota.action = p_action
        and quota.window_start = p_window_start;

    return query select false, 0, coalesce(v_request_count, p_limit);
    return;
  end if;

  return query select true, greatest(p_limit - v_request_count, 0), v_request_count;
end;
$$;

revoke all on function public.vibeshield_consume_burst_quota(text, text, timestamptz, integer, integer) from public;
revoke all on function public.vibeshield_consume_burst_quota(text, text, timestamptz, integer, integer) from anon;
revoke all on function public.vibeshield_consume_burst_quota(text, text, timestamptz, integer, integer) from authenticated;
grant execute on function public.vibeshield_consume_burst_quota(text, text, timestamptz, integer, integer) to service_role;

comment on table public.vibeshield_burst_usage is
  'Short-window API burst counters. Subjects are salted hashes, not raw IP addresses or emails.';
