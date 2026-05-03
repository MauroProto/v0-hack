create or replace function public.vibeshield_consume_scan_quota(
  p_subject_hash text,
  p_window_start date,
  p_limit integer,
  p_cost integer default 1
)
returns table (
  allowed boolean,
  remaining integer,
  scan_count integer
)
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_scan_count integer;
  v_cost integer;
begin
  if p_subject_hash is null or length(p_subject_hash) < 16 then
    raise exception 'invalid subject hash';
  end if;

  if p_limit is null or p_limit < 1 or p_limit > 1000 then
    raise exception 'invalid quota limit';
  end if;

  v_cost := greatest(1, least(coalesce(p_cost, 1), 10));

  if v_cost > p_limit then
    return query select false, 0, 0;
    return;
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
    v_cost,
    now()
  )
  on conflict (subject_hash, window_start)
  do update
    set scan_count = target.scan_count + v_cost,
        updated_at = now()
    where target.scan_count + v_cost <= p_limit
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

revoke all on function public.vibeshield_consume_scan_quota(text, date, integer, integer) from public;
revoke all on function public.vibeshield_consume_scan_quota(text, date, integer, integer) from anon;
revoke all on function public.vibeshield_consume_scan_quota(text, date, integer, integer) from authenticated;
grant execute on function public.vibeshield_consume_scan_quota(text, date, integer, integer) to service_role;

comment on table public.vibeshield_scan_usage is
  'Per-user monthly scan credit counters. window_start is the first UTC day of the month. Subjects are salted hashes, not raw IP addresses or emails.';
