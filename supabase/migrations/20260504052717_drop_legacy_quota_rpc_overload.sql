drop function if exists public.vibeshield_consume_scan_quota(text, date, integer);

comment on function public.vibeshield_consume_scan_quota(text, date, integer, integer) is
  'Consumes monthly scan credits atomically. Keep only this cost-aware signature so PostgREST can resolve RPC calls unambiguously.';
