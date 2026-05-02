revoke all on table public.vibeshield_scan_reports from public;
revoke all on table public.vibeshield_scan_reports from anon;
revoke all on table public.vibeshield_scan_reports from authenticated;

revoke all on table public.vibeshield_scan_usage from public;
revoke all on table public.vibeshield_scan_usage from anon;
revoke all on table public.vibeshield_scan_usage from authenticated;

revoke all on table public.vibeshield_scan_jobs from public;
revoke all on table public.vibeshield_scan_jobs from anon;
revoke all on table public.vibeshield_scan_jobs from authenticated;

revoke all on table public.vibeshield_repo_baselines from public;
revoke all on table public.vibeshield_repo_baselines from anon;
revoke all on table public.vibeshield_repo_baselines from authenticated;

revoke all on table public.vibeshield_scan_events from public;
revoke all on table public.vibeshield_scan_events from anon;
revoke all on table public.vibeshield_scan_events from authenticated;

grant select, insert, update, delete on table public.vibeshield_scan_reports to service_role;
grant select, insert, update, delete on table public.vibeshield_scan_usage to service_role;
grant select, insert, update, delete on table public.vibeshield_scan_jobs to service_role;
grant select, insert, update, delete on table public.vibeshield_repo_baselines to service_role;
grant select, insert, update, delete on table public.vibeshield_scan_events to service_role;
