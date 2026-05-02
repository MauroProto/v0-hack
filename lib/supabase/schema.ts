export const VIBESHIELD_SUPABASE_TABLES = {
  reports: "vibeshield_scan_reports",
  usage: "vibeshield_scan_usage",
  jobs: "vibeshield_scan_jobs",
  baselines: "vibeshield_repo_baselines",
  events: "vibeshield_scan_events",
} as const

export const VIBESHIELD_SUPABASE_EXPECTED_TABLES = [
  VIBESHIELD_SUPABASE_TABLES.reports,
  VIBESHIELD_SUPABASE_TABLES.usage,
  VIBESHIELD_SUPABASE_TABLES.jobs,
  VIBESHIELD_SUPABASE_TABLES.baselines,
  VIBESHIELD_SUPABASE_TABLES.events,
] as const

export const VIBESHIELD_SUPABASE_QUOTA_RPC = "vibeshield_consume_scan_quota"

export const VIBESHIELD_SUPABASE_MIGRATIONS = [
  "supabase/migrations/0001_vibeshield_scan_reports.sql",
  "supabase/migrations/0002_vibeshield_jobs_baselines_events.sql",
  "supabase/migrations/0003_vibeshield_revoke_public_table_access.sql",
] as const
