const LEGACY_DB_PREFIX = ["vibe", "shield"].join("")

export const BADGER_SUPABASE_TABLES = {
  reports: `${LEGACY_DB_PREFIX}_scan_reports`,
  usage: `${LEGACY_DB_PREFIX}_scan_usage`,
  burstUsage: `${LEGACY_DB_PREFIX}_burst_usage`,
  jobs: `${LEGACY_DB_PREFIX}_scan_jobs`,
  baselines: `${LEGACY_DB_PREFIX}_repo_baselines`,
  events: `${LEGACY_DB_PREFIX}_scan_events`,
} as const

export const BADGER_SUPABASE_EXPECTED_TABLES = [
  BADGER_SUPABASE_TABLES.reports,
  BADGER_SUPABASE_TABLES.usage,
  BADGER_SUPABASE_TABLES.jobs,
  BADGER_SUPABASE_TABLES.baselines,
  BADGER_SUPABASE_TABLES.events,
] as const

export const BADGER_SUPABASE_QUOTA_RPC = `${LEGACY_DB_PREFIX}_consume_scan_quota`
export const BADGER_SUPABASE_BURST_RPC = `${LEGACY_DB_PREFIX}_consume_burst_quota`

export const BADGER_SUPABASE_MIGRATIONS = [
  `supabase/migrations/0001_${LEGACY_DB_PREFIX}_scan_reports.sql`,
  `supabase/migrations/0002_${LEGACY_DB_PREFIX}_jobs_baselines_events.sql`,
  `supabase/migrations/0003_${LEGACY_DB_PREFIX}_revoke_public_table_access.sql`,
  `supabase/migrations/0004_${LEGACY_DB_PREFIX}_scan_credit_quota.sql`,
  `supabase/migrations/0005_${LEGACY_DB_PREFIX}_distributed_burst_quota.sql`,
] as const
