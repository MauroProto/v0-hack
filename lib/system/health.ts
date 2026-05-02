import { backgroundJobsEnabled } from "@/lib/scanner/jobs"
import { getStorageMode } from "@/lib/scanner/store"
import { isSupabaseConfigured } from "@/lib/supabase/config"
import { isGitHubAppConfigured } from "@/lib/utils/github-app-config"
import {
  getProductionReadiness,
  isAiConfigured,
  isGitHubOAuthConfigured,
  isPrSafetyReviewConfigured,
} from "./readiness"

type SystemHealthOptions = {
  publicView?: boolean
}

type PublicSystemHealth = {
  ok: boolean
  productionReady: boolean
  status: "ready" | "not_ready"
}

type DetailedSystemHealth = {
  ok: boolean
  productionReady: boolean
  supabaseConfigured: boolean
  storageMode: string
  persistentQuotaRequired: boolean
  persistentStorageRequired: boolean
  aiConfigured: boolean
  prSafetyReviewConfigured: boolean
  githubOAuthConfigured: boolean
  githubAppConfigured: boolean
  osvEnabled: boolean
  backgroundJobsEnabled: boolean
  blockingChecks: string[]
  warningChecks: string[]
}

export function getSystemHealth(): DetailedSystemHealth
export function getSystemHealth(options: { publicView?: false }): DetailedSystemHealth
export function getSystemHealth(options: { publicView: true }): DetailedSystemHealth | PublicSystemHealth
export function getSystemHealth(options: SystemHealthOptions = {}): DetailedSystemHealth | PublicSystemHealth {
  const readiness = getProductionReadiness()
  const detailed = shouldExposeDetailedHealth(options.publicView)

  const base = {
    ok: detailed ? true : readiness.ready,
    productionReady: readiness.ready,
  }

  if (!detailed) {
    const status: PublicSystemHealth["status"] = readiness.ready ? "ready" : "not_ready"

    return {
      ...base,
      status,
    }
  }

  return {
    ...base,
    supabaseConfigured: isSupabaseConfigured(),
    storageMode: getStorageMode(),
    persistentQuotaRequired: persistentEnvEnabled("VIBESHIELD_REQUIRE_PERSISTENT_QUOTA"),
    persistentStorageRequired: persistentEnvEnabled("VIBESHIELD_REQUIRE_PERSISTENT_STORAGE"),
    aiConfigured: isAiConfigured(),
    prSafetyReviewConfigured: isPrSafetyReviewConfigured(),
    githubOAuthConfigured: isGitHubOAuthConfigured(),
    githubAppConfigured: isGitHubAppConfigured(),
    osvEnabled: process.env.VIBESHIELD_ENABLE_OSV !== "false",
    backgroundJobsEnabled: backgroundJobsEnabled(),
    blockingChecks: readiness.blockingChecks,
    warningChecks: readiness.warningChecks,
  }
}

function shouldExposeDetailedHealth(publicView?: boolean) {
  if (!publicView) return true
  if (process.env.VIBESHIELD_PUBLIC_HEALTH_DETAILS === "true") return true
  return process.env.NODE_ENV !== "production" && process.env.VERCEL !== "1"
}

function persistentEnvEnabled(name: string) {
  const value = process.env[name]?.trim().toLowerCase()
  if (value === "true") return true
  if (value === "false") return false
  return process.env.NODE_ENV === "production"
}
