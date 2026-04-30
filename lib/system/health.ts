import { backgroundJobsEnabled } from "@/lib/scanner/jobs"
import { getStorageMode } from "@/lib/scanner/store"
import { isSupabaseConfigured } from "@/lib/supabase/config"
import { isGitHubAppConfigured } from "@/lib/utils/github-app-config"

export function getSystemHealth() {
  return {
    ok: true,
    supabaseConfigured: isSupabaseConfigured(),
    storageMode: getStorageMode(),
    persistentQuotaRequired: persistentEnvEnabled("VIBESHIELD_REQUIRE_PERSISTENT_QUOTA"),
    persistentStorageRequired: persistentEnvEnabled("VIBESHIELD_REQUIRE_PERSISTENT_STORAGE"),
    aiConfigured: isAiConfigured(),
    githubOAuthConfigured: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && process.env.VIBESHIELD_GITHUB_SESSION_SECRET),
    githubAppConfigured: isGitHubAppConfigured(),
    osvEnabled: process.env.VIBESHIELD_ENABLE_OSV !== "false",
    backgroundJobsEnabled: backgroundJobsEnabled(),
  }
}

function isAiConfigured() {
  return Boolean(
    process.env.AI_GATEWAY_API_KEY ||
      process.env.VERCEL_OIDC_TOKEN ||
      process.env.ANTHROPIC_API_KEY ||
      process.env.CLAUDE_API_KEY ||
      process.env.DEEPSEEK_API_KEY,
  )
}

function persistentEnvEnabled(name: string) {
  const value = process.env[name]?.trim().toLowerCase()
  if (value === "true") return true
  if (value === "false") return false
  return process.env.NODE_ENV === "production"
}
