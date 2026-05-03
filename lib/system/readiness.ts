import { badgerEnv } from "@/lib/config/env"
import { backgroundJobsEnabled } from "@/lib/scanner/jobs"
import { isSupabaseConfigured } from "@/lib/supabase/config"
import { isGitHubAppInstallationConfigured } from "@/lib/utils/github-app-config"

export type ReadinessSeverity = "blocker" | "warning"

export type ReadinessCheck = {
  id: string
  ok: boolean
  severity: ReadinessSeverity
  label: string
  remediation: string
}

export type ProductionReadiness = {
  ready: boolean
  blockingChecks: string[]
  warningChecks: string[]
  checks: ReadinessCheck[]
}

export function getProductionReadiness(): ProductionReadiness {
  const checks: ReadinessCheck[] = [
    {
      id: "supabase_persistence",
      ok: isSupabaseConfigured(),
      severity: "blocker",
      label: "Supabase server-side persistence is configured",
      remediation: "Connect the Supabase project and configure the server-only persistence credential in Vercel/v0.",
    },
    {
      id: "persistent_storage_required",
      ok: productionPersistenceEnabled("REQUIRE_PERSISTENT_STORAGE"),
      severity: "blocker",
      label: "Production storage cannot fall back to local memory or files",
      remediation: "Keep persistent report storage required in production.",
    },
    {
      id: "persistent_quota_required",
      ok: productionPersistenceEnabled("REQUIRE_PERSISTENT_QUOTA"),
      severity: "blocker",
      label: "Production monthly quota cannot fall back to memory",
      remediation: "Keep persistent monthly quota required in production.",
    },
    {
      id: "identity_salt",
      ok: hasStrongIdentitySalt(),
      severity: "blocker",
      label: "Request identity hashing uses a dedicated random salt",
      remediation: "Configure a long random server-only identity salt before accepting production traffic.",
    },
    {
      id: "github_oauth",
      ok: isGitHubOAuthConfigured(),
      severity: "blocker",
      label: "GitHub OAuth is configured for repository login and PR creation",
      remediation: "Configure GitHub OAuth client ID, client secret, callback URL and encrypted session secret.",
    },
    {
      id: "github_redirect_public",
      ok: isProductionRedirectUri(),
      severity: "blocker",
      label: "GitHub OAuth callback uses a public HTTPS production URL",
      remediation: "Set the production callback URL to the deployed domain, not localhost.",
    },
    {
      id: "ai_provider",
      ok: isAiConfigured(),
      severity: "warning",
      label: "AI explanation provider is configured",
      remediation: "Configure AI Gateway, Claude/Anthropic, or DeepSeek for richer triage; deterministic rules still run without AI.",
    },
    {
      id: "pr_safety_review",
      ok: isPrSafetyReviewConfigured(),
      severity: "blocker",
      label: "PR safety review model is configured",
      remediation: "Configure the server-only Claude/Anthropic credential so public PRs fail closed unless reviewed.",
    },
    {
      id: "background_worker_secret",
      ok: !backgroundJobsEnabled() || Boolean(badgerEnv("WORKER_SECRET")),
      severity: "blocker",
      label: "Background worker endpoint is protected when jobs are enabled",
      remediation: "If background jobs are enabled, configure a long random worker secret and send it only from a trusted cron/worker.",
    },
    {
      id: "public_scan_list_disabled",
      ok: badgerEnv("ENABLE_PUBLIC_SCAN_LIST") !== "true",
      severity: "blocker",
      label: "Report history is not publicly enumerable",
      remediation: "Keep public report listing disabled; reports should be filtered by the request identity.",
    },
    {
      id: "legacy_report_access_disabled",
      ok: badgerEnv("ALLOW_LEGACY_REPORT_ACCESS") !== "true",
      severity: "blocker",
      label: "Legacy unauthenticated report access is disabled",
      remediation: "Keep legacy report access disabled so report retrieval requires the creating identity.",
    },
    {
      id: "private_ai_review_opt_in",
      ok: badgerEnv("ALLOW_PRIVATE_AI_REVIEW") !== "true",
      severity: "warning",
      label: "Private repository snippets are not sent to AI by default",
      remediation: "Only enable private AI review with explicit product consent and a provider posture you can defend.",
    },
    {
      id: "public_env_safety",
      ok: !hasDangerousPublicEnv(),
      severity: "blocker",
      label: "No secret-shaped environment variable is exposed with a public prefix",
      remediation: "Move secret, private, token, service-role, database and API credentials to server-only environment variables.",
    },
    {
      id: "github_app_optional",
      ok: isGitHubAppInstallationConfigured(),
      severity: "warning",
      label: "Badger GitHub App installation is available for server-side public scans",
      remediation: "Configure BADGER_GITHUB_APP_ID, BADGER_GITHUB_APP_PRIVATE_KEY and BADGER_GITHUB_APP_INSTALLATION_ID so public repository scans do not depend on anonymous GitHub API limits.",
    },
  ]

  const blockingChecks = checks.filter((check) => !check.ok && check.severity === "blocker").map((check) => check.id)
  const warningChecks = checks.filter((check) => !check.ok && check.severity === "warning").map((check) => check.id)

  return {
    ready: blockingChecks.length === 0,
    blockingChecks,
    warningChecks,
    checks,
  }
}

export function isAiConfigured() {
  return Boolean(
    process.env.AI_GATEWAY_API_KEY ||
      process.env.VERCEL_OIDC_TOKEN ||
      process.env.ANTHROPIC_API_KEY ||
      process.env.CLAUDE_API_KEY ||
      process.env.DEEPSEEK_API_KEY,
  )
}

export function isPrSafetyReviewConfigured() {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY)
}

export function isGitHubOAuthConfigured() {
  return Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && badgerEnv("GITHUB_SESSION_SECRET"))
}

function productionPersistenceEnabled(name: string) {
  return badgerEnv(name)?.toLowerCase() !== "false"
}

function hasStrongIdentitySalt() {
  const salt = badgerEnv("IDENTITY_SALT")
  return Boolean(salt && salt.length >= 24)
}

function isProductionRedirectUri() {
  const redirectUri = process.env.GITHUB_REDIRECT_URI?.trim()
  if (!redirectUri) return false

  try {
    const url = new URL(redirectUri)
    return url.protocol === "https:" && !["localhost", "127.0.0.1", "::1"].includes(url.hostname)
  } catch {
    return false
  }
}

function hasDangerousPublicEnv() {
  return Object.keys(process.env).some((name) => {
    if (!name.startsWith("NEXT_PUBLIC_")) return false
    if (name === "NEXT_PUBLIC_SUPABASE_URL" || name === "NEXT_PUBLIC_SUPABASE_ANON_KEY") return false
    return /(SECRET|PRIVATE|TOKEN|SERVICE_ROLE|DATABASE_URL|API_KEY)/i.test(name)
  })
}
