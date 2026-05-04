import { execFileSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import path from "node:path"
import {
  BADGER_SUPABASE_EXPECTED_TABLES,
  BADGER_SUPABASE_BURST_RPC,
  BADGER_SUPABASE_MIGRATIONS,
  BADGER_SUPABASE_QUOTA_RPC,
  BADGER_SUPABASE_TABLES,
} from "../lib/supabase/schema"
import { loadEnvFiles } from "./lib/env"

type Check = {
  id: string
  ok: boolean
  severity: "blocker" | "warning"
  label: string
  remediation: string
}

async function main() {
  const strict = process.argv.includes("--production") || process.argv.includes("--strict")
  await loadEnvFiles(strict ? "production" : "development")
  if (strict) await applyVercelSensitiveReadinessPlaceholders()
  const { getProductionReadiness } = await import("../lib/system/readiness")
  const checks: Check[] = [...getProductionReadiness().checks, ...(await repositoryChecks())]
  const blockers = checks.filter((check) => !check.ok && check.severity === "blocker")
  const warnings = checks.filter((check) => !check.ok && check.severity === "warning")

  console.log("Badger production readiness")
  console.log(`Mode: ${strict ? "strict production" : "advisory"}`)
  console.log("")

  for (const check of checks) {
    const state = check.ok ? "ok" : check.severity === "blocker" ? "fail" : "warn"
    console.log(`[${state}] ${check.id}: ${check.label}`)
    if (!check.ok) console.log(`      ${check.remediation}`)
  }

  console.log("")
  console.log(`Summary: ${checks.length - blockers.length - warnings.length}/${checks.length} ok, ${blockers.length} blockers, ${warnings.length} warnings`)

  if (strict && blockers.length > 0) {
    process.exitCode = 1
  }
}

async function repositoryChecks(): Promise<Check[]> {
  const migrationTexts = await Promise.all(BADGER_SUPABASE_MIGRATIONS.map((migration) => readText(migration)))
  const nextConfig = await readText("next.config.mjs")
  const gitignore = await readText(".gitignore")
  const scanRoute = await readText("app/api/scan/route.ts")
  const explainRoute = await readText("app/api/scan/[scanId]/explain/route.ts")
  const pullRequestRoute = await readText("app/api/scan/[scanId]/pull-request/route.ts")
  const drainRoute = await readText("app/api/scan/jobs/drain/route.ts")
  const secretLiteralMatches = await scanRepositoryForSecretLiterals()

  const migrations = migrationTexts.join("\n")

  return [
    {
      id: "supabase_migrations_present",
      ok: migrationTexts.every(Boolean),
      severity: "blocker",
      label: "Supabase migrations for reports, quotas, jobs, baselines and events exist",
      remediation: "Keep both Supabase migration files in the repository and run them in order before production traffic.",
    },
    {
      id: "supabase_rls_forced",
      ok: hasAll(
        migrations,
        ...BADGER_SUPABASE_EXPECTED_TABLES.map((table) => `alter table public.${table} force row level security`),
      ),
      severity: "blocker",
      label: "Supabase tables force RLS for defense in depth",
      remediation: "Force RLS on every Badger table exposed under the public schema.",
    },
    {
      id: "supabase_client_roles_denied",
      ok: hasAll(
        migrations,
        ...BADGER_SUPABASE_EXPECTED_TABLES.flatMap((table) => [
          `revoke all on table public.${table} from public`,
          `revoke all on table public.${table} from anon`,
          `revoke all on table public.${table} from authenticated`,
        ]),
      ),
      severity: "blocker",
      label: "Supabase client roles are denied direct table access",
      remediation: "Deny direct anon/authenticated table access and keep writes behind route handlers with the service role.",
    },
    {
      id: "quota_rpc_service_role_only",
      ok: hasAll(
        migrations,
        `create or replace function public.${BADGER_SUPABASE_QUOTA_RPC}`,
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from public`,
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from anon`,
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from authenticated`,
        `grant execute on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) to service_role`,
      ),
      severity: "blocker",
      label: "Monthly quota RPC is callable only by the service role",
      remediation: "Restrict quota mutation to server-side code; never expose quota writes to client roles.",
    },
    {
      id: "quota_rpc_credit_cost_supported",
      ok: hasAll(
        migrations,
        "p_cost integer default 1",
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from public`,
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from anon`,
        `revoke all on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) from authenticated`,
        `grant execute on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer) to service_role`,
      ),
      severity: "blocker",
      label: "Monthly quota RPC supports multi-credit scans",
      remediation: "Run the latest scan credit quota migration before enabling Max mode in production.",
    },
    {
      id: "quota_rpc_has_single_signature",
      ok: hasAll(
        migrations,
        `drop function if exists public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer)`,
        `comment on function public.${BADGER_SUPABASE_QUOTA_RPC}(text, date, integer, integer)`,
      ),
      severity: "blocker",
      label: "Monthly quota RPC has a single unambiguous production signature",
      remediation: "Drop the legacy three-argument quota RPC overload so Supabase/PostgREST can resolve scan quota calls.",
    },
    {
      id: "burst_rpc_service_role_only",
      ok: hasAll(
        migrations,
        `create table if not exists public.${BADGER_SUPABASE_TABLES.burstUsage}`,
        `create or replace function public.${BADGER_SUPABASE_BURST_RPC}`,
        `revoke all on function public.${BADGER_SUPABASE_BURST_RPC}(text, text, timestamptz, integer, integer) from public`,
        `revoke all on function public.${BADGER_SUPABASE_BURST_RPC}(text, text, timestamptz, integer, integer) from anon`,
        `revoke all on function public.${BADGER_SUPABASE_BURST_RPC}(text, text, timestamptz, integer, integer) from authenticated`,
        `grant execute on function public.${BADGER_SUPABASE_BURST_RPC}(text, text, timestamptz, integer, integer) to service_role`,
      ),
      severity: "blocker",
      label: "Short-window burst limits are persisted and callable only by the service role",
      remediation: "Run the distributed burst quota migration so public API abuse cannot bypass per-instance memory counters.",
    },
    {
      id: "security_headers_configured",
      ok: hasAll(
        nextConfig,
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Cross-Origin-Opener-Policy",
        "Referrer-Policy",
        "X-Frame-Options",
        "Permissions-Policy",
      ),
      severity: "blocker",
      label: "Next.js sends baseline browser security headers",
      remediation: "Keep CSP, nosniff, HSTS, COOP, no-referrer, frame denial and permissions-policy headers configured.",
    },
    {
      id: "vercel_heavy_route_duration",
      ok: [scanRoute, explainRoute, pullRequestRoute, drainRoute].every(hasLongMaxDuration),
      severity: "blocker",
      label: "Long-running scan, AI, PR and worker routes declare Vercel max duration",
      remediation: "Keep explicit maxDuration on heavy route handlers so Vercel does not terminate scans or safety reviews early.",
    },
    {
      id: "env_files_ignored",
      ok: gitignore.includes(".env*.local") || gitignore.includes(".env.local"),
      severity: "blocker",
      label: "Local environment files are ignored by git",
      remediation: "Keep local secret files ignored and never commit provider or service credentials.",
    },
    {
      id: "repository_secret_literals_absent",
      ok: secretLiteralMatches.length === 0,
      severity: "blocker",
      label: "Public repository files do not contain high-risk secret literals",
      remediation:
        secretLiteralMatches.length > 0
          ? `Remove or rotate high-risk literals before deployment. Affected paths: ${secretLiteralMatches.slice(0, 5).join(", ")}`
          : "Keep real provider keys only in local or hosted environment variables, never in tracked source.",
    },
  ]
}

async function applyVercelSensitiveReadinessPlaceholders() {
  const envFile = await readText(".vercel/.env.production.local")
  if (!envFile) return

  const masked = new Set<string>()
  for (const line of envFile.split(/\r?\n/)) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=""$/.exec(line.trim())
    if (match) masked.add(match[1])
  }

  const placeholders: Record<string, string> = {
    BADGER_IDENTITY_SALT: "placeholder://readiness/BADGER_IDENTITY_SALT",
    [legacyEnvName("IDENTITY_SALT")]: `placeholder://readiness/${legacyEnvName("IDENTITY_SALT")}`,
    GITHUB_CLIENT_SECRET: "vercel-sensitive-placeholder-github-client-secret",
    BADGER_GITHUB_SESSION_SECRET: "placeholder://readiness/BADGER_GITHUB_SESSION_SECRET",
    [legacyEnvName("GITHUB_SESSION_SECRET")]: `placeholder://readiness/${legacyEnvName("GITHUB_SESSION_SECRET")}`,
    ANTHROPIC_API_KEY: "vercel-sensitive-placeholder-anthropic-key",
    CLAUDE_API_KEY: "vercel-sensitive-placeholder-claude-key",
    DEEPSEEK_API_KEY: "vercel-sensitive-placeholder-deepseek-key",
    AI_GATEWAY_API_KEY: "vercel-sensitive-placeholder-ai-gateway-key",
  }

  for (const [name, placeholder] of Object.entries(placeholders)) {
    if (masked.has(name) && !process.env[name]?.trim()) process.env[name] = placeholder
  }
}

function legacyEnvName(name: string) {
  return `${["VIBE", "SHIELD"].join("")}_${name}`
}

function hasAll(source: string, ...needles: string[]) {
  const normalized = source.toLowerCase()
  return needles.every((needle) => normalized.includes(needle.toLowerCase()))
}

function hasLongMaxDuration(source: string) {
  const match = /export\s+const\s+maxDuration\s*=\s*(\d+)/.exec(source)
  return Boolean(match && Number(match[1]) >= 300)
}

async function scanRepositoryForSecretLiterals() {
  const files = listGitVisibleFiles()
  const matches = new Set<string>()

  for (const file of files) {
    if (shouldSkipSecretLiteralScan(file)) continue

    const text = await readText(file)
    if (!text || text.length > 2_000_000) continue
    if (containsHighRiskSecretLiteral(text)) matches.add(file)
  }

  return [...matches].sort()
}

function listGitVisibleFiles() {
  try {
    return execFileSync("git", ["ls-files", "-co", "--exclude-standard"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    })
      .split(/\r?\n/)
      .map((file) => file.trim())
      .filter(Boolean)
  } catch {
    return []
  }
}

function shouldSkipSecretLiteralScan(file: string) {
  return (
    file.startsWith("examples/") ||
    file.startsWith(".next/") ||
    file.startsWith("node_modules/") ||
    file === "pnpm-lock.yaml" ||
    file.endsWith(".png") ||
    file.endsWith(".jpg") ||
    file.endsWith(".jpeg") ||
    file.endsWith(".gif") ||
    file.endsWith(".webp")
  )
}

function containsHighRiskSecretLiteral(text: string) {
  return text
    .split(/\r?\n/)
    .some((line) => !isSecretDetectorImplementationLine(line) && highRiskSecretPatterns().some((pattern) => pattern.test(line)))
}

function isSecretDetectorImplementationLine(line: string) {
  return /(?:regex|pattern|redact|redacted|replace|RegExp|A-Za-z|\\b|\\s|\\S|\[\^|PRIVATE KEY-----\\|sk-\[|ghp_\[|github_pat_\[)/.test(line)
}

function highRiskSecretPatterns() {
  return [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{40,}\b/,
    /\bsk-proj-[A-Za-z0-9_-]{40,}\b/,
    /\bsk-[a-f0-9]{32,}\b/i,
    /\bsk_live_[A-Za-z0-9]{24,}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
    /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/,
    /\bvercel_[A-Za-z0-9]{24,}\b/i,
  ]
}

async function readText(relativePath: string) {
  try {
    return await readFile(path.join(process.cwd(), relativePath), "utf8")
  } catch {
    return ""
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Production readiness check failed")
  process.exitCode = 1
})
