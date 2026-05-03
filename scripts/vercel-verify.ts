import { execFileSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import path from "node:path"

const REQUIRED_PRODUCTION_ENV_GROUPS = [
  ["SUPABASE_URL"],
  ["NEXT_PUBLIC_SUPABASE_URL"],
  ["NEXT_PUBLIC_SUPABASE_ANON_KEY"],
  ["BADGER_IDENTITY_SALT", "VIBESHIELD_IDENTITY_SALT"],
  ["BADGER_REQUIRE_PERSISTENT_QUOTA", "VIBESHIELD_REQUIRE_PERSISTENT_QUOTA"],
  ["BADGER_REQUIRE_PERSISTENT_STORAGE", "VIBESHIELD_REQUIRE_PERSISTENT_STORAGE"],
  ["GITHUB_CLIENT_ID"],
  ["GITHUB_CLIENT_SECRET"],
  ["GITHUB_REDIRECT_URI"],
  ["BADGER_GITHUB_SESSION_SECRET", "VIBESHIELD_GITHUB_SESSION_SECRET"],
] as const

const ONE_OF_PRODUCTION_ENV_NAMES = [
  ["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY"],
  ["AI_GATEWAY_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "DEEPSEEK_API_KEY"],
] as const

async function main() {
  console.log("Badger Vercel verification")

  if (!commandExists("vercel")) {
    console.log("[fail] vercel_cli: Vercel CLI is not installed")
    process.exitCode = 1
    return
  }

  const project = await readProjectLink()
  if (!project) {
    console.log("[fail] vercel_project_link: .vercel/project.json is missing")
    console.log("      Run `vercel pull --yes` or link this checkout to the production Vercel project.")
    process.exitCode = 1
    return
  }

  console.log("[ok] vercel_cli: installed")
  console.log("[ok] vercel_project_link: project is linked locally")

  const envNames = listProductionEnvNames()
  if (!envNames) {
    console.log("[fail] vercel_env_access: could not list production environment variables")
    console.log("      Authenticate Vercel CLI and confirm this checkout is linked to the correct project.")
    process.exitCode = 1
    return
  }

  let failed = 0
  for (const group of REQUIRED_PRODUCTION_ENV_GROUPS) {
    const label = group.join("|")
    if (group.some((name) => envNames.has(name))) {
      console.log(`[ok] env:${label}: configured in production`)
    } else {
      failed += 1
      console.log(`[fail] env:${label}: missing from production`)
    }
  }

  for (const group of ONE_OF_PRODUCTION_ENV_NAMES) {
    if (group.some((name) => envNames.has(name))) {
      console.log(`[ok] env:${group.join("|")}: at least one configured in production`)
    } else {
      failed += 1
      console.log(`[fail] env:${group.join("|")}: none configured in production`)
    }
  }

  if (failed > 0) {
    process.exitCode = 1
    return
  }

  console.log("[ok] vercel_environment: required production env var names are present")
  console.log("No environment values were printed.")
}

function commandExists(command: string) {
  try {
    execFileSync("command", ["-v", command], { shell: true, stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

async function readProjectLink() {
  const raw = await readText(".vercel/project.json")
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as { projectId?: string; orgId?: string }
    if (!parsed.projectId || !parsed.orgId) return null
    return parsed
  } catch {
    return null
  }
}

function listProductionEnvNames() {
  try {
    const output = execFileSync("vercel", ["env", "ls", "production"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    })

    const names = new Set<string>()
    for (const line of output.split(/\r?\n/)) {
      for (const token of line.trim().split(/\s+/)) {
        if (/^[A-Z][A-Z0-9_]+$/.test(token)) names.add(token)
      }
    }
    return names
  } catch {
    return null
  }
}

async function readText(relativePath: string) {
  try {
    return await readFile(path.join(process.cwd(), relativePath), "utf8")
  } catch {
    return ""
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? sanitizeError(error.message) : "Vercel verification failed")
  process.exitCode = 1
})

function sanitizeError(message: string) {
  return message.replace(/https:\/\/[^\s)]+/g, "https://...redacted").slice(0, 240)
}
