import type { ProjectFile } from "./types"
import { redactSecrets, type RuleFinding } from "./rules"

export interface RulePackScanResult {
  findings: RuleFinding[]
  summary: {
    packs: string[]
    rulesEvaluated: number
    findings: number
  }
}

type RulePackFinding = RuleFinding

const SEMGREP_STYLE_PACKS = [
  "nextjs-data-security",
  "supabase-rls",
  "vercel-posture",
] as const

export function scanStaticRulePacks(files: ProjectFile[]): RulePackScanResult {
  const findings: RulePackFinding[] = []
  const seen = new Set<string>()

  const add = (finding: RulePackFinding) => {
    const key = `${finding.ruleId}|${finding.filePath}|${finding.lineStart ?? ""}|${finding.evidence ?? ""}`
    if (seen.has(key)) return
    seen.add(key)
    findings.push(finding)
  }

  for (const file of files) {
    scanNextDataAccessPack(file, add)
    scanSupabaseRlsPack(file, add)
    scanVercelPosturePack(file, add)
  }

  return {
    findings,
    summary: {
      packs: [...SEMGREP_STYLE_PACKS],
      rulesEvaluated: 5,
      findings: findings.length,
    },
  }
}

function scanNextDataAccessPack(file: ProjectFile, add: (finding: RulePackFinding) => void) {
  const normalized = normalizePath(file.path)
  if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(normalized)) return
  if (!/(^|\/)(lib|src\/lib)\/data\//.test(normalized)) return
  if (hasServerOnlyImport(file.text)) return
  if (!/\b(prisma|supabaseAdmin|service[_-]?role|DATABASE_URL|db\.)\b/i.test(file.text)) return

  const hit = findLineMatching(file.text, /\b(prisma|supabaseAdmin|service[_-]?role|DATABASE_URL|db\.)\b/i)
  add({
    kind: "hardening",
    severity: "medium",
    category: "client_data_exposure",
    ruleId: "next.data-access.server-only-missing",
    title: "Data access module is missing a server-only boundary",
    description:
      "This data access file touches database or privileged server resources but does not import server-only. In Next.js apps, that import prevents accidental client-bundle usage of server data access code.",
    filePath: file.path,
    lineStart: hit?.lineNumber ?? 1,
    evidence: redactSecrets(hit?.line.trim() ?? basename(file.path)),
    confidence: 0.78,
    confidenceReason:
      "Semgrep-style rule pack match: data access path plus database/admin signal, without an import \"server-only\" boundary.",
    reachability: "unknown",
    exploitability: "medium",
    recommendation: "Add `import \"server-only\"` at the top of server-only data access modules and expose minimal DTOs to client components.",
    patchable: true,
    source: "rule",
  })
}

function scanSupabaseRlsPack(file: ProjectFile, add: (finding: RulePackFinding) => void) {
  const normalized = normalizePath(file.path).toLowerCase()
  if (!normalized.endsWith(".sql") || !normalized.includes("supabase/migrations/")) return

  for (const table of findCreatedPublicTables(file.text)) {
    if (hasRlsCoverage(file.text, table.name)) continue

    add({
      kind: "vulnerability",
      severity: "high",
      category: "supabase_rls_risk",
      ruleId: "supabase.rls.table-without-policy-coverage",
      title: "Supabase table is created without visible RLS policy coverage",
      description:
        "A public Supabase table is created in a migration, but the same migration does not show row level security enablement or a policy for that table. For client-facing Supabase apps, missing RLS coverage can expose tenant or user data.",
      filePath: file.path,
      lineStart: table.lineNumber,
      evidence: redactSecrets(table.line.trim()),
      confidence: 0.82,
      confidenceReason:
        "SupaShield-inspired rule pack match: public table creation without enable row level security or create policy evidence in the migration.",
      reachability: "reachable",
      exploitability: "high",
      cwe: "CWE-284",
      recommendation:
        "Enable row level security for the table and add least-privilege policies for anon/authenticated roles before exposing it to client code.",
      patchable: false,
      source: "rule",
    })
  }

  const publicBucket = findLineMatching(file.text, /\bstorage\.buckets\b[\s\S]{0,160}\bpublic\b[\s\S]{0,80}\btrue\b/i)
  if (publicBucket) {
    add({
      kind: "repo_posture",
      severity: "medium",
      category: "supabase_rls_risk",
      ruleId: "supabase.storage.public-bucket-review",
      title: "Supabase storage bucket is configured as public",
      description:
        "A Supabase storage bucket appears to be public. That can be intentional for assets, but professional apps should review bucket contents, upload paths, and object policies.",
      filePath: file.path,
      lineStart: publicBucket.lineNumber,
      evidence: redactSecrets(publicBucket.line.trim()),
      confidence: 0.76,
      confidenceReason:
        "SupaShield-inspired rule pack match: storage.buckets operation with public=true evidence.",
      reachability: "reachable",
      exploitability: "medium",
      recommendation:
        "Keep public buckets only for non-sensitive assets, add explicit object policies, and verify uploads cannot overwrite or enumerate private user data.",
      patchable: false,
      source: "rule",
    })
  }
}

function scanVercelPosturePack(file: ProjectFile, add: (finding: RulePackFinding) => void) {
  const normalized = normalizePath(file.path).toLowerCase()

  if (/^next\.config\.(mjs|js|ts|cjs)$/.test(normalized)) {
    const sourceMaps = findLineMatching(file.text, /\bproductionBrowserSourceMaps\s*:\s*true\b/i)
    if (sourceMaps) {
      add({
        kind: "hardening",
        severity: "medium",
        category: "vercel_hardening",
        ruleId: "vercel.source-maps.enabled-in-production",
        title: "Production browser source maps are enabled",
        description:
          "Next.js production browser source maps make debugging easier, but they also expose more source structure to anyone who can fetch client assets.",
        filePath: file.path,
        lineStart: sourceMaps.lineNumber,
        evidence: redactSecrets(sourceMaps.line.trim()),
        confidence: 0.86,
        confidenceReason: "Vercelsior-inspired posture rule pack match in next.config.*.",
        reachability: "reachable",
        exploitability: "low",
        recommendation:
          "Disable productionBrowserSourceMaps unless you intentionally publish source maps, or restrict source map upload to a private error-monitoring provider.",
        patchable: false,
        source: "rule",
      })
    }
  }

  if (isCronRoute(normalized) && !hasCronSecretGuard(file.text)) {
    const handler = findLineMatching(file.text, /\bexport\s+(async\s+)?function\s+(GET|POST)\b/i)
    add({
      kind: "vulnerability",
      severity: "medium",
      category: "vercel_hardening",
      ruleId: "vercel.cron.missing-secret-guard",
      title: "Cron route is missing an obvious secret guard",
      description:
        "A cron-like route is reachable as an HTTP endpoint, but no CRON_SECRET, Authorization header, or signature guard is visible before the handler returns work.",
      filePath: file.path,
      lineStart: handler?.lineNumber ?? 1,
      evidence: redactSecrets(handler?.line.trim() ?? basename(file.path)),
      confidence: 0.74,
      confidenceReason: "Vercelsior-inspired posture rule pack match: cron route path without a visible secret guard.",
      reachability: "reachable",
      exploitability: "medium",
      recommendation:
        "Require a CRON_SECRET or signed Authorization header at the start of the cron handler and return 401 before doing work when it is missing or invalid.",
      patchable: true,
      source: "rule",
    })
  }
}

function findCreatedPublicTables(text: string) {
  const tables: Array<{ name: string; line: string; lineNumber: number }> = []
  const lines = text.split(/\r?\n/)

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    const match = line.match(/\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:(public)\.)?([a-zA-Z_][\w]*)\b/i)
    if (!match) continue
    if (match[1] !== "public" && /\b(auth|storage|realtime|extensions)\./i.test(line)) continue
    tables.push({ name: match[2], line, lineNumber: index + 1 })
  }

  return tables
}

function hasRlsCoverage(text: string, table: string) {
  const escaped = escapeRegExp(table)
  const enableRls = new RegExp(`\\balter\\s+table\\s+(?:public\\.)?${escaped}\\s+enable\\s+row\\s+level\\s+security\\b`, "i")
  const forceRls = new RegExp(`\\balter\\s+table\\s+(?:public\\.)?${escaped}\\s+force\\s+row\\s+level\\s+security\\b`, "i")
  const policy = new RegExp(`\\bcreate\\s+policy\\b[\\s\\S]{0,400}\\bon\\s+(?:public\\.)?${escaped}\\b`, "i")
  return enableRls.test(text) || forceRls.test(text) || policy.test(text)
}

function hasServerOnlyImport(text: string) {
  return /^\s*import\s+["']server-only["']\s*;?\s*$/m.test(text)
}

function isCronRoute(path: string) {
  return /^app\/api\/(?:cron|jobs|scheduled|tasks)\//.test(path) && /\/route\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)
}

function hasCronSecretGuard(text: string) {
  return /\b(CRON_SECRET|Authorization|authorization|Bearer|x-vercel-cron-signature|verifySignature|timingSafeEqual|createHmac)\b/.test(text)
}

function findLineMatching(text: string, regex: RegExp) {
  const flags = regex.flags.includes("i") ? "i" : ""
  const lineRegex = new RegExp(regex.source, flags)
  const lines = text.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    if (lineRegex.test(lines[index])) return { line: lines[index], lineNumber: index + 1 }
  }
  return undefined
}

function normalizePath(path: string) {
  return path.replaceAll("\\", "/").replace(/^\/+/, "")
}

function basename(path: string) {
  return normalizePath(path).split("/").pop() ?? path
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}
