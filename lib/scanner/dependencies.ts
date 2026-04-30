import type { DependencySummary, ProjectFile, ScanFinding, Severity } from "./types"
import { redactSecrets } from "./rules"

type DependencyFinding = Omit<ScanFinding, "id">

type PackageCandidate = {
  name: string
  version: string
  ecosystem: "npm" | "PyPI" | "crates.io" | "Go" | "RubyGems" | "Packagist"
  filePath: string
  lineStart?: number
  direct: boolean
  devOnly?: boolean
}

type OsvBatchResponse = {
  results?: Array<{
    vulns?: OsvVulnerability[]
  }>
}

type OsvVulnerability = {
  id?: string
  aliases?: string[]
  summary?: string
  details?: string
  severity?: Array<{ type?: string; score?: string }>
  database_specific?: { severity?: string }
  affected?: Array<{
    ranges?: Array<{
      events?: Array<{ fixed?: string }>
    }>
  }>
}

export interface DependencyScanResult {
  findings: DependencyFinding[]
  summary: DependencySummary
}

export async function scanDependencies(files: ProjectFile[]): Promise<DependencyScanResult> {
  const candidates = dedupeCandidates(files.flatMap(extractPackageCandidates)).slice(0, readPositiveInt(process.env.MAX_OSV_PACKAGES, 150))
  const summary: DependencySummary = {
    manifests: files.filter(isManifestFile).length,
    lockfiles: files.filter(isLockfile).length,
    packages: candidates.length,
    vulnerablePackages: 0,
    ecosystems: [...new Set(candidates.map((candidate) => candidate.ecosystem))].sort(),
    osvEnabled: process.env.VIBESHIELD_ENABLE_OSV !== "false",
  }

  if (!summary.osvEnabled || candidates.length === 0) {
    return { findings: [], summary }
  }

  try {
    const response = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: candidates.map((candidate) => ({
          version: candidate.version,
          package: {
            name: candidate.name,
            ecosystem: candidate.ecosystem,
          },
        })),
      }),
      signal: AbortSignal.timeout(readPositiveInt(process.env.OSV_TIMEOUT_MS, 8_000)),
    })

    if (!response.ok) {
      return { findings: [], summary: { ...summary, error: `OSV returned ${response.status}` } }
    }

    const data = (await response.json()) as OsvBatchResponse
    const findings: DependencyFinding[] = []

    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = candidates[index]
      const vulns = data.results?.[index]?.vulns ?? []
      if (vulns.length === 0) continue

      summary.vulnerablePackages += 1
      for (const vuln of vulns.slice(0, 3)) {
        findings.push(toFinding(candidate, vuln))
      }
    }

    return { findings, summary }
  } catch (error) {
    return {
      findings: [],
      summary: {
        ...summary,
        error: error instanceof Error ? error.message.slice(0, 180) : "OSV dependency scan failed",
      },
    }
  }
}

function toFinding(candidate: PackageCandidate, vuln: OsvVulnerability): DependencyFinding {
  const osvId = vuln.id ?? "OSV vulnerability"
  const aliases = vuln.aliases ?? []
  const maintenanceOnly = isMaintenanceOnlyAdvisory(vuln)
  const severity = maintenanceOnly ? "info" : severityFromOsv(vuln)
  const fixedVersion = firstFixedVersion(vuln)
  const runtimeContext = candidate.devOnly ? "development dependency" : candidate.direct ? "direct dependency" : "locked dependency"

  return {
    kind: maintenanceOnly ? "repo_posture" : "vulnerability",
    severity,
    category: maintenanceOnly ? "dependency_signal" : "dependency_vulnerability",
    ruleId: maintenanceOnly ? "dependency.osv.maintenance-risk" : "dependency.osv.known-vulnerability",
    title: maintenanceOnly ? `Dependency maintenance risk: ${candidate.name}` : `Known vulnerable dependency: ${candidate.name}`,
    description: maintenanceOnly
      ? `${candidate.name}@${candidate.version} matches ${osvId}${aliases.length ? ` (${aliases.slice(0, 2).join(", ")})` : ""}, but OSV/RustSec classifies it as maintenance or informational risk rather than a confirmed exploitable vulnerability.`
      : `${candidate.name}@${candidate.version} matches ${osvId}${aliases.length ? ` (${aliases.slice(0, 2).join(", ")})` : ""}.`,
    filePath: candidate.filePath,
    lineStart: candidate.lineStart,
    evidence: redactSecrets(`${candidate.ecosystem}:${candidate.name}@${candidate.version} -> ${osvId}`),
    confidence: maintenanceOnly ? 0.88 : 0.92,
    confidenceReason: maintenanceOnly
      ? "Matched exact package ecosystem, name, and version through OSV querybatch; advisory is informational/unmaintained, so this is repo posture until reachable unsafe usage is proven."
      : "Matched exact package ecosystem, name, and version through OSV querybatch.",
    reachability: maintenanceOnly || candidate.devOnly ? "unknown" : "reachable",
    exploitability: maintenanceOnly ? "low" : severity === "critical" || severity === "high" ? "high" : "unknown",
    cwe: aliases.find((alias) => alias.startsWith("CWE-")),
    recommendation: maintenanceOnly
      ? `Review whether ${candidate.name} handles untrusted input in this project. Prefer a maintained alternative or isolate usage, but do not treat this as a confirmed exploit without reachability evidence.`
      : fixedVersion
      ? `Upgrade ${candidate.name} to ${fixedVersion} or later. Confirm whether it is a ${runtimeContext} before prioritizing rollout.`
      : `Upgrade ${candidate.name} to a non-vulnerable version and confirm whether it is a ${runtimeContext}.`,
    patchable: false,
    source: "rule",
  }
}

function isMaintenanceOnlyAdvisory(vuln: OsvVulnerability) {
  if (vuln.id === "RUSTSEC-2025-0141") return true

  const raw = [
    vuln.id,
    vuln.summary,
    vuln.details,
    vuln.database_specific?.severity,
    ...(vuln.aliases ?? []),
    ...(vuln.severity?.map((item) => `${item.type ?? ""} ${item.score ?? ""}`) ?? []),
  ].join(" ").toLowerCase()

  return /\b(info|informational|unmaintained|maintenance|no patched versions?)\b/.test(raw) &&
    !/\b(critical|high|medium|cvss:[^\s]*[789]\.|9\.[0-9]|10\.0)\b/.test(raw)
}

function extractPackageCandidates(file: ProjectFile): PackageCandidate[] {
  const name = basename(file.path)
  if (name === "package.json") return extractPackageJson(file)
  if (name === "package-lock.json") return extractPackageLock(file)
  if (name === "pnpm-lock.yaml") return extractPnpmLock(file)
  if (name === "requirements.txt") return extractRequirements(file)
  if (name === "pyproject.toml") return extractPyProject(file)
  if (name === "Cargo.lock") return extractCargoLock(file)
  if (name === "Cargo.toml") return extractCargoToml(file)
  if (name === "go.sum") return extractGoSum(file)
  if (name === "Gemfile.lock") return extractGemfileLock(file)
  return []
}

function extractPackageJson(file: ProjectFile): PackageCandidate[] {
  try {
    const parsed = JSON.parse(file.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    return [
      ...Object.entries(parsed.dependencies ?? {}).flatMap(([name, raw]) => candidateFromRange(file, name, raw, "npm", false)),
      ...Object.entries(parsed.devDependencies ?? {}).flatMap(([name, raw]) => candidateFromRange(file, name, raw, "npm", true)),
    ]
  } catch {
    return []
  }
}

function extractPackageLock(file: ProjectFile): PackageCandidate[] {
  try {
    const parsed = JSON.parse(file.text) as { packages?: Record<string, { version?: string; dev?: boolean }>; dependencies?: Record<string, { version?: string; dev?: boolean }> }
    const entries = parsed.packages
      ? Object.entries(parsed.packages)
          .filter(([path]) => path.startsWith("node_modules/"))
          .map(([path, value]) => [path.replace(/^node_modules\//, ""), value] as const)
      : Object.entries(parsed.dependencies ?? {})
    return entries.flatMap(([name, value]) => exactCandidate(file, name, value.version, "npm", Boolean(value.dev)))
  } catch {
    return []
  }
}

function extractPnpmLock(file: ProjectFile): PackageCandidate[] {
  const candidates: PackageCandidate[] = []
  const lines = file.text.split(/\r?\n/)
  for (const [index, line] of lines.entries()) {
    const match = line.match(/^\s{2,}\/?(@?[^@\s][^@\s/]*(?:\/[^@\s]+)?|[^@\s]+)@(\d+\.\d+\.\d+[^:\s]*):\s*$/)
    if (!match) continue
    candidates.push({ name: match[1], version: cleanVersion(match[2]), ecosystem: "npm", filePath: file.path, lineStart: index + 1, direct: false })
  }
  return candidates
}

function extractRequirements(file: ProjectFile): PackageCandidate[] {
  return file.text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.!+-]+)/)
    if (!match) return []
    return [{ name: match[1], version: match[2], ecosystem: "PyPI", filePath: file.path, lineStart: index + 1, direct: true }]
  })
}

function extractPyProject(file: ProjectFile): PackageCandidate[] {
  return file.text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/["']?([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)["']?/)
    if (!match) return []
    return [{ name: match[1], version: match[2], ecosystem: "PyPI", filePath: file.path, lineStart: index + 1, direct: true }]
  })
}

function extractCargoLock(file: ProjectFile): PackageCandidate[] {
  const candidates: PackageCandidate[] = []
  const blocks = file.text.split(/\n\[\[package\]\]\n/g)
  let lineOffset = 1
  for (const block of blocks) {
    const name = block.match(/name\s*=\s*"([^"]+)"/)?.[1]
    const version = block.match(/version\s*=\s*"([^"]+)"/)?.[1]
    if (name && version) candidates.push({ name, version, ecosystem: "crates.io", filePath: file.path, lineStart: lineOffset, direct: false })
    lineOffset += block.split(/\r?\n/).length
  }
  return candidates
}

function extractCargoToml(file: ProjectFile): PackageCandidate[] {
  return file.text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*"(\d+\.\d+\.\d+[^"]*)"/)
    if (!match) return []
    return [{ name: match[1], version: cleanVersion(match[2]), ecosystem: "crates.io", filePath: file.path, lineStart: index + 1, direct: true }]
  })
}

function extractGoSum(file: ProjectFile): PackageCandidate[] {
  return file.text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/^(\S+)\s+v?(\d+\.\d+\.\d+[^\s]*)\s+/)
    if (!match) return []
    return [{ name: match[1], version: `v${match[2].replace(/^v/, "")}`, ecosystem: "Go", filePath: file.path, lineStart: index + 1, direct: false }]
  })
}

function extractGemfileLock(file: ProjectFile): PackageCandidate[] {
  return file.text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/^\s{4}([A-Za-z0-9_.-]+)\s+\(([\d.]+[^)]*)\)/)
    if (!match) return []
    return [{ name: match[1], version: cleanVersion(match[2]), ecosystem: "RubyGems", filePath: file.path, lineStart: index + 1, direct: false }]
  })
}

function candidateFromRange(file: ProjectFile, name: string, raw: string, ecosystem: PackageCandidate["ecosystem"], devOnly: boolean) {
  const version = cleanVersion(raw)
  if (!/^\d+\.\d+\.\d+/.test(version)) return []
  return exactCandidate(file, name, version, ecosystem, devOnly)
}

function exactCandidate(file: ProjectFile, name: string, version: string | undefined, ecosystem: PackageCandidate["ecosystem"], devOnly = false): PackageCandidate[] {
  if (!version || !/^\d+\.\d+\.\d+/.test(cleanVersion(version))) return []
  return [{ name, version: cleanVersion(version), ecosystem, filePath: file.path, lineStart: findLine(file.text, name), direct: true, devOnly }]
}

function dedupeCandidates(candidates: PackageCandidate[]) {
  const seen = new Set<string>()
  return candidates.filter((candidate) => {
    const key = `${candidate.ecosystem}:${candidate.name}@${candidate.version}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function severityFromOsv(vuln: OsvVulnerability): Severity {
  const raw = `${vuln.database_specific?.severity ?? ""} ${vuln.severity?.map((item) => item.score).join(" ") ?? ""}`.toLowerCase()
  if (/critical|9\.[0-9]|10\.0/.test(raw)) return "critical"
  if (/high|[78]\.[0-9]/.test(raw)) return "high"
  if (/medium|[456]\.[0-9]/.test(raw)) return "medium"
  if (/low|[123]\.[0-9]/.test(raw)) return "low"
  return "medium"
}

function firstFixedVersion(vuln: OsvVulnerability) {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      const fixed = range.events?.find((event) => event.fixed)?.fixed
      if (fixed) return fixed
    }
  }
  return null
}

function isManifestFile(file: ProjectFile) {
  return /(^|\/)(package\.json|requirements\.txt|pyproject\.toml|Cargo\.toml|go\.mod|Gemfile|composer\.json)$/i.test(file.path)
}

function isLockfile(file: ProjectFile) {
  return /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|poetry\.lock|Pipfile\.lock|composer\.lock)$/i.test(file.path)
}

function cleanVersion(raw: string) {
  return raw.trim().replace(/^[~^<>=\s]+/, "").replace(/\s.*$/, "")
}

function findLine(text: string, needle: string) {
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(needle))
  return index >= 0 ? index + 1 : undefined
}

function basename(path: string) {
  return path.split("/").pop() ?? path
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
