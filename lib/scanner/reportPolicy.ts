import type { ProjectFile, ScanBaseline, ScanFinding, ScanReport } from "./types"
import { withReportDerivedFields } from "./enrich"

type SuppressionRule =
  | { kind: "rule"; value: string }
  | { kind: "fingerprint"; value: string }
  | { kind: "category"; value: string }
  | { kind: "path"; value: string; regex: RegExp }

export function applyReportPolicy(report: ScanReport, files: ProjectFile[], baseline?: ScanBaseline | null): ScanReport {
  const suppressionRules = parseBadgerIgnore(files)
  const suppressed = applySuppressions(report.findings, suppressionRules)
  const withBaseline = applyBaselineToFindings(suppressed, baseline)
  const resolved = countResolvedFindings(withBaseline, baseline)

  return withReportDerivedFields({
    ...report,
    findings: withBaseline,
    baselineSummary: baseline
      ? {
          new: withBaseline.filter((finding) => finding.baselineState === "new").length,
          existing: withBaseline.filter((finding) => finding.baselineState === "existing").length,
          resolved,
          suppressed: withBaseline.filter((finding) => finding.suppressed).length,
        }
      : report.baselineSummary,
  })
}

export function createBaselineFromReport(report: ScanReport): ScanBaseline {
  const activeFingerprints = report.findings
    .filter((finding) => !finding.suppressed && finding.fingerprint)
    .map((finding) => finding.fingerprint as string)

  const now = new Date().toISOString()
  return {
    id: baselineIdFor(report.sourceLabel, report.ownerHash),
    sourceLabel: report.sourceLabel,
    ownerHash: report.ownerHash,
    createdAt: now,
    updatedAt: now,
    fingerprints: [...new Set(activeFingerprints)].sort(),
    findingCount: activeFingerprints.length,
    scannerVersion: report.scannerVersion,
  }
}

export function baselineIdFor(sourceLabel: string, ownerHash?: string) {
  return `${ownerHash ?? "public"}:${sourceLabel}`.toLowerCase()
}

function parseBadgerIgnore(files: ProjectFile[]): SuppressionRule[] {
  const ignore = files.find((file) => {
    const normalized = normalizePath(file.path)
    return normalized === ".badgerignore" || normalized === ".badgerignore"
  })
  if (!ignore) return []

  const rules: SuppressionRule[] = []
  for (const rawLine of ignore.text.split(/\r?\n/)) {
    const line = rawLine.split("#")[0]?.trim()
    if (!line) continue

    const [prefix, ...rest] = line.split(":")
    const value = rest.join(":").trim()
    if (!value) continue

    if (prefix === "rule") rules.push({ kind: "rule", value })
    else if (prefix === "fingerprint") rules.push({ kind: "fingerprint", value })
    else if (prefix === "category") rules.push({ kind: "category", value })
    else if (prefix === "path") rules.push({ kind: "path", value, regex: globToRegex(value) })
  }

  return rules
}

function applySuppressions(findings: ScanFinding[], rules: SuppressionRule[]) {
  if (rules.length === 0) return findings

  return findings.map((finding) => {
    const rule = rules.find((candidate) => matchesSuppression(candidate, finding))
    if (!rule) return finding

    return {
      ...finding,
      suppressed: true,
      suppressionReason: `${rule.kind}:${rule.value}`,
    }
  })
}

function matchesSuppression(rule: SuppressionRule, finding: ScanFinding) {
  if (rule.kind === "rule") return finding.ruleId === rule.value
  if (rule.kind === "fingerprint") return finding.fingerprint === rule.value
  if (rule.kind === "category") return finding.category === rule.value
  return rule.regex.test(normalizePath(finding.filePath))
}

function applyBaselineToFindings(findings: ScanFinding[], baseline?: ScanBaseline | null): ScanFinding[] {
  if (!baseline) return findings

  const baselineFingerprints = new Set(baseline.fingerprints)
  return findings.map((finding) => {
    if (finding.suppressed || !finding.fingerprint) return finding
    return {
      ...finding,
      baselineState: baselineFingerprints.has(finding.fingerprint) ? "existing" as const : "new" as const,
    }
  })
}

function countResolvedFindings(findings: ScanFinding[], baseline?: ScanBaseline | null) {
  if (!baseline) return 0

  const activeFingerprints = new Set(
    findings
      .filter((finding) => !finding.suppressed && finding.fingerprint)
      .map((finding) => finding.fingerprint as string),
  )
  return baseline.fingerprints.filter((fingerprint) => !activeFingerprints.has(fingerprint)).length
}

function globToRegex(glob: string) {
  const normalized = normalizePath(glob)
  const token = "\u0000DOUBLE_STAR\u0000"
  const pattern = normalized
    .replaceAll("**", token)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replaceAll("*", "[^/]*")
    .replaceAll(token, ".*")
  return new RegExp(`^${pattern}$`)
}

function normalizePath(path: string) {
  return path.replaceAll("\\", "/").replace(/^\/+/, "")
}
