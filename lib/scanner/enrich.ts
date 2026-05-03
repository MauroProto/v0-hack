import { createHash } from "node:crypto"
import type { BaselineSummary, FindingGroups, FindingKind, ScanFinding, ScanReport } from "./types"
import { buildRiskBreakdown } from "./riskBreakdown"

export const SCANNER_VERSION = "badger-hybrid-0.3"

export function normalizeFinding(finding: ScanFinding): ScanFinding {
  const kind = finding.kind ?? inferFindingKind(finding)
  const ruleId = finding.ruleId ?? defaultRuleId(finding)

  return {
    reachability: "unknown",
    exploitability: "unknown",
    ...finding,
    kind,
    ruleId,
    fingerprint: finding.fingerprint ?? fingerprintFinding({ ...finding, kind, ruleId }),
  }
}

export function normalizeFindings(findings: ScanFinding[]) {
  return findings.map(normalizeFinding)
}

export function withReportDerivedFields(report: ScanReport): ScanReport {
  const findings = normalizeFindings(report.findings)
  const activeFindings = findings.filter((finding) => !finding.suppressed)

  return {
    ...report,
    scannerVersion: report.scannerVersion ?? SCANNER_VERSION,
    sarifAvailable: true,
    findings,
    riskScore: calculateHybridRiskScore(activeFindings),
    riskBreakdown: buildRiskBreakdown(findings, undefined, report.riskBreakdown),
    findingGroups: groupFindings(activeFindings),
    baselineSummary: summarizeBaseline(findings, report.baselineSummary),
  }
}

export function groupFindings(findings: Pick<ScanFinding, "kind" | "category" | "severity">[]): FindingGroups {
  const groups: FindingGroups = {
    vulnerabilities: 0,
    hardening: 0,
    repo_posture: 0,
    platform_recommendations: 0,
    informational: 0,
  }

  for (const finding of findings) {
    const kind = finding.kind ?? inferFindingKind(finding as ScanFinding)
    if (kind === "vulnerability") groups.vulnerabilities += 1
    else if (kind === "hardening") groups.hardening += 1
    else if (kind === "repo_posture") groups.repo_posture += 1
    else if (kind === "platform_recommendation") groups.platform_recommendations += 1
    else groups.informational += 1
  }

  return groups
}

type ScoreableFinding = Pick<ScanFinding, "severity" | "confidence" | "kind" | "category" | "reachability" | "exploitability"> &
  Partial<Pick<ScanFinding, "ruleId" | "title" | "filePath">>

export function calculateHybridRiskScore(findings: ScoreableFinding[]) {
  const grouped = new Map<string, number[]>()
  for (const finding of findings) {
    const key = riskRootCauseKey(finding)
    grouped.set(key, [...(grouped.get(key) ?? []), scoreFinding(finding)])
  }

  let score = 0
  for (const values of grouped.values()) {
    const sorted = [...values].sort((a, b) => b - a)
    const head = sorted[0] ?? 0
    const tail = sorted.slice(1).reduce((total, value) => total + value * 0.25, 0)
    score += Math.min(head + tail, Math.max(head, 28))
  }

  return Math.min(100, Math.round(applyRiskCaps(score, findings)))
}

function scoreFinding(finding: ScoreableFinding) {
  const kind = finding.kind ?? inferFindingKind(finding as ScanFinding)
  if (kind === "platform_recommendation") return finding.severity === "info" ? 0.5 : 1.5
  if (kind === "repo_posture") return finding.severity === "high" ? 6 : finding.severity === "medium" ? 3 : 1
  if (kind === "hardening") return finding.severity === "high" ? 7 : finding.severity === "medium" ? 4 : finding.severity === "low" ? 2 : 0.5
  if (kind === "info") return 0.5

  const base =
    finding.severity === "critical" ? 24 :
    finding.severity === "high" ? 14 :
    finding.severity === "medium" ? 7 :
    finding.severity === "low" ? 3 :
    1

  const confidence = Math.max(0.35, Math.min(1, finding.confidence || 0.7))
  const reachable = finding.reachability === "reachable" ? 1.25 : finding.reachability === "unreachable" ? 0.35 : 1
  const exploitability = finding.exploitability === "high" ? 1.2 : finding.exploitability === "medium" ? 1.05 : finding.exploitability === "low" ? 0.8 : 1
  const categoryBoost =
    finding.category === "secret_exposure" || finding.category === "public_env_misuse" ? 1.15 :
    finding.category === "ai_endpoint_risk" || finding.category === "ai_unbounded_consumption" ? 1.1 :
    finding.category === "sql_injection" || finding.category === "command_injection" ? 1.2 :
    1

  return base * confidence * reachable * exploitability * categoryBoost
}

function riskRootCauseKey(finding: ScoreableFinding) {
  const kind = finding.kind ?? inferFindingKind(finding as ScanFinding)
  const ruleId = finding.ruleId ?? finding.title ?? finding.category
  if (kind === "vulnerability" && /missing_|server_action|input_validation|sql_injection|unsafe_redirect|command_injection/.test(finding.category)) {
    return `${kind}:${finding.category}:${ruleId}:${finding.filePath ?? ""}`
  }
  if (finding.category === "dependency_vulnerability" || finding.category === "dependency_signal" || finding.category === "supply_chain_posture") {
    return `${kind}:${finding.category}:${finding.title ?? ruleId}`
  }
  return `${kind}:${finding.category}:${ruleId}`
}

function applyRiskCaps(score: number, findings: ScoreableFinding[]) {
  const kinds = findings.map((finding) => finding.kind ?? inferFindingKind(finding as ScanFinding))
  const vulnerabilities = findings.filter((finding, index) => kinds[index] === "vulnerability")
  if (vulnerabilities.length === 0) return Math.min(score, 35)

  const hasCritical = vulnerabilities.some((finding) => finding.severity === "critical")
  const hasReachableHighImpact = vulnerabilities.some((finding) =>
    (finding.reachability === "reachable" || finding.category === "secret_exposure" || finding.category === "public_env_misuse") &&
    (finding.severity === "critical" || finding.exploitability === "high" || /sql_injection|command_injection|unsafe_tool_calling|mcp_risk/.test(finding.category)),
  )

  if (!hasCritical) return Math.min(score, hasReachableHighImpact ? 79 : 65)
  return score
}

export function inferFindingKind(finding: Pick<ScanFinding, "category" | "severity" | "title">): FindingKind {
  if (finding.category === "vercel_hardening" || finding.category === "platform_hardening") return "platform_recommendation"
  if (finding.category === "repo_security_posture" || finding.category === "supply_chain_posture") return "repo_posture"
  if (finding.category === "dependency_signal" && !/vulnerab/i.test(finding.title)) return "repo_posture"
  if (finding.severity === "info") return "info"
  return "vulnerability"
}

function defaultRuleId(finding: Pick<ScanFinding, "category" | "title" | "source">) {
  const slug = finding.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .slice(0, 72)
  return `${finding.source}.${finding.category}.${slug}`
}

function fingerprintFinding(finding: Pick<ScanFinding, "ruleId" | "category" | "filePath" | "lineStart" | "title" | "evidence" | "kind">) {
  const raw = [
    finding.ruleId,
    finding.kind,
    finding.category,
    finding.filePath,
    finding.lineStart ?? "",
    finding.title,
    finding.evidence ?? "",
  ].join("|")
  return createHash("sha256").update(raw).digest("hex").slice(0, 24)
}

function summarizeBaseline(findings: ScanFinding[], existing?: BaselineSummary): BaselineSummary | undefined {
  const summary: BaselineSummary = {
    new: 0,
    existing: 0,
    resolved: existing?.resolved ?? 0,
    suppressed: 0,
  }

  let hasBaselineState = Boolean(existing)
  for (const finding of findings) {
    if (finding.suppressed) summary.suppressed += 1
    if (finding.baselineState === "new") {
      summary.new += 1
      hasBaselineState = true
    } else if (finding.baselineState === "existing") {
      summary.existing += 1
      hasBaselineState = true
    }
  }

  if (!hasBaselineState && summary.suppressed === 0) return undefined
  return summary
}
