import { withReportDerivedFields } from "@/lib/scanner/enrich"
import type {
  FindingCategory,
  FindingKind,
  FindingTriageVerdict,
  ReportAiTriage,
  RiskBand,
  RiskBreakdown,
  RiskBreakdownBucket,
  ScanFinding,
  ScanReport,
  Severity,
  TriagePriority,
} from "@/lib/scanner/types"

type AiFindingTriage = {
  findingId: string
  verdict: FindingTriageVerdict
  reason: string
  adjustedSeverity?: Severity
  adjustedKind?: FindingKind
  adjustedCategory?: FindingCategory
  confidence: number
  detectedControls?: string[]
  missingControls?: string[]
  attackScenario?: string
  priority?: TriagePriority
}

export type AiTriageOutput = {
  triage?: AiFindingTriage[]
  reportSummary?: {
    riskNarrative: string
    recommendedNextSteps: string[]
    runtimeAgentRisk?: RiskBand | string
    repoPostureRisk?: RiskBand | string
    dependencyRisk?: RiskBand | string
    secretsRisk?: RiskBand | string
  }
  model?: string
  provider?: string
  reasoningEffort?: string
}

export function applyAiTriage(report: ScanReport, output: AiTriageOutput): ScanReport {
  const triageById = new Map((output.triage ?? []).map((entry) => [entry.findingId, entry]))
  const findings = report.findings.map((finding) => applyFindingTriage(finding, triageById.get(finding.id)))
  const derived = withReportDerivedFields({
    ...report,
    findings,
    aiTriage: buildReportAiTriage(output, triageById, report.aiTriage),
  })

  return {
    ...derived,
    riskBreakdown: buildRiskBreakdown(derived.findings, output.reportSummary, report.riskBreakdown),
  }
}

export function buildRiskBreakdown(
  findings: ScanFinding[],
  labels?: AiTriageOutput["reportSummary"],
  fallback?: RiskBreakdown,
): RiskBreakdown {
  const active = findings.filter((finding) => !finding.suppressed)

  return {
    runtimeAgentRisk: bucketRisk(
      scoreBucket(active.filter(isRuntimeAgentFinding)),
      labels?.runtimeAgentRisk,
      fallback?.runtimeAgentRisk,
    ),
    repoPostureRisk: bucketRisk(
      scoreBucket(active.filter(isRepoPostureFinding)),
      labels?.repoPostureRisk,
      fallback?.repoPostureRisk,
    ),
    dependencyRisk: bucketRisk(
      scoreBucket(active.filter(isDependencyFinding)),
      labels?.dependencyRisk,
      fallback?.dependencyRisk,
    ),
    secretsRisk: bucketRisk(
      scoreBucket(active.filter(isSecretFinding)),
      labels?.secretsRisk,
      fallback?.secretsRisk,
    ),
  }
}

function applyFindingTriage(finding: ScanFinding, triage?: AiFindingTriage): ScanFinding {
  if (!triage) return finding

  const baseTriage = {
    verdict: triage.verdict,
    reason: cleanText(triage.reason, 520) || "AI triage did not provide a reason.",
    confidence: clamp(triage.confidence, 0, 1),
    reviewedBy: "ai" as const,
    detectedControls: cleanList(triage.detectedControls, 8, 120),
    missingControls: cleanList(triage.missingControls, 8, 120),
    attackScenario: cleanText(triage.attackScenario ?? "", 520) || undefined,
    priority: triage.priority,
  }

  if (shouldSuppressSupportedFalsePositive(finding, triage, baseTriage.reason)) {
    const adjustedSeverity = normalizeAdjustedSeverity(finding, triage)
    const adjustedKind = normalizeAdjustedKind(finding, triage)
    const adjustedCategory = normalizeAdjustedCategory(finding, triage)
    const changed =
      adjustedSeverity !== finding.severity ||
      adjustedKind !== finding.kind ||
      adjustedCategory !== finding.category

    return {
      ...finding,
      severity: adjustedSeverity,
      kind: adjustedKind,
      category: adjustedCategory,
      confidence: adjustedConfidence(finding, triage),
      suppressed: true,
      suppressionReason: "ai:likely_false_positive",
      patchable: false,
      triage: {
        ...baseTriage,
        adjustedFrom: changed
          ? {
              severity: finding.severity,
              kind: finding.kind,
              category: finding.category,
            }
          : undefined,
      },
    }
  }

  if (shouldBlockTriageAdjustment(finding, triage)) {
    return {
      ...finding,
      triage: {
        ...baseTriage,
        verdict: "needs_review",
        reason: `AI downgrade blocked by VibeShield guardrail: ${baseTriage.reason}`,
      },
    }
  }

  const adjustedSeverity = normalizeAdjustedSeverity(finding, triage)
  const adjustedKind = normalizeAdjustedKind(finding, triage)
  const adjustedCategory = normalizeAdjustedCategory(finding, triage)
  const changed =
    adjustedSeverity !== finding.severity ||
    adjustedKind !== finding.kind ||
    adjustedCategory !== finding.category

  return {
    ...finding,
    severity: adjustedSeverity,
    kind: adjustedKind,
    category: adjustedCategory,
    confidence: adjustedConfidence(finding, triage),
    triage: {
      ...baseTriage,
      adjustedFrom: changed
        ? {
            severity: finding.severity,
            kind: finding.kind,
            category: finding.category,
          }
        : undefined,
    },
  }
}

function shouldBlockTriageAdjustment(finding: ScanFinding, triage: AiFindingTriage) {
  const protectedSecret =
    (finding.category === "secret_exposure" || finding.category === "public_env_misuse") &&
    (finding.severity === "critical" || /sk-|secret|private|token|service[_-]?role|database_url/i.test(finding.evidence ?? finding.title))

  if (protectedSecret && isSupportedFalsePositiveContext(finding, triage.reason) && triage.confidence >= 0.9) return false
  if (!protectedSecret) return false
  if (triage.verdict === "likely_false_positive" || triage.verdict === "posture_only") return true
  if (triage.adjustedKind && triage.adjustedKind !== "vulnerability") return true
  if (triage.adjustedCategory && triage.adjustedCategory !== finding.category) return true
  if (triage.adjustedSeverity && severityRank(triage.adjustedSeverity) < severityRank(finding.severity)) return true
  return false
}

function shouldSuppressSupportedFalsePositive(finding: ScanFinding, triage: AiFindingTriage, reason: string) {
  if (triage.verdict !== "likely_false_positive") return false
  if (triage.confidence < 0.85) return false
  return isSupportedFalsePositiveContext(finding, reason)
}

function isSupportedFalsePositiveContext(finding: ScanFinding, reason: string) {
  const path = finding.filePath.replaceAll("\\", "/").toLowerCase()
  const evidence = `${finding.evidence ?? ""}\n${finding.title}\n${finding.ruleId ?? ""}\n${reason}`.toLowerCase()

  if (isEnvFilePath(path) && !isClearlyFixtureOrDetectorPath(path)) return false

  const detectorContext =
    /(^|\/)(lib|src)\/(?:scanner|security-scanner|sast|rules?)\//.test(path) ||
    /(^|\/)(rules?|detectors?|analyzers?|reviewproject)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)
  if (detectorContext && /\b(detector|allowlist|denylist|pattern|regex|regexp|rule|harness|scanner|triage|redaction)\b/.test(evidence)) {
    return true
  }

  const fixtureContext =
    /(^|\/)(__tests__|__fixtures__|tests?|fixtures?|snapshots?|examples?)\//.test(path) ||
    /(^|[._-])(test|tests|spec|fixture|fixtures|smoke)\.(ts|tsx|js|jsx|rs|py|go|java|rb|php|md|yml|yaml)$/.test(path)
  if (fixtureContext && /\b(test|fixture|snapshot|mock|example|demo|placeholder|redacted|redaction|assert|expect|not a real|not real)\b/.test(evidence)) {
    return true
  }

  const documentationContext = /(^|\/)(docs?|readme|examples?)\//.test(path) || /(^|\/)readme(\.|$)/.test(path)
  if (documentationContext && /\b(example|placeholder|demo|redacted|documentation|docs|readme)\b/.test(evidence)) {
    return true
  }

  if (/\b(comment|regex\.exec|regexp\.exec|detector code|rule definition|string literal|scanner's own|scanner own)\b/.test(evidence)) {
    return true
  }

  return false
}

function isEnvFilePath(path: string) {
  const name = path.split("/").pop() ?? path
  return name === ".env" || name.startsWith(".env.")
}

function isClearlyFixtureOrDetectorPath(path: string) {
  return /(^|\/)(__tests__|__fixtures__|tests?|fixtures?|snapshots?|examples?)\//.test(path) ||
    /(^|[._-])(test|tests|spec|fixture|fixtures|smoke)\./.test(path) ||
    /(^|\/)(lib|src)\/(?:scanner|security-scanner|sast|rules?)\//.test(path)
}

function normalizeAdjustedSeverity(finding: ScanFinding, triage: AiFindingTriage): Severity {
  const requested = triage.adjustedSeverity
  if (triage.verdict === "likely_false_positive") return "info"
  if (triage.verdict === "posture_only") return capSeverity(requested ?? "medium", "medium")
  if (!requested) return finding.severity

  if (requested === "critical" && finding.severity !== "critical" && !isSecretFinding(finding)) return "high"
  if (triage.verdict === "needs_review" && severityRank(requested) > severityRank(finding.severity)) return finding.severity
  return requested
}

function normalizeAdjustedKind(finding: ScanFinding, triage: AiFindingTriage): FindingKind | undefined {
  if (triage.verdict === "likely_false_positive") return "info"
  if (triage.verdict === "posture_only") return triage.adjustedKind ?? "repo_posture"
  return triage.adjustedKind ?? finding.kind
}

function normalizeAdjustedCategory(finding: ScanFinding, triage: AiFindingTriage): FindingCategory {
  if (triage.verdict === "likely_false_positive") return triage.adjustedCategory ?? finding.category
  if (triage.verdict === "posture_only") return triage.adjustedCategory ?? "repo_security_posture"

  if (triage.adjustedCategory === "secret_exposure" || triage.adjustedCategory === "public_env_misuse") {
    return isSecretFinding(finding) ? triage.adjustedCategory : finding.category
  }

  return triage.adjustedCategory ?? finding.category
}

function adjustedConfidence(finding: ScanFinding, triage: AiFindingTriage) {
  if (triage.verdict === "likely_false_positive") return Math.min(finding.confidence, Math.max(0.25, triage.confidence * 0.45))
  if (triage.verdict === "posture_only") return Math.min(0.9, Math.max(0.45, triage.confidence))
  return Math.min(0.95, Math.max(finding.confidence, triage.confidence * 0.9))
}

function buildReportAiTriage(
  output: AiTriageOutput,
  triageById: Map<string, AiFindingTriage>,
  existing?: ReportAiTriage,
): ReportAiTriage | undefined {
  const summary = output.reportSummary
  if (!summary && !triageById.size && !existing) return undefined

  return {
    riskNarrative: cleanText(summary?.riskNarrative ?? existing?.riskNarrative ?? "AI triage reviewed deterministic findings and preserved scanner guardrails.", 900),
    recommendedNextSteps: cleanList(summary?.recommendedNextSteps ?? existing?.recommendedNextSteps ?? [], 8, 360),
    model: output.model ?? existing?.model,
    provider: output.provider ?? existing?.provider,
    reasoningEffort: output.reasoningEffort ?? existing?.reasoningEffort,
    reviewedFindings: triageById.size || existing?.reviewedFindings || 0,
  }
}

function scoreBucket(findings: ScanFinding[]) {
  if (!findings.length) return 0
  const rootCauses = new Map<string, number[]>()

  for (const finding of findings) {
    const key = `${finding.kind ?? "unknown"}:${finding.category}:${finding.ruleId ?? finding.title}`
    rootCauses.set(key, [...(rootCauses.get(key) ?? []), scoreRiskFinding(finding)])
  }

  let score = 0
  for (const values of rootCauses.values()) {
    const sorted = values.sort((a, b) => b - a)
    score += (sorted[0] ?? 0) + sorted.slice(1).reduce((total, value) => total + value * 0.2, 0)
  }

  return Math.min(100, Math.round(score))
}

function scoreRiskFinding(finding: ScanFinding) {
  const base =
    finding.severity === "critical" ? 34 :
    finding.severity === "high" ? 22 :
    finding.severity === "medium" ? 12 :
    finding.severity === "low" ? 5 :
    1
  const kindMultiplier =
    finding.kind === "repo_posture" ? 0.55 :
    finding.kind === "hardening" ? 0.45 :
    finding.kind === "info" ? 0.25 :
    1
  const confidence = Math.max(0.35, Math.min(1, finding.confidence || 0.7))
  const reachability = finding.reachability === "reachable" ? 1.18 : finding.reachability === "unreachable" ? 0.45 : 1
  const exploitability = finding.exploitability === "high" ? 1.18 : finding.exploitability === "low" ? 0.75 : 1
  return base * kindMultiplier * confidence * reachability * exploitability
}

function bucketRisk(score: number, requested?: RiskBand | string, fallback?: RiskBreakdownBucket): RiskBreakdownBucket {
  const requestedLabel = normalizeRiskBand(requested)
  if (score <= 0) {
    if (requestedLabel && labelFloor(requestedLabel) >= 20) {
      return { score: labelFloor(requestedLabel), label: requestedLabel }
    }
    return { score: 0, label: "None" }
  }
  if (requestedLabel) return { score: Math.max(score, labelFloor(requestedLabel)), label: requestedLabel }
  if (score > 0) return { score, label: labelForScore(score) }
  return fallback ?? { score: 0, label: "None" }
}

function normalizeRiskBand(value?: RiskBand | string): RiskBand | null {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) return null
  if (normalized === "none" || normalized === "no" || normalized === "clear") return "None"
  if (normalized === "low") return "Low"
  if (normalized === "medium" || normalized === "moderate") return "Moderate"
  if (normalized === "high") return "High"
  if (normalized === "critical") return "Critical"
  return null
}

function labelForScore(score: number): RiskBand {
  if (score <= 0) return "None"
  if (score <= 19) return "Low"
  if (score <= 44) return "Moderate"
  if (score <= 74) return "High"
  return "Critical"
}

function labelFloor(label: RiskBand) {
  if (label === "Critical") return 75
  if (label === "High") return 45
  if (label === "Moderate") return 20
  if (label === "Low") return 1
  return 0
}

function isRuntimeAgentFinding(finding: ScanFinding) {
  return (
    finding.category === "mcp_risk" ||
    finding.category === "unsafe_tool_calling" ||
    finding.category === "ai_endpoint_risk" ||
    finding.category === "ai_prompt_injection_risk" ||
    finding.category === "ai_excessive_agency" ||
    finding.category === "ai_unbounded_consumption" ||
    finding.category === "command_injection" ||
    /agent|mcp|tool|shell/i.test(`${finding.ruleId ?? ""} ${finding.title}`)
  )
}

function isRepoPostureFinding(finding: ScanFinding) {
  return (
    finding.kind === "repo_posture" ||
    finding.category === "repo_security_posture" ||
    finding.category === "supply_chain_posture" ||
    finding.category === "platform_hardening" ||
    finding.category === "vercel_hardening"
  )
}

function isDependencyFinding(finding: ScanFinding) {
  return finding.category === "dependency_vulnerability" || finding.category === "dependency_signal"
}

function isSecretFinding(finding: Pick<ScanFinding, "category">) {
  return finding.category === "secret_exposure" || finding.category === "public_env_misuse"
}

function cleanList(values: string[] | undefined, maxItems: number, maxLength: number) {
  return (values ?? [])
    .map((value) => cleanText(value, maxLength))
    .filter(Boolean)
    .slice(0, maxItems)
}

function cleanText(value: string, maxLength: number) {
  const normalized = value.replace(/\s+/g, " ").trim()
  if (normalized.length <= maxLength) return normalized
  const clipped = normalized.slice(0, maxLength)
  const lastSpace = clipped.lastIndexOf(" ")
  return `${(lastSpace > maxLength * 0.65 ? clipped.slice(0, lastSpace) : clipped).trim()}...`
}

function capSeverity(severity: Severity, max: Severity): Severity {
  return severityRank(severity) > severityRank(max) ? max : severity
}

function severityRank(severity: Severity) {
  if (severity === "critical") return 5
  if (severity === "high") return 4
  if (severity === "medium") return 3
  if (severity === "low") return 2
  return 1
}

function clamp(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) return min
  return Math.min(max, Math.max(min, value))
}
