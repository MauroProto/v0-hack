import type { RiskBand, RiskBreakdown, RiskBreakdownBucket, ScanFinding } from "./types"

export type RiskBreakdownLabels = {
  runtimeAgentRisk?: RiskBand | string
  repoPostureRisk?: RiskBand | string
  dependencyRisk?: RiskBand | string
  secretsRisk?: RiskBand | string
}

export function buildRiskBreakdown(
  findings: ScanFinding[],
  labels?: RiskBreakdownLabels,
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
