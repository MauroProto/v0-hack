import type { ScanFinding, Severity } from "./types"

export function compareFindingsForReport(a: ScanFinding, b: ScanFinding) {
  const severityDelta = severityRank(b.severity) - severityRank(a.severity)
  if (severityDelta !== 0) return severityDelta

  const priorityDelta = findingPriorityRank(a) - findingPriorityRank(b)
  if (priorityDelta !== 0) return priorityDelta

  const sourceDelta = sourceRank(a) - sourceRank(b)
  if (sourceDelta !== 0) return sourceDelta

  const pathDelta = a.filePath.localeCompare(b.filePath)
  if (pathDelta !== 0) return pathDelta
  return (a.lineStart ?? 0) - (b.lineStart ?? 0)
}

export function severityRank(severity: Severity) {
  if (severity === "critical") return 5
  if (severity === "high") return 4
  if (severity === "medium") return 3
  if (severity === "low") return 2
  return 1
}

function findingPriorityRank(finding: ScanFinding) {
  const signature = `${finding.ruleId ?? ""} ${finding.title}`.toLowerCase()
  if (finding.category === "mcp_risk" && /inherits|environment|env/.test(signature)) return 0
  if (finding.category === "mcp_risk") return 1
  if (finding.category === "unsafe_tool_calling" && /shell|bash|tool|agent/.test(signature)) return 2
  if (finding.category === "command_injection" || finding.category === "sql_injection" || finding.category === "ssrf" || finding.category === "xss") return 3
  if (finding.category === "secret_exposure" || finding.category === "public_env_misuse") return 4
  if (finding.category === "ai_endpoint_risk" || finding.category === "ai_unbounded_consumption" || finding.category === "ai_excessive_agency") return 5
  if (finding.kind === "vulnerability") return 6
  if (finding.category === "repo_security_posture" && /github-actions|workflow|release|secret|write/.test(signature)) return 7
  if (finding.category === "supply_chain_posture") return 8
  if (finding.kind === "repo_posture") return 9
  if (finding.category === "dependency_vulnerability") return 10
  if (finding.category === "dependency_signal") return 11
  if (finding.kind === "hardening") return 12
  if (finding.kind === "platform_recommendation") return 13
  return 14
}

function sourceRank(finding: ScanFinding) {
  if (finding.source === "hybrid") return 0
  if (finding.source === "rule") return 1
  return 2
}
