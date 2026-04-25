import type { AuditTrailEvent, ScanFinding, ScanInput, ScanReport, Severity } from "./types"
import { calculateRiskScore, createDeterministicPatch } from "./patches"
import { collectRuleFindings } from "./rules"

export function scanProject(input: ScanInput): ScanReport {
  const startedAt = new Date()
  const ruleResult = collectRuleFindings(input.files)
  const findings = ruleResult.findings
    .map<ScanFinding>((finding, index) => ({
      ...finding,
      id: `F-${String(index + 1).padStart(3, "0")}`,
    }))
    .sort(compareFindings)
    .map((finding, index) => {
      const withStableId = { ...finding, id: `F-${String(index + 1).padStart(3, "0")}` }
      return {
        ...withStableId,
        patch: createDeterministicPatch(withStableId),
      }
    })

  const auditTrail: AuditTrailEvent[] = [
    ...(input.auditTrail ?? []),
    auditEvent("Fingerprint project", "complete", {
      framework: ruleResult.signals.framework ?? "unknown",
      files: input.files.length,
    }),
    auditEvent("Run deterministic security rules", "complete", {
      findings: findings.length,
      aiEndpoints: ruleResult.stats.aiEndpointsInspected,
    }),
    auditEvent("Generate conservative patch templates", "complete", {
      patchable: findings.filter((finding) => finding.patchable).length,
    }),
  ]

  return {
    id: crypto.randomUUID(),
    createdAt: startedAt.toISOString(),
    projectName: input.projectName,
    framework: ruleResult.signals.framework,
    sourceType: input.sourceType,
    sourceLabel: input.sourceLabel,
    status: "completed",
    riskScore: calculateRiskScore(findings),
    filesInspected: input.files.length,
    apiRoutesInspected: ruleResult.stats.apiRoutesInspected,
    clientComponentsInspected: ruleResult.stats.clientComponentsInspected,
    aiEndpointsInspected: ruleResult.stats.aiEndpointsInspected,
    findings,
    auditTrail,
  }
}

export function auditEvent(
  label: string,
  status: AuditTrailEvent["status"],
  metadata?: Record<string, unknown>,
): AuditTrailEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    label,
    status,
    metadata,
  }
}

function compareFindings(a: ScanFinding, b: ScanFinding) {
  const severityDelta = severityRank(b.severity) - severityRank(a.severity)
  if (severityDelta !== 0) return severityDelta
  return a.filePath.localeCompare(b.filePath)
}

function severityRank(severity: Severity) {
  if (severity === "critical") return 5
  if (severity === "high") return 4
  if (severity === "medium") return 3
  if (severity === "low") return 2
  return 1
}
