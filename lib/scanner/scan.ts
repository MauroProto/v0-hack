import type { AuditTrailEvent, ScanFinding, ScanInput, ScanReport } from "./types"
import { runHybridAnalyzers } from "./analyzers"
import { calculateRiskScore, createDeterministicPatch } from "./patches"
import { normalizeFindings, withReportDerivedFields } from "./enrich"
import { applyReportPolicy } from "./reportPolicy"
import { compareFindingsForReport } from "./prioritize"

export async function scanProject(input: ScanInput): Promise<ScanReport> {
  const startedAt = new Date()
  const analysisMode = input.analysisMode ?? "normal"
  const analyzerResult = await runHybridAnalyzers(input.files)
  const { dependencyResult, repoInventory, ruleResult } = analyzerResult
  const allRawFindings = analyzerResult.findings
  const findings = normalizeFindings(allRawFindings
    .map<ScanFinding>((finding, index) => ({
      ...finding,
      id: `F-${String(index + 1).padStart(3, "0")}`,
    }))
    .sort(compareFindingsForReport)
    .map((finding, index) => {
      const withStableId = { ...finding, id: `F-${String(index + 1).padStart(3, "0")}` }
      return {
        ...withStableId,
        patch: createDeterministicPatch(withStableId),
      }
    }))
  const auditTrail: AuditTrailEvent[] = [
    ...(input.auditTrail ?? []),
    auditEvent("Select analysis depth", "complete", {
      mode: analysisMode,
      filesAccepted: input.files.length,
    }),
    auditEvent("Fingerprint project", "complete", {
      framework: ruleResult.signals.framework ?? "unknown",
      files: input.files.length,
    }),
    auditEvent("Run deterministic security rules", "complete", {
      findings: ruleResult.findings.length,
      aiEndpoints: ruleResult.stats.aiEndpointsInspected,
    }),
    auditEvent("Run inter-file taint analysis", "complete", {
      findings: analyzerResult.interfileFindings.length,
      maxDepth: 3,
    }),
    auditEvent("Run OSV dependency intelligence", dependencyResult.summary.error ? "failed" : "complete", {
      packages: dependencyResult.summary.packages,
      vulnerablePackages: dependencyResult.summary.vulnerablePackages,
      ecosystems: dependencyResult.summary.ecosystems.join(", ") || "none",
      error: dependencyResult.summary.error,
    }),
    auditEvent("Build repository inventory", "complete", {
      languages: repoInventory.languages.join(", ") || "unknown",
      serverActions: repoInventory.serverActions,
      workflows: repoInventory.githubWorkflows,
      supabaseMigrations: repoInventory.supabaseMigrations,
    }),
    auditEvent("Generate conservative patch templates", "complete", {
      patchable: findings.filter((finding) => finding.patchable).length,
    }),
  ]

  return applyReportPolicy(withReportDerivedFields({
    id: crypto.randomUUID(),
    createdAt: startedAt.toISOString(),
    projectName: input.projectName,
    framework: ruleResult.signals.framework,
    sourceType: input.sourceType,
    sourceLabel: input.sourceLabel,
    analysisMode,
    status: "completed",
    riskScore: calculateRiskScore(findings),
    dependencySummary: dependencyResult.summary,
    repoInventory,
    sarifAvailable: true,
    filesInspected: input.files.length,
    apiRoutesInspected: ruleResult.stats.apiRoutesInspected,
    clientComponentsInspected: ruleResult.stats.clientComponentsInspected,
    aiEndpointsInspected: ruleResult.stats.aiEndpointsInspected,
    findings,
    auditTrail,
  }), input.files)
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
