import type { FindingKind, PatchSuggestion, ScanFinding, ScanReport } from "./types"
import { compareFindingsForReport } from "./prioritize"

export function getRiskLabel(score: number) {
  if (score <= 19) return "Low"
  if (score <= 49) return "Moderate"
  if (score <= 79) return "Action required"
  return "Critical"
}

export function calculateRiskScore(
  findings: Array<Pick<ScanFinding, "severity"> & Partial<Pick<ScanFinding, "confidence" | "kind" | "category" | "reachability" | "exploitability" | "ruleId" | "title" | "filePath">>>,
) {
  const normalized = findings.map((finding) => ({
    ...finding,
    confidence: typeof finding.confidence === "number" ? finding.confidence : 0.7,
    category: finding.category ?? "dangerous_code",
  }))
  const grouped = new Map<string, number[]>()
  for (const finding of normalized) {
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

  return Math.min(100, Math.round(applyRiskCaps(score, normalized)))
}

export function createDeterministicPatch(finding: ScanFinding): PatchSuggestion | undefined {
  if (!finding.patchable) return undefined

  if (finding.category === "input_validation") {
    return {
      title: "Validate request body with Zod",
      summary:
        "Add a route-specific schema based on the actual request contract and parse the JSON body before any business logic uses it.",
      reviewRequired: true,
    }
  }

  if (finding.category === "missing_auth") {
    return {
      title: "Add a server-side auth guard",
      summary:
        "Use the project's real authentication provider to verify the user on the server, then enforce role or ownership checks before returning sensitive data.",
      reviewRequired: true,
    }
  }

  if (finding.category === "ai_endpoint_risk") {
    if (/execution bounds|tool-calling/i.test(finding.title)) {
      return {
        title: "Bound AI tool execution",
        summary:
          "Add explicit tool-call step limits, token limits, and per-user quota/budget checks before allowing the model to invoke tools.",
        reviewRequired: true,
      }
    }

    return {
      title: "Add rate limiting before model calls",
      summary:
        "Insert the project's real quota, rate-limit, bot protection, and budget checks before the first model invocation in this route.",
      reviewRequired: true,
    }
  }

  if (finding.category === "public_env_misuse") {
    return {
      title: "Move public secret to server-only environment variable",
      summary: "Rename the variable without NEXT_PUBLIC_ and read it only from server code.",
      reviewRequired: true,
    }
  }

  if (finding.category === "secret_exposure") {
    return {
      title: "Remove committed secret and rotate it",
      summary: "Delete the committed value, rotate the credential, and load it from server-only environment variables.",
      before: finding.evidence,
      reviewRequired: true,
    }
  }

  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk") {
    return {
      title: "Replace dynamic tool dispatch with an allowlist",
      summary:
        "Define the exact tools this route is allowed to call, validate the requested name against that fixed set, and reject anything outside it before dispatch.",
      reviewRequired: true,
    }
  }

  return undefined
}

export function filterReportFindings(report: ScanReport, findingIds?: string[]) {
  const activeFindings = report.findings.filter((finding) => !finding.suppressed)
  if (!findingIds || findingIds.length === 0) {
    return {
      ...report,
      riskScore: calculateRiskScore(activeFindings),
      findings: activeFindings,
    }
  }

  const allowed = new Set(findingIds)
  const findings = activeFindings.filter((finding) => allowed.has(finding.id))
  return {
    ...report,
    riskScore: calculateRiskScore(findings),
    findings,
  }
}

export function generateIssueBody(report: ScanReport, findingIds?: string[]) {
  const scopedReport = filterReportFindings(report, findingIds)
  const topFindings = [...scopedReport.findings].sort(compareFindingsForReport).slice(0, 10)
  const nextSteps = recommendedNextStepsForReport(scopedReport)

  const lines = [
    "# Static security scan",
    "",
    `**Project:** ${scopedReport.projectName}`,
    `**Source:** ${scopedReport.sourceLabel}`,
    `**Risk score:** ${scopedReport.riskScore}/100 (${getRiskLabel(scopedReport.riskScore)})`,
    `**Files inspected:** ${scopedReport.filesInspected}`,
    `**Findings included:** ${scopedReport.findings.length} of ${report.findings.length}`,
    `**Baseline:** ${formatBaselineSummary(scopedReport)}`,
    "",
    ...formatRiskBreakdown(scopedReport),
    "## Top findings",
    "",
    ...topFindings.flatMap((finding) => [
      `- **${finding.severity.toUpperCase()}** ${finding.title}`,
      `  - File: \`${formatFindingLocation(finding)}\``,
      `  - Category: \`${finding.category}\``,
      `  - Recommendation: ${finding.recommendation}`,
    ]),
    "",
    "## Recommended next steps",
    "",
    ...nextSteps.map((step, index) => `${index + 1}. ${step}`),
    "",
    "_Generated from static security analysis._",
  ]

  return lines.join("\n")
}

export function generateFullReportBody(report: ScanReport) {
  const activeFindings = report.findings.filter((finding) => !finding.suppressed)
  const suppressedFindings = report.findings.filter((finding) => finding.suppressed)
  const sortedFindings = [...report.findings].sort(compareFindingsForReport)

  const lines = [
    "# Full static security report",
    "",
    "## Scan metadata",
    "",
    `- **Project:** ${report.projectName}`,
    `- **Scan ID:** \`${report.id}\``,
    `- **Created:** ${report.createdAt}`,
    `- **Source:** ${report.sourceLabel}`,
    `- **Mode:** ${report.analysisMode}`,
    `- **Status:** ${report.status}`,
    `- **Risk score:** ${report.riskScore}/100 (${getRiskLabel(report.riskScore)})`,
    `- **Framework:** ${report.framework ?? report.repoInventory?.framework ?? "unknown"}`,
    `- **Scanner version:** ${report.scannerVersion ?? "unknown"}`,
    "",
    "## Coverage",
    "",
    `- **Files inspected:** ${report.filesInspected}`,
    `- **API routes inspected:** ${report.apiRoutesInspected}`,
    `- **Client components inspected:** ${report.clientComponentsInspected}`,
    `- **AI endpoints inspected:** ${report.aiEndpointsInspected}`,
    `- **Findings total:** ${report.findings.length}`,
    `- **Active findings:** ${activeFindings.length}`,
    `- **Suppressed findings:** ${suppressedFindings.length}`,
    `- **Baseline:** ${formatBaselineSummary(report)}`,
    "",
    ...formatFindingGroups(report),
    ...formatRiskBreakdown(report),
    ...formatRepoInventory(report),
    ...formatDependencySummary(report),
    "## All findings",
    "",
    ...(sortedFindings.length
      ? sortedFindings.flatMap((finding, index) => formatFullFinding(finding, index + 1))
      : ["No findings were returned by this scan.", ""]),
    ...formatAuditTrail(report),
    "_Generated from static security analysis._",
  ]

  return lines.join("\n")
}

function formatBaselineSummary(report: ScanReport) {
  const summary = report.baselineSummary
  if (!summary) return "No baseline saved yet"
  return `${summary.new} new, ${summary.existing} existing, ${summary.resolved} resolved, ${summary.suppressed} suppressed`
}

function formatFindingGroups(report: ScanReport) {
  if (!report.findingGroups) return []
  return [
    "## Finding groups",
    "",
    `- **Security vulnerabilities:** ${report.findingGroups.vulnerabilities}`,
    `- **Hardening:** ${report.findingGroups.hardening}`,
    `- **Repository posture:** ${report.findingGroups.repo_posture}`,
    `- **Platform recommendations:** ${report.findingGroups.platform_recommendations}`,
    `- **Informational:** ${report.findingGroups.informational}`,
    "",
  ]
}

function formatRiskBreakdown(report: ScanReport) {
  const breakdown = report.riskBreakdown
  if (!breakdown) return []

  return [
    "## Risk breakdown",
    "",
    `- **Runtime / agent risk:** ${breakdown.runtimeAgentRisk.label} (${breakdown.runtimeAgentRisk.score}/100)`,
    `- **CI / supply-chain posture:** ${breakdown.repoPostureRisk.label} (${breakdown.repoPostureRisk.score}/100)`,
    `- **Dependency risk:** ${breakdown.dependencyRisk.label} (${breakdown.dependencyRisk.score}/100)`,
    `- **Secrets risk:** ${breakdown.secretsRisk.label} (${breakdown.secretsRisk.score}/100)`,
    "",
  ]
}

function formatRepoInventory(report: ScanReport) {
  const inventory = report.repoInventory
  if (!inventory) return []
  return [
    "## Repository inventory",
    "",
    `- **Languages:** ${inventory.languages.length ? inventory.languages.join(", ") : "unknown"}`,
    `- **Route handlers:** ${inventory.routeHandlers}`,
    `- **Server actions:** ${inventory.serverActions}`,
    `- **Client components:** ${inventory.clientComponents}`,
    `- **Imports inspected:** ${inventory.imports}`,
    `- **Env reads:** ${inventory.envReads}`,
    `- **Auth calls:** ${inventory.authCalls}`,
    `- **Validation calls:** ${inventory.validationCalls}`,
    `- **Dangerous sinks:** ${inventory.dangerousSinks}`,
    `- **AI calls:** ${inventory.aiCalls}`,
    `- **DB calls:** ${inventory.dbCalls}`,
    `- **GitHub workflows:** ${inventory.githubWorkflows}`,
    `- **Supabase migrations:** ${inventory.supabaseMigrations}`,
    `- **Prisma schemas:** ${inventory.prismaSchemas}`,
    "",
  ]
}

function formatDependencySummary(report: ScanReport) {
  const summary = report.dependencySummary
  if (!summary) return []
  return [
    "## Dependency summary",
    "",
    `- **Manifests:** ${summary.manifests}`,
    `- **Lockfiles:** ${summary.lockfiles}`,
    `- **Packages inspected:** ${summary.packages}`,
    `- **Vulnerable packages:** ${summary.vulnerablePackages}`,
    `- **Ecosystems:** ${summary.ecosystems.length ? summary.ecosystems.join(", ") : "none"}`,
    `- **OSV enabled:** ${summary.osvEnabled ? "yes" : "no"}`,
    ...(summary.error ? [`- **OSV error:** ${summary.error}`] : []),
    "",
  ]
}

function recommendedNextStepsForReport(report: ScanReport) {
  const aiSteps = report.aiTriage?.recommendedNextSteps.filter(Boolean) ?? []
  if (aiSteps.length) return unique(aiSteps).slice(0, 8)

  const findings = report.findings.filter((finding) => !finding.suppressed)
  const categories = new Set(findings.map((finding) => finding.category))
  const ruleText = findings.map((finding) => `${finding.ruleId ?? ""} ${finding.title}`).join("\n")
  const steps: string[] = []

  if (categories.has("mcp_risk")) {
    steps.push("Review MCP execution policy: command allowlist, explicit consent, config trust boundary, and env allowlist.")
  }
  if (categories.has("unsafe_tool_calling") || categories.has("ai_excessive_agency") || /agent-controlled shell|mcp|tool calling|excessive agency/i.test(ruleText)) {
    steps.push("Verify agent tool safeguards: approval gate, sandboxing, timeout, output limits, env stripping, and dangerous-command policy.")
  }
  if (categories.has("repo_security_posture") && /github-actions|workflow|release|unpinned/i.test(ruleText)) {
    steps.push("Pin third-party GitHub Actions to reviewed commit SHAs, prioritizing workflows with secrets or write permissions.")
  }
  if (categories.has("supply_chain_posture")) {
    steps.push("Replace curl|bash style install paths with signed releases, checksum verification, or package-manager-first installation.")
  }
  if (categories.has("secret_exposure") || categories.has("public_env_misuse")) {
    steps.push("Rotate exposed credentials, remove committed secret values, and keep only safe placeholders in documentation or examples.")
  }
  if (categories.has("missing_auth") || categories.has("missing_authentication") || categories.has("missing_authorization")) {
    steps.push("Add server-side authentication, authorization, and ownership checks before sensitive data access.")
  }
  if (categories.has("ai_endpoint_risk") || categories.has("ai_unbounded_consumption")) {
    steps.push("Add model rate limits, per-user quota, token caps, budget checks, and bounded tool-call steps before model invocation.")
  }
  if (categories.has("input_validation") || categories.has("sql_injection") || categories.has("ssrf") || categories.has("unsafe_redirect")) {
    steps.push("Validate and normalize user-controlled input before it reaches database, network, redirect, file, or shell sinks.")
  }
  if (categories.has("dependency_vulnerability")) {
    steps.push("Upgrade vulnerable runtime dependencies first, then verify reachability before prioritizing dev-only advisories.")
  }

  steps.push("Review generated patch suggestions before applying them; patch previews are intentionally review-required.")
  return unique(steps).slice(0, 8)
}

function unique(values: string[]) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))]
}

function formatFullFinding(finding: ScanFinding, index: number) {
  return [
    `### ${index}. [${finding.severity.toUpperCase()}] ${finding.title}`,
    "",
    `- **ID:** \`${finding.id}\``,
    `- **Kind:** \`${finding.kind ?? inferFindingKindForCopy(finding)}\``,
    `- **Category:** \`${finding.category}\``,
    `- **Rule:** \`${finding.ruleId ?? "unknown"}\``,
    `- **Source:** \`${finding.source}\``,
    `- **Location:** \`${formatFindingLocation(finding)}\``,
    `- **Confidence:** ${Math.round(finding.confidence * 100)}%${finding.confidenceReason ? ` - ${finding.confidenceReason}` : ""}`,
    `- **Reachability:** ${finding.reachability ?? "unknown"}`,
    `- **Exploitability:** ${finding.exploitability ?? "unknown"}`,
    ...(finding.cwe ? [`- **CWE:** ${finding.cwe}`] : []),
    ...(finding.owasp ? [`- **OWASP:** ${finding.owasp}`] : []),
    ...(finding.asvs ? [`- **ASVS:** ${finding.asvs}`] : []),
    ...(finding.baselineState ? [`- **Baseline state:** ${finding.baselineState}`] : []),
    ...(finding.suppressed ? [`- **Suppressed:** yes${finding.suppressionReason ? ` - ${finding.suppressionReason}` : ""}`] : []),
    ...(finding.triage ? [`- **AI triage:** ${finding.triage.verdict} (${Math.round(finding.triage.confidence * 100)}%) - ${finding.triage.reason}`] : []),
    "",
    "**What static analysis found**",
    "",
    finding.description,
    "",
    ...(finding.evidence ? ["**Evidence**", "", "```text", redactCopiedText(finding.evidence), "```", ""] : []),
    "**Recommendation**",
    "",
    finding.recommendation,
    "",
    ...formatFindingExplanation(finding),
    ...formatFindingTriage(finding),
    ...formatEvidenceTrace(finding),
    ...formatPatchSuggestion(finding),
  ]
}

function formatFindingTriage(finding: ScanFinding) {
  const triage = finding.triage
  if (!triage) return []

  return [
    "**AI triage**",
    "",
    `- **Verdict:** ${triage.verdict}`,
    `- **Reason:** ${triage.reason}`,
    ...(triage.priority ? [`- **Priority:** ${triage.priority}`] : []),
    ...(triage.attackScenario ? [`- **Attack scenario:** ${triage.attackScenario}`] : []),
    ...(triage.detectedControls?.length ? ["- **Detected controls:**", ...triage.detectedControls.map((control) => `  - ${control}`)] : []),
    ...(triage.missingControls?.length ? ["- **Missing or unclear controls:**", ...triage.missingControls.map((control) => `  - ${control}`)] : []),
    "",
  ]
}

function formatFindingExplanation(finding: ScanFinding) {
  if (!finding.explanation) return []
  return [
    "**Explanation**",
    "",
    `- **Summary:** ${finding.explanation.summary}`,
    `- **Impact:** ${finding.explanation.impact}`,
    ...(finding.explanation.fixSteps.length
      ? ["- **Fix steps:**", ...finding.explanation.fixSteps.map((step, index) => `  ${index + 1}. ${step}`)]
      : []),
    "",
  ]
}

function formatEvidenceTrace(finding: ScanFinding) {
  if (!finding.evidenceTrace?.length) return []
  return [
    "**Evidence trace**",
    "",
    ...finding.evidenceTrace.map((step, index) => {
      const code = step.code ? ` - \`${redactCopiedText(step.code)}\`` : ""
      return `${index + 1}. **${step.kind}:** ${step.label} at \`${formatTraceLocation(step)}\`${code}`
    }),
    "",
  ]
}

function formatPatchSuggestion(finding: ScanFinding) {
  const patch = finding.patch
  if (!patch) return []
  return [
    "**Patch suggestion**",
    "",
    `- **Title:** ${patch.title}`,
    `- **Summary:** ${patch.summary}`,
    `- **Review required:** ${patch.reviewRequired ? "yes" : "no"}`,
    ...(patch.before ? ["", "Before:", "```text", redactCopiedText(patch.before), "```"] : []),
    ...(patch.after ? ["", "After:", "```text", redactCopiedText(patch.after), "```"] : []),
    ...(patch.unifiedDiff ? ["", "Unified diff:", "```diff", redactCopiedText(patch.unifiedDiff), "```"] : []),
    "",
  ]
}

function formatAuditTrail(report: ScanReport) {
  if (!report.auditTrail.length) return []
  return [
    "## Audit trail",
    "",
    ...report.auditTrail.map((event) => `- **${event.status}:** ${event.label} (${event.timestamp})${event.metadata ? ` - ${JSON.stringify(event.metadata)}` : ""}`),
    "",
  ]
}

function formatTraceLocation(step: { filePath: string; lineStart: number; lineEnd?: number }) {
  if (step.lineEnd && step.lineEnd !== step.lineStart) return `${step.filePath}:${step.lineStart}-${step.lineEnd}`
  return `${step.filePath}:${step.lineStart}`
}

function inferFindingKindForCopy(finding: ScanFinding): FindingKind {
  if (finding.category === "vercel_hardening" || finding.category === "platform_hardening") return "platform_recommendation"
  if (finding.category === "repo_security_posture" || finding.category === "supply_chain_posture") return "repo_posture"
  if (finding.category === "dependency_signal" && !/vulnerab/i.test(finding.title)) return "repo_posture"
  if (finding.severity === "info") return "info"
  return "vulnerability"
}

function redactCopiedText(value: string) {
  return value
    .replace(/\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{8,}\b/g, "sk-...redacted")
    .replace(/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "sk-ant-...redacted")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b/g, "sk_...redacted")
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b/g, "ghp_...redacted")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "github_pat_...redacted")
    .replace(/\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b/g, "jwt...redacted")
}

function formatFindingLocation(finding: ScanFinding) {
  if (!finding.lineStart) return finding.filePath
  return `${finding.filePath}:${finding.lineStart}`
}

type ScoreableFinding = Pick<ScanFinding, "severity" | "confidence" | "kind" | "category" | "reachability" | "exploitability"> &
  Partial<Pick<ScanFinding, "ruleId" | "title" | "filePath">>

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

function inferFindingKind(finding: Pick<ScanFinding, "category" | "severity" | "title">): FindingKind {
  if (finding.category === "vercel_hardening" || finding.category === "platform_hardening") return "platform_recommendation"
  if (finding.category === "repo_security_posture" || finding.category === "supply_chain_posture") return "repo_posture"
  if (finding.category === "dependency_signal" && !/vulnerab/i.test(finding.title)) return "repo_posture"
  if (finding.severity === "info") return "info"
  return "vulnerability"
}
