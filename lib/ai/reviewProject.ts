import "server-only"

import { generateText, Output } from "ai"
import { z } from "zod"
import { resolveAiModel } from "@/lib/ai/model"
import { applyAiTriage } from "@/lib/ai/triage"
import { auditEvent } from "@/lib/scanner/scan"
import { calculateRiskScore } from "@/lib/scanner/patches"
import { normalizeFindings, withReportDerivedFields } from "@/lib/scanner/enrich"
import { compareFindingsForReport } from "@/lib/scanner/prioritize"
import { isApiRoute, isDocumentationSecretExample, redactSecrets } from "@/lib/scanner/rules"
import type { FindingCategory, FindingKind, FindingTriageVerdict, ProjectFile, ScanFinding, ScanMode, ScanReport, Severity, TriagePriority } from "@/lib/scanner/types"

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"])
const KindSchema = z.enum(["vulnerability", "hardening", "repo_posture", "platform_recommendation", "info"])
const TriageVerdictSchema = z.enum(["confirmed", "needs_review", "posture_only", "likely_false_positive"])
const TriagePrioritySchema = z.enum(["urgent", "high", "normal", "low"])
const RiskBandSchema = z.enum(["none", "low", "medium", "moderate", "high", "critical"])
const CategorySchema = z.enum([
  "secret_exposure",
  "public_env_misuse",
  "dependency_vulnerability",
  "broken_access_control",
  "missing_auth",
  "missing_authentication",
  "missing_authorization",
  "ai_endpoint_risk",
  "ai_prompt_injection_risk",
  "ai_excessive_agency",
  "ai_unbounded_consumption",
  "unsafe_tool_calling",
  "mcp_risk",
  "input_validation",
  "sql_injection",
  "command_injection",
  "ssrf",
  "xss",
  "unsafe_redirect",
  "csrf",
  "insecure_cookie",
  "client_data_exposure",
  "dangerous_code",
  "server_action_risk",
  "supabase_rls_risk",
  "repo_security_posture",
  "supply_chain_posture",
  "platform_hardening",
  "vercel_hardening",
  "dependency_signal",
])

const AiReviewSchema = z.object({
  triage: z
    .array(
      z.object({
        findingId: z.string().min(1).max(40),
        verdict: TriageVerdictSchema,
        reason: z.string().min(1).max(700),
        adjustedSeverity: SeveritySchema.optional(),
        adjustedKind: KindSchema.optional(),
        adjustedCategory: CategorySchema.optional(),
        confidence: z.number().min(0).max(1),
        detectedControls: z.array(z.string().min(1).max(140)).max(10).optional(),
        missingControls: z.array(z.string().min(1).max(140)).max(10).optional(),
        attackScenario: z.string().min(1).max(700).optional(),
        priority: TriagePrioritySchema.optional(),
      }),
    )
    .max(90)
    .optional(),
  reportSummary: z
    .object({
      riskNarrative: z.string().min(1).max(900),
      recommendedNextSteps: z.array(z.string().min(1).max(240)).min(1).max(8),
      runtimeAgentRisk: RiskBandSchema.optional(),
      repoPostureRisk: RiskBandSchema.optional(),
      dependencyRisk: RiskBandSchema.optional(),
      secretsRisk: RiskBandSchema.optional(),
    })
    .optional(),
  findings: z
    .array(
      z.object({
        severity: SeveritySchema,
        category: CategorySchema,
        title: z.string().min(1).max(160),
        description: z.string().min(1).max(700),
        filePath: z.string().min(1).max(260),
        lineStart: z.number().int().positive().optional(),
        evidence: z.string().min(1).max(500),
        confidence: z.number().min(0).max(1),
        recommendation: z.string().min(1).max(700),
      }),
    )
    .max(12)
    .optional(),
})

type AiReviewOutput = z.infer<typeof AiReviewSchema>
type AiFindingCandidate = NonNullable<AiReviewOutput["findings"]>[number]

type SnippetContext = {
  file: ProjectFile
  score: number
  reasons: string[]
  redactedText: string
  numberedText: string
}

type AiReviewConfig = {
  mode: ScanMode
  label: string
  maxFiles: number
  maxContextChars: number
  maxFindings: number
  maxTriageFindings: number
  timeoutMs: number
  rangePadding: number
  maxInterestingLines: number
  maxLinesPerFile: number
  lineCharLimit: number
}

const STATIC_RULE_HARNESS = [
  {
    category: "secret_exposure",
    objective: "Find committed env files, provider keys, private key blocks, database URLs, service role keys, and high-risk secret names.",
    evidenceRequired: "A redacted line containing the env variable, provider key prefix, private key marker, or assigned secret-looking value.",
  },
  {
    category: "public_env_misuse",
    objective: "Find dangerous NEXT_PUBLIC_* values that would be bundled into browser JavaScript.",
    evidenceRequired: "A line containing a NEXT_PUBLIC_* variable with secret, token, private, database, service role, or API key semantics.",
  },
  {
    category: "missing_auth",
    objective: "Find admin, internal, billing, users, or secrets endpoints without obvious server-side authentication and authorization.",
    evidenceRequired: "An API route handler or exported function showing sensitive behavior without an auth guard nearby.",
  },
  {
    category: "ai_endpoint_risk",
    objective:
      "Find AI/model endpoints without rate limits, quota checks, bot protection, budget controls, token caps, or bounded tool-call steps before model invocation.",
    evidenceRequired: "A model call, AI SDK/OpenAI/Anthropic import, tools object, or model configuration line with no nearby guard or execution bound.",
  },
  {
    category: "unsafe_tool_calling",
    objective: "Find dynamic tool dispatch, MCP/tool execution, shell access, or tool names selected from user-controlled input.",
    evidenceRequired: "A line where request/user input influences tool selection, process execution, or tool arguments.",
  },
  {
    category: "input_validation",
    objective: "Find request JSON parsing without Zod/Yup/Valibot/Superstruct validation before use.",
    evidenceRequired: "A route line with req.json/request.json and no schema parse/safeParse nearby.",
  },
  {
    category: "client_data_exposure",
    objective: "Find sensitive-looking data inside browser/client components.",
    evidenceRequired: "A 'use client' file line referencing passwords, tokens, API keys, secrets, PII, or sensitive mock records.",
  },
  {
    category: "dangerous_code",
    objective: "Find dynamic code execution, raw HTML rendering, OS command execution, unsafe Rust, or file writes from request input.",
    evidenceRequired: "A concrete line with eval, new Function, dangerouslySetInnerHTML, child_process, Command::new, unsafe, or risky file write.",
  },
  {
    category: "input_validation",
    objective: "Find webhook handlers without signature/HMAC verification before parsing or trusting provider payloads.",
    evidenceRequired: "A webhook route line that parses text/json/arrayBuffer or uses provider webhook payloads without a constructEvent/verifySignature/HMAC check nearby.",
  },
  {
    category: "input_validation",
    objective: "Find unsafe database query construction, especially raw query helpers or request-controlled string interpolation.",
    evidenceRequired: "A concrete raw query or interpolated query line tied to request, params, body, input, or search params.",
  },
  {
    category: "client_data_exposure",
    objective: "Find browser/session exposure mistakes such as permissive CORS or session cookies missing httpOnly/secure/sameSite.",
    evidenceRequired: "A concrete CORS wildcard/reflection line or session-cookie-setting line with missing hardening attributes.",
  },
  {
    category: "dependency_signal",
    objective: "Find high-risk supply-chain install scripts that download or execute shell commands during package installation.",
    evidenceRequired: "A package.json install/preinstall/postinstall/prepare script that includes curl, wget, bash, sh, node -e, npx, pnpm dlx, or bunx.",
  },
] as const

export async function reviewProjectWithAi(report: ScanReport, files: ProjectFile[]): Promise<ScanReport> {
  const startedAt = Date.now()

  if (report.analysisMode === "rules") {
    return appendAudit(report, "AI auditor skipped", "complete", {
      reason: "rules_only_mode",
      mode: "rules",
    })
  }

  if (process.env.VIBESHIELD_ENABLE_AI_REVIEW === "false") {
    return appendAudit(report, "AI auditor skipped", "complete", {
      reason: "disabled_by_env",
    })
  }

  const config = getAiReviewConfig(report.analysisMode ?? "normal")

  if (report.repository?.private && process.env.VIBESHIELD_ALLOW_PRIVATE_AI_REVIEW !== "true") {
    return appendAudit(report, "AI auditor skipped", "complete", {
      reason: "private_repository_requires_explicit_ai_opt_in",
    })
  }

  const snippets = selectSnippetContexts(files, report, config)
  const activeFindings = report.findings.filter((finding) => !finding.suppressed)
  const harnessedReport = appendAudit(report, "Build hybrid static-AI harness", "complete", {
    mode: config.mode,
    profile: config.label,
    ruleObjectives: STATIC_RULE_HARNESS.length,
    candidateFiles: snippets.length,
    contextChars: snippets.reduce((total, snippet) => total + snippet.numberedText.length, 0),
    confirmedRuleFindings: activeFindings.length,
  })

  const aiModel = resolveAiModel()
  if (!aiModel) {
    return appendAudit(harnessedReport, "AI auditor skipped", "complete", {
      reason: "no_server_side_model_configured",
    })
  }

  if (snippets.length === 0) {
    return appendAudit(harnessedReport, "AI auditor skipped", "complete", {
      reason: "no_reviewable_context",
      provider: aiModel.provider,
      model: aiModel.modelId,
    })
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs)

  try {
    const { output } = await generateText({
      model: aiModel.model,
      providerOptions: aiModel.providerOptions,
      abortSignal: controller.signal,
      output: Output.object({ schema: AiReviewSchema }),
      system: [
        "You are VibeShield's second-pass security auditor.",
        "You operate inside a deterministic static-analysis harness. The harness chooses files, redacts secrets, and supplies rule objectives.",
        "Review only the redacted source snippets and harness signals provided by the scanner.",
        "Your first job is to triage deterministic findings: confirm them, mark them as needs_review, downgrade posture-only signals, or flag likely false positives.",
        "Your second job is to find additional security or production-readiness issues the deterministic rules may have missed, then tie every claim to snippet evidence.",
        "Use likely_false_positive only when the provided evidence is clearly docs, tests, placeholders, redaction regexes, or otherwise not a production risk.",
        "Use posture_only when the signal is real but represents CI, release, install, maintenance, or inventory posture instead of an app/runtime vulnerability.",
        "Use confirmed when the deterministic finding has concrete source, sink, control-gap, or sensitive asset evidence.",
        "Do not downgrade critical secret evidence, dangerous NEXT_PUBLIC secrets, or concrete provider tokens. The scanner has a guardrail, but you must respect it.",
        "For agentic repos, CLI tools, MCP clients, or coding agents, prioritize runtime/agent risks such as MCP env inheritance, shell tools, tool approval, sandboxing, env isolation, and supply-chain release workflows.",
        "For non-web repos, do not emit generic Next.js advice such as API route auth, rate limiting, or request-body validation unless the repository actually contains that surface.",
        "Report detected controls and missing or unclear controls for top runtime findings when possible.",
        "Do not report style issues, generic advice, or findings without concrete file evidence.",
        "Do not report an API key or secret from variable name alone. There must be a concrete non-placeholder value, dangerous NEXT_PUBLIC exposure, or a concrete unsafe use.",
        "In README, docs, examples, and setup guides, env names with localhost URLs, username/password placeholders, redacted values, or install instructions are documentation, not secret exposure.",
        "Treat demo, fake, redacted, sample, example, changeme, placeholder, xxxx, and empty env values as placeholders unless the unsafe contract itself is the issue.",
        "Do not repeat confirmed deterministic findings unless you identify a materially different issue.",
        "Never include full secrets. Evidence is already redacted and must stay redacted.",
        "Prefer no finding over a speculative finding.",
      ].join(" "),
      prompt: JSON.stringify({
        project: {
          name: harnessedReport.projectName,
          framework: harnessedReport.framework ?? "unknown",
          source: harnessedReport.sourceLabel,
          filesInspected: harnessedReport.filesInspected,
        },
        staticRuleHarness: STATIC_RULE_HARNESS,
        scannerStats: {
          apiRoutesInspected: harnessedReport.apiRoutesInspected,
          clientComponentsInspected: harnessedReport.clientComponentsInspected,
          aiEndpointsInspected: harnessedReport.aiEndpointsInspected,
          deterministicRiskScore: harnessedReport.riskScore,
        },
        structuredArtifacts: {
          repoInventory: harnessedReport.repoInventory,
          dependencySummary: harnessedReport.dependencySummary,
          findingGroups: harnessedReport.findingGroups,
        },
        deterministicFindings: activeFindings.slice(0, config.maxTriageFindings).map((finding) => ({
          id: finding.id,
          kind: finding.kind,
          severity: finding.severity,
          category: finding.category,
          ruleId: finding.ruleId,
          title: finding.title,
          description: finding.description,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          evidence: redactSecrets(finding.evidence ?? ""),
          confidence: finding.confidence,
          confidenceReason: finding.confidenceReason,
          reachability: finding.reachability,
          exploitability: finding.exploitability,
          recommendation: finding.recommendation,
          evidenceTrace: finding.evidenceTrace?.slice(0, 8).map((step) => ({
            ...step,
            code: step.code ? redactSecrets(step.code) : undefined,
          })),
        })),
        instructions: {
          analysisMode: config.mode,
          reviewDepth: config.label,
          maxFindings: config.maxFindings,
          maxTriageFindings: config.maxTriageFindings,
          requireEvidenceFromSnippets: true,
          allowedFiles: snippets.map((snippet) => snippet.file.path),
          triageContract:
            "Return triage entries for the most important deterministic findings. Prefer MCP and shell/runtime agent findings before CI posture when severities tie. Explain why a finding is confirmed, posture-only, needs-review, or likely false positive.",
          reportSummaryContract:
            "Return context-aware recommended next steps for this repository type. Do not mention rotating credentials, API auth guards, model rate limits, or Zod validation unless the report actually contains those issue families.",
          normalModeContract:
            "Normal mode is still professional: prioritize high-confidence vulnerabilities and production blockers over broad advisory noise.",
          maxModeContract:
            "Max mode may spend more context on cross-file trust boundaries, webhook/auth/CORS/session/database paths, AI tool execution and supply-chain scripts.",
        },
        redactedSnippets: snippets.map((snippet) => ({
          filePath: snippet.file.path,
          scannerPriority: snippet.score,
          selectedBecause: snippet.reasons,
          content: snippet.numberedText,
        })),
      }),
    })

    const aiFindings = normalizeAiFindings(output, snippets, harnessedReport.findings).slice(0, config.maxFindings)
    const findings = normalizeFindings(assignFindingIds([...harnessedReport.findings, ...aiFindings]))
    const triage = normalizeAiTriage(output, new Set(findings.map((finding) => finding.id))).slice(0, config.maxTriageFindings)

    const reportWithAiFindings = withReportDerivedFields({
      ...harnessedReport,
      riskScore: calculateRiskScore(findings),
      findings,
      auditTrail: [
        ...harnessedReport.auditTrail,
        auditEvent("Run AI auditor model", "complete", {
          provider: aiModel.provider,
          model: aiModel.modelId,
          mode: config.mode,
          reviewedFiles: snippets.length,
          acceptedFindings: aiFindings.length,
          triagedFindings: triage.length,
          durationMs: Date.now() - startedAt,
        }),
      ],
    })
    return applyAiTriage(reportWithAiFindings, {
      triage,
      reportSummary: output.reportSummary,
      model: aiModel.modelId,
      provider: aiModel.provider,
    })
  } catch (error) {
    return appendAudit(harnessedReport, "Run AI auditor model", "failed", {
      provider: aiModel.provider,
      model: aiModel.modelId,
      mode: config.mode,
      error: error instanceof Error ? error.message.slice(0, 240) : "AI review failed",
      durationMs: Date.now() - startedAt,
    })
  } finally {
    clearTimeout(timeout)
  }
}

function normalizeAiFindings(output: AiReviewOutput, snippets: SnippetContext[], existing: ScanFinding[]): ScanFinding[] {
  const byPath = new Map(snippets.map((snippet) => [snippet.file.path, snippet]))
  const findings: ScanFinding[] = []

  for (const candidate of output.findings ?? []) {
    const snippet = byPath.get(candidate.filePath)
    if (!snippet) continue

    const evidence = evidenceFromSnippet(candidate, snippet)
    if (!evidence) continue
    if (candidate.category === "secret_exposure" && isDocumentationSecretExample(candidate.filePath, evidence)) continue
    if (isDuplicateFinding(candidate, existing) || isDuplicateFinding(candidate, findings)) continue

    findings.push({
      id: "AI-000",
      severity: capAiSeverity(candidate.severity, candidate.category),
      category: candidate.category,
      title: candidate.title,
      description: candidate.description,
      filePath: candidate.filePath,
      lineStart: candidate.lineStart,
      evidence,
      confidence: Math.min(candidate.confidence, 0.76),
      recommendation: candidate.recommendation,
      patchable: false,
      source: "ai",
    })
  }

  return findings
}

function normalizeAiTriage(output: AiReviewOutput, allowedFindingIds: Set<string>) {
  return (output.triage ?? [])
    .filter((entry) => allowedFindingIds.has(entry.findingId))
    .map((entry) => ({
      findingId: entry.findingId,
      verdict: entry.verdict as FindingTriageVerdict,
      reason: entry.reason,
      adjustedSeverity: entry.adjustedSeverity as Severity | undefined,
      adjustedKind: entry.adjustedKind as FindingKind | undefined,
      adjustedCategory: entry.adjustedCategory as FindingCategory | undefined,
      confidence: entry.confidence,
      detectedControls: entry.detectedControls,
      missingControls: entry.missingControls,
      attackScenario: entry.attackScenario,
      priority: entry.priority as TriagePriority | undefined,
    }))
}

function evidenceFromSnippet(candidate: AiFindingCandidate, snippet: SnippetContext) {
  if (candidate.lineStart) {
    const line = lineAt(snippet.file.text, candidate.lineStart)
    if (line) return redactSecrets(line.trim()).slice(0, 500)
  }

  const redactedEvidence = redactSecrets(candidate.evidence.trim())
  if (!redactedEvidence) return null

  const lineNumber = findLineNumber(snippet.redactedText, redactedEvidence)
  if (!lineNumber) return null
  candidate.lineStart = lineNumber
  return redactedEvidence
}

function getAiReviewConfig(mode: ScanMode): AiReviewConfig {
  const configuredNormalTimeout = readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_TIMEOUT_MS, 30_000)
  const configuredMaxTimeout = readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_MAX_TIMEOUT_MS, 60_000)

  if (mode === "max") {
    return {
      mode,
      label: "max-depth hybrid review",
      maxFiles: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_MAX_FILES_MAX, 42), 64),
      maxContextChars: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_CONTEXT_CHARS_MAX, 58_000), 80_000),
      maxFindings: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_FINDINGS_MAX, 10), 12),
      maxTriageFindings: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_TRIAGE_MAX, 80), 90),
      timeoutMs: Math.min(Math.max(configuredMaxTimeout, 120_000), 300_000),
      rangePadding: 28,
      maxInterestingLines: 42,
      maxLinesPerFile: 260,
      lineCharLimit: 260,
    }
  }

  return {
    mode,
    label: "targeted hybrid review",
    maxFiles: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_MAX_FILES, 18), 32),
    maxContextChars: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_CONTEXT_CHARS, 28_000), 40_000),
    maxFindings: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_FINDINGS, 6), 8),
    maxTriageFindings: Math.min(readPositiveInt(process.env.VIBESHIELD_AI_REVIEW_TRIAGE, 35), 45),
    timeoutMs: Math.min(Math.max(configuredNormalTimeout, 30_000), 60_000),
    rangePadding: 18,
    maxInterestingLines: 24,
    maxLinesPerFile: 180,
    lineCharLimit: 220,
  }
}

function selectSnippetContexts(files: ProjectFile[], report: ScanReport, config: AiReviewConfig) {
  const maxFiles = config.maxFiles
  const existingFindingPaths = new Set(report.findings.filter((finding) => !finding.suppressed).map((finding) => finding.filePath))
  const scored = files
    .map((file) => scoreFile(file, existingFindingPaths))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score || a.file.path.localeCompare(b.file.path))
    .slice(0, maxFiles)

  const snippets: SnippetContext[] = []
  let totalChars = 0

  for (const entry of scored) {
    const redactedText = redactSecrets(entry.file.text)
    const numberedText = buildNumberedSnippet(entry.file, redactedText, report, config)
    if (!numberedText.trim()) continue

    const nextTotal = totalChars + numberedText.length
    if (nextTotal > config.maxContextChars && snippets.length > 0) break

    snippets.push({
      file: entry.file,
      score: entry.score,
      reasons: entry.reasons,
      redactedText,
      numberedText: numberedText.slice(0, Math.max(800, config.maxContextChars - totalChars)),
    })
    totalChars += numberedText.length
  }

  return snippets
}

function scoreFile(file: ProjectFile, existingFindingPaths: Set<string>) {
  const path = file.path
  const text = file.text.slice(0, 120_000)
  let score = 0
  const reasons: string[] = []

  const add = (points: number, reason: string) => {
    score += points
    reasons.push(reason)
  }

  if (existingFindingPaths.has(path)) add(90, "deterministic finding already exists in this file")
  if (isApiRoute(path)) add(80, "API route")
  if (isEnvLike(path)) add(80, "environment file")
  if (/(\bpackage\.json|Cargo\.toml|next\.config\.|vite\.config\.|middleware\.)$/i.test(path)) add(45, "framework or dependency configuration")
  if (/\.(ts|tsx|js|jsx|mjs|cjs|rs)$/.test(path)) add(20, "source file")
  if (SECURITY_REVIEW_KEYWORDS.test(text)) add(45, "security-sensitive keywords")
  if (DANGEROUS_PRIMITIVE_KEYWORDS.test(text)) add(50, "dangerous execution or rendering primitive")
  if (AI_SURFACE_KEYWORDS.test(text)) add(45, "AI model or tool-calling surface")
  if (WEBHOOK_OR_DATABASE_KEYWORDS.test(text) || /webhooks?/i.test(path)) add(40, "webhook or database trust boundary")
  if (PACKAGE_SCRIPT_KEYWORDS.test(text) && /package\.json$/i.test(path)) add(38, "supply-chain install script")

  return { file, score, reasons }
}

const SECURITY_REVIEW_KEYWORDS =
  /\b(auth|admin|internal|billing|token|secret|password|api[_-]?key|private[_-]?key|service[_-]?role|database_url|webhook|stripe|supabase|process\.env|headers\(|cookies\(|Set-Cookie|req\.json|request\.json|cors|origin|signature|hmac|sameSite|httpOnly)\b/i
const DANGEROUS_PRIMITIVE_KEYWORDS =
  /\b(Command::new|unsafe\s*\{|child_process|exec\s*\(|spawn\s*\(|eval\s*\(|dangerouslySetInnerHTML|\$queryRawUnsafe|\$executeRawUnsafe)\b/i
const AI_SURFACE_KEYWORDS =
  /\b(generateText|streamText|generateObject|streamObject|openai|anthropic|deepseek|tools\s*:|toolName|mcp|maxSteps|stopWhen|stepCountIs)\b/i
const WEBHOOK_OR_DATABASE_KEYWORDS =
  /\b(webhook|stripe-signature|svix-signature|x-hub-signature|constructEvent|verifySignature|createHmac|\$queryRawUnsafe|\$executeRawUnsafe|db\.query|pool\.query)\b/i
const PACKAGE_SCRIPT_KEYWORDS = /\b(preinstall|postinstall|prepare|curl|wget|bash|node\s+-e|npx|pnpm\s+dlx|bunx)\b/i

function buildNumberedSnippet(file: ProjectFile, redactedText: string, report: ScanReport, config: AiReviewConfig) {
  const lines = redactedText.split(/\r?\n/)
  const interestingLines = collectInterestingLines(file, lines, report, config)
  const ranges =
    interestingLines.length > 0
      ? mergeRanges(interestingLines.map((line) => [line - config.rangePadding, line + config.rangePadding]))
      : [[1, config.mode === "max" ? 160 : 100]]
  const output: string[] = []
  let emitted = 0

  for (const [rawStart, rawEnd] of ranges) {
    const start = Math.max(1, rawStart)
    const end = Math.min(lines.length, rawEnd)
    if (start > end) continue
    if (output.length > 0) output.push("...")

    for (let lineNumber = start; lineNumber <= end; lineNumber += 1) {
      const line = lines[lineNumber - 1]
      output.push(`L${lineNumber}: ${line.slice(0, config.lineCharLimit)}`)
      emitted += 1
      if (emitted >= config.maxLinesPerFile) return output.join("\n")
    }
  }

  return output.join("\n")
}

function collectInterestingLines(file: ProjectFile, lines: string[], report: ScanReport, config: AiReviewConfig) {
  const lineNumbers = new Set<number>()

  for (const finding of report.findings) {
    if (finding.suppressed) continue
    if (finding.filePath === file.path && finding.lineStart) lineNumbers.add(finding.lineStart)
  }

  lines.forEach((line, index) => {
    if (SECURITY_REVIEW_KEYWORDS.test(line)) lineNumbers.add(index + 1)
    if (DANGEROUS_PRIMITIVE_KEYWORDS.test(line)) {
      lineNumbers.add(index + 1)
    }
    if (AI_SURFACE_KEYWORDS.test(line) || WEBHOOK_OR_DATABASE_KEYWORDS.test(line) || PACKAGE_SCRIPT_KEYWORDS.test(line)) {
      lineNumbers.add(index + 1)
    }
  })

  return [...lineNumbers].sort((a, b) => a - b).slice(0, config.maxInterestingLines)
}

function mergeRanges(ranges: number[][]) {
  const sorted = ranges.sort((a, b) => a[0] - b[0])
  const merged: number[][] = []

  for (const range of sorted) {
    const current = merged[merged.length - 1]
    if (!current || range[0] > current[1] + 1) {
      merged.push([...range])
      continue
    }

    current[1] = Math.max(current[1], range[1])
  }

  return merged
}

function isEnvLike(path: string) {
  const name = path.split("/").pop() ?? path
  return name === ".env" || name.startsWith(".env.")
}

function appendAudit(
  report: ScanReport,
  label: string,
  status: "complete" | "failed",
  metadata: Record<string, unknown>,
): ScanReport {
  return {
    ...report,
    auditTrail: [...report.auditTrail, auditEvent(label, status, metadata)],
  }
}

function assignFindingIds(findings: ScanFinding[]) {
  let nextId = findings.reduce((max, finding) => {
    const match = /^F-(\d+)$/.exec(finding.id)
    return match ? Math.max(max, Number(match[1])) : max
  }, 0) + 1

  return [...findings].sort(compareFindingsForReport).map((finding) => ({
    ...finding,
    id: finding.id && finding.id !== "AI-000" ? finding.id : `F-${String(nextId++).padStart(3, "0")}`,
  }))
}

function capAiSeverity(severity: Severity, category: FindingCategory): Severity {
  if (severity !== "critical") return severity
  if (category === "secret_exposure" || category === "public_env_misuse") return "critical"
  return "high"
}

function isDuplicateFinding(
  candidate: Pick<ScanFinding, "category" | "filePath" | "lineStart" | "title">,
  existing: Array<Pick<ScanFinding, "category" | "filePath" | "lineStart" | "title">>,
) {
  const title = normalizeText(candidate.title)
  return existing.some((finding) => {
    if (finding.category !== candidate.category) return false
    if (finding.filePath !== candidate.filePath) return false
    if (finding.lineStart && candidate.lineStart && Math.abs(finding.lineStart - candidate.lineStart) <= 3) return true
    return normalizeText(finding.title) === title
  })
}

function lineAt(text: string, lineNumber: number) {
  return text.split(/\r?\n/)[lineNumber - 1]
}

function findLineNumber(redactedText: string, evidence: string) {
  const target = normalizeText(evidence)
  if (!target || target.length < 4) return null

  const lines = redactedText.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    if (normalizeText(lines[index]).includes(target)) return index + 1
  }

  return null
}

function normalizeText(value: string) {
  return value.toLowerCase().replace(/\s+/g, " ").trim()
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
