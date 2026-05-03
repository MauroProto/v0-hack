import "server-only"

import { generateText, Output } from "ai"
import { resolveAiModel } from "@/lib/ai/model"
import {
  isUsablePullRequestCopy,
  sanitizePublicPullRequestCopy,
  type PullRequestCopyDraft,
} from "@/lib/ai/publicPullRequestCopy"
import { PullRequestCopySchema } from "@/lib/ai/structuredSchemas"
import { badgerEnv } from "@/lib/config/env"
import { redactSecrets } from "@/lib/scanner/rules"
import type { ScanFinding, ScanReport } from "@/lib/scanner/types"

export interface ProfessionalPullRequestCopyInput {
  report: ScanReport
  draft: PullRequestCopyDraft
  filesChanged: string[]
  appliedFixes: string[]
  skippedFixes: string[]
}

export async function generateProfessionalPullRequestCopy(input: ProfessionalPullRequestCopyInput): Promise<PullRequestCopyDraft> {
  if (badgerEnv("ENABLE_PR_AI_COPY") === "false") return sanitizePublicPullRequestCopy(input.draft)

  const aiModel = resolveAiModel()
  if (!aiModel) return sanitizePublicPullRequestCopy(input.draft)

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), readPositiveInt(badgerEnv("PR_AI_TIMEOUT_MS"), 20_000))

  try {
    const { output } = await generateText({
      model: aiModel.model,
      providerOptions: aiModel.providerOptions,
      abortSignal: controller.signal,
      output: Output.object({ schema: PullRequestCopySchema }),
      system: [
        "You write professional public GitHub pull request copy for maintainers as a careful human contributor.",
        "Write in clear English only.",
        "Never mention Badger, VibeShield, scanner vendor branding, model names, AI, local URLs, localhost, internal API routes, or private tooling.",
        "Avoid words that make the PR look machine-created: generated, auto-generated, scanner, scan metadata, scan ID, static analysis report.",
        "Do not exaggerate. Do not claim that vulnerabilities are fixed unless low-risk changes were actually applied.",
        "When concrete files were changed, make the PR about those exact changes rather than about a broad security report.",
        "Only mention maintainer review for selected review-required items that are explicitly present in the draft.",
        "Keep the tone neutral, precise, and useful for a public open-source repository.",
        "Avoid marketing language, fear language, and unsupported claims.",
        "Preserve all redactions. Never reconstruct or invent secret values.",
        "Preserve a precise Markdown structure with Summary, Change or What changed, Motivation when relevant, and Notes.",
        "If the draft includes a concrete diff for a safe change, keep that diff and do not replace it with vague prose.",
      ].join(" "),
      prompt: JSON.stringify({
        repository: {
          source: input.report.sourceLabel,
          projectName: input.report.projectName,
          mode: input.report.analysisMode,
          riskScore: input.report.riskScore,
          baseline: input.report.baselineSummary,
          riskBreakdown: input.report.riskBreakdown,
          aiTriage: input.report.aiTriage
            ? {
                riskNarrative: input.report.aiTriage.riskNarrative,
                recommendedNextSteps: input.report.aiTriage.recommendedNextSteps.slice(0, 6),
              }
            : undefined,
        },
        selectedFindings: input.report.findings.slice(0, 20).map(formatFindingForPrompt),
        changes: {
          filesChanged: input.filesChanged,
          appliedFixes: input.appliedFixes,
          reviewRequired: input.skippedFixes.slice(0, 20),
        },
        deterministicDraft: sanitizePublicPullRequestCopy(input.draft),
        requestedOutput: {
          title: "Neutral PR title, <= 90 chars, no product branding.",
          body:
            "Professional human-authored PR body with Summary, What changed, Findings for maintainer review, Review notes. Include only true applied changes. No local links.",
          reportExecutiveSummary:
            "Short executive summary to prepend to the committed report markdown. It must explain scope, confidence, and review-required nature.",
        },
      }),
    })

    const sanitized = sanitizePublicPullRequestCopy({
      title: output.title,
      body: output.body,
      reportMarkdown: [
        "# Security review notes",
        "",
        "## Executive summary",
        "",
        output.reportExecutiveSummary,
        "",
        input.draft.reportMarkdown.replace(/^# Security review notes\s*/i, "").trimStart(),
      ].join("\n"),
    })

    if (!isUsablePullRequestCopy(sanitized)) return sanitizePublicPullRequestCopy(input.draft)
    return sanitized
  } catch {
    return sanitizePublicPullRequestCopy(input.draft)
  } finally {
    clearTimeout(timeout)
  }
}

function formatFindingForPrompt(finding: ScanFinding) {
  return {
    id: finding.id,
    severity: finding.severity,
    kind: finding.kind,
    category: finding.category,
    ruleId: finding.ruleId,
    title: finding.title,
    location: finding.lineStart ? `${finding.filePath}:${finding.lineStart}` : finding.filePath,
    confidence: Math.round(finding.confidence * 100),
    evidence: finding.evidence ? redactSecrets(finding.evidence).slice(0, 300) : undefined,
    recommendation: finding.recommendation.slice(0, 500),
    triage: finding.triage
      ? {
          verdict: finding.triage.verdict,
          reason: finding.triage.reason.slice(0, 400),
          detectedControls: finding.triage.detectedControls?.slice(0, 6),
          missingControls: finding.triage.missingControls?.slice(0, 6),
        }
      : undefined,
  }
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number.parseInt(value ?? "", 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}
