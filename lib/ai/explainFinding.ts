import { generateText, Output } from "ai"
import { z } from "zod"
import { resolveAiModel } from "@/lib/ai/model"
import { createDeterministicPatch } from "@/lib/scanner/patches"
import { redactSecrets } from "@/lib/scanner/rules"
import type { FindingExplanation, ScanFinding, ScanReport } from "@/lib/scanner/types"

const ExplanationSchema = z.object({
  summary: z.string().min(1).max(800),
  impact: z.string().min(1).max(900),
  fixSteps: z.array(z.string().min(1).max(300)).min(1).max(6),
  patch: z
    .object({
      title: z.string().min(1).max(160),
      summary: z.string().min(1).max(700),
      unifiedDiff: z.string().max(3000).optional(),
      reviewRequired: z.literal(true),
    })
    .optional(),
})

export type ExplainFindingContext = Pick<ScanReport, "projectName" | "framework" | "sourceType" | "sourceLabel"> & {
  fileSnippet?: string
}

export async function explainFinding(
  finding: ScanFinding,
  context: ExplainFindingContext,
): Promise<FindingExplanation> {
  const fallback = fallbackExplanation(finding)
  const aiModel = resolveAiModel()
  if (!aiModel) return fallback

  try {
    const { output } = await generateText({
      model: aiModel.model,
      providerOptions: aiModel.providerOptions,
      output: Output.object({
        schema: ExplanationSchema,
      }),
      system: [
        "You are VibeShield, a security scanner for AI-built Next.js and React apps.",
        "Explain deterministic static-analysis findings in practical language.",
        "Never include full secrets. Treat evidence as redacted. Patch suggestions must be conservative and review-required.",
      ].join(" "),
      prompt: JSON.stringify({
        project: {
          name: context.projectName,
          framework: context.framework,
          sourceType: context.sourceType,
          sourceLabel: context.sourceLabel,
        },
        finding: {
          severity: finding.severity,
          category: finding.category,
          title: finding.title,
          description: finding.description,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          evidence: redactSecrets(finding.evidence ?? ""),
          recommendation: finding.recommendation,
          patchable: finding.patchable,
        },
        redactedContext: redactSecrets((context.fileSnippet ?? "").slice(0, 2500)),
      }),
    })

    return {
      summary: output.summary,
      impact: output.impact,
      fixSteps: output.fixSteps,
      patch: output.patch
        ? {
            ...output.patch,
            reviewRequired: true,
          }
        : fallback.patch,
    }
  } catch {
    return fallback
  }
}

export function fallbackExplanation(finding: ScanFinding): FindingExplanation {
  return {
    summary: `${finding.title} in ${formatLocation(finding)}.`,
    impact: finding.description,
    fixSteps: [
      finding.recommendation,
      "Review the affected code path manually before shipping.",
      "Re-run the scan after applying the change.",
    ],
    patch: createDeterministicPatch(finding),
  }
}

function formatLocation(finding: ScanFinding) {
  if (!finding.lineStart) return finding.filePath
  return `${finding.filePath}:${finding.lineStart}`
}
