import { generateText, Output } from "ai"
import { resolveAiModel } from "@/lib/ai/model"
import { PatchSchema } from "@/lib/ai/structuredSchemas"
import { createDeterministicPatch } from "@/lib/scanner/patches"
import { redactSecrets } from "@/lib/scanner/rules"
import type { PatchSuggestion, ScanFinding } from "@/lib/scanner/types"

export async function generatePatch(finding: ScanFinding, fileSnippet?: string): Promise<PatchSuggestion | undefined> {
  const fallback = createDeterministicPatch(finding)
  if (!finding.patchable) return fallback
  const aiModel = resolveAiModel()
  if (!aiModel) return fallback

  try {
    const { output } = await generateText({
      model: aiModel.model,
      providerOptions: aiModel.providerOptions,
      output: Output.object({ schema: PatchSchema }),
      system: [
        "You generate conservative patch suggestions for security findings.",
        "Never include full secrets. Do not claim the patch is automatically safe.",
        "Return a short review-required patch preview only.",
      ].join(" "),
      prompt: JSON.stringify({
        finding: {
          severity: finding.severity,
          category: finding.category,
          title: finding.title,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          evidence: redactSecrets(finding.evidence ?? ""),
          recommendation: finding.recommendation,
        },
        redactedContext: redactSecrets((fileSnippet ?? "").slice(0, 2500)),
      }),
    })

    return {
      ...output,
      reviewRequired: true,
    }
  } catch {
    return fallback
  }
}
