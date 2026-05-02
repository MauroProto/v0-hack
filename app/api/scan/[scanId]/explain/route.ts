import { NextResponse } from "next/server"
import { explainFinding, fallbackExplanation } from "@/lib/ai/explainFinding"
import { getAiModelStatus } from "@/lib/ai/model"
import { withReportDerivedFields } from "@/lib/scanner/enrich"
import { compareFindingsForReport } from "@/lib/scanner/prioritize"
import { auditEvent } from "@/lib/scanner/scan"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 300

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    assertContentLengthAllowed(request, 1_000)

    const aiStatus = getAiModelStatus()
    const identity = await getRequestIdentity(request)
    await assertBurstAllowed(identity, "explain")

    const current = await getScanReport(scanId)

    if (!current || !canAccessReport(current, identity)) {
      return NextResponse.json({ error: "Scan report not found." }, { status: 404, headers: apiHeaders() })
    }

    const maxAiExplanations = aiStatus.configured ? maxAiExplanationsForReport(current) : 0
    const aiEligibleFindingIds = new Set(
      [...current.findings]
        .filter((finding) => !finding.suppressed && !(finding.explanation && finding.patch))
        .sort(compareFindingsForReport)
        .slice(0, maxAiExplanations)
        .map((finding) => finding.id),
    )
    let aiExplanationsRequested = 0
    let fallbackExplanations = 0
    const findings = []
    for (const finding of current.findings) {
      if (finding.explanation && finding.patch) {
        findings.push(finding)
        continue
      }

      const useAi = aiEligibleFindingIds.has(finding.id)
      const explanation = useAi
        ? await withFindingTimeout(explainFinding(finding, {
            projectName: current.projectName,
            framework: current.framework,
            sourceType: current.sourceType,
            sourceLabel: current.sourceLabel,
            repositoryPrivate: current.repository?.private,
          }), fallbackExplanation(finding))
        : fallbackExplanation(finding)

      if (useAi) aiExplanationsRequested += 1
      else fallbackExplanations += 1

      findings.push({
        ...finding,
        explanation,
        patch: explanation.patch ?? finding.patch,
        source: "hybrid" as const,
      })
    }

    const report = await saveScanReport(withReportDerivedFields({
      ...current,
      findings,
      auditTrail: [
        ...current.auditTrail,
        auditEvent("Generate AI explanations and patch previews", "complete", {
          aiConfigured: aiStatus.configured,
          aiProvider: aiStatus.provider ?? "deterministic_fallback",
          aiModel: aiStatus.modelId ?? "none",
          findings: findings.length,
          aiExplanationsRequested,
          fallbackExplanations,
        }),
      ],
    }))

    return NextResponse.json({ report: publicReport(report) }, { headers: apiHeaders() })
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
    }

    return NextResponse.json({ error: "Could not generate explanations." }, { status: 500, headers: apiHeaders() })
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: apiHeaders() })
}

async function withFindingTimeout(promise: Promise<ReturnType<typeof fallbackExplanation>>, fallback: ReturnType<typeof fallbackExplanation>) {
  let timeout: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<ReturnType<typeof fallbackExplanation>>((resolve) => {
        timeout = setTimeout(() => resolve(fallback), aiFindingBudgetMs())
      }),
    ])
  } finally {
    if (timeout) clearTimeout(timeout)
  }
}

function maxAiExplanationsForReport(report: { analysisMode?: "rules" | "normal" | "max" }) {
  const envValue = Number(process.env.VIBESHIELD_AI_EXPLAIN_MAX_FINDINGS)
  if (Number.isFinite(envValue) && envValue >= 0) return Math.min(Math.floor(envValue), 6)
  if (report.analysisMode === "max") return 3
  return 2
}

function aiFindingBudgetMs() {
  const parsed = Number(process.env.VIBESHIELD_AI_EXPLAIN_FINDING_BUDGET_MS)
  if (!Number.isFinite(parsed) || parsed <= 0) return 9_000
  return Math.min(Math.floor(parsed), 15_000)
}
