import { NextResponse } from "next/server"
import { explainFinding } from "@/lib/ai/explainFinding"
import { getAiModelStatus } from "@/lib/ai/model"
import { auditEvent } from "@/lib/scanner/scan"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

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

    const findings = []
    for (const finding of current.findings) {
      if (finding.explanation && finding.patch) {
        findings.push(finding)
        continue
      }

      const explanation = await explainFinding(finding, {
        projectName: current.projectName,
        framework: current.framework,
        sourceType: current.sourceType,
        sourceLabel: current.sourceLabel,
        repositoryPrivate: current.repository?.private,
      })

      findings.push({
        ...finding,
        explanation,
        patch: explanation.patch ?? finding.patch,
        source: "hybrid" as const,
      })
    }

    const report = await saveScanReport({
      ...current,
      findings,
      auditTrail: [
        ...current.auditTrail,
        auditEvent("Generate AI explanations and patch previews", "complete", {
          aiConfigured: aiStatus.configured,
          aiProvider: aiStatus.provider ?? "deterministic_fallback",
          aiModel: aiStatus.modelId ?? "none",
          findings: findings.length,
        }),
      ],
    })

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
