import { NextResponse } from "next/server"
import { explainFinding } from "@/lib/ai/explainFinding"
import { auditEvent } from "@/lib/scanner/scan"
import { getOrCreateDemoReport } from "@/lib/scanner/demo"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, isSecurityError } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    const identity = await getRequestIdentity(request)
    await assertBurstAllowed(identity, "explain")

    const current = scanId === "demo" ? await getOrCreateDemoReport() : await getScanReport(scanId)

    if (!current || !canAccessReport(current, identity)) {
      return NextResponse.json({ error: "Scan report not found." }, { status: 404 })
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
          aiConfigured: Boolean(process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN),
          findings: findings.length,
        }),
      ],
    })

    return NextResponse.json({ report: publicReport(report) })
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: error.headers })
    }

    return NextResponse.json({ error: "Could not generate explanations." }, { status: 500 })
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204 })
}
