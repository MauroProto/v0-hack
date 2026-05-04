import { NextResponse } from "next/server"
import { withReportDerivedFields } from "@/lib/scanner/enrich"
import { createBaselineFromReport } from "@/lib/scanner/reportPolicy"
import { auditEvent } from "@/lib/scanner/scan"
import { getScanReport, saveScanBaseline, saveScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { assertSameOriginRequest } from "@/lib/security/origin"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    assertSameOriginRequest(request)
    const { scanId } = await params
    assertContentLengthAllowed(request, 1_000)

    const identity = await getRequestIdentity(request)
    await assertBurstAllowed(identity, "scan")

    const current = await getScanReport(scanId)
    if (!current || !canAccessReport(current, identity)) {
      return NextResponse.json({ error: "Scan report not found." }, { status: 404, headers: apiHeaders() })
    }

    const baseline = await saveScanBaseline(createBaselineFromReport(current))
    const activeExisting = current.findings.filter((finding) => !finding.suppressed && finding.fingerprint).length
    const suppressed = current.findings.filter((finding) => finding.suppressed).length
    const report = await saveScanReport(withReportDerivedFields({
      ...current,
      findings: current.findings.map((finding) =>
        !finding.suppressed && finding.fingerprint ? { ...finding, baselineState: "existing" as const } : finding,
      ),
      baselineSummary: {
        new: 0,
        existing: activeExisting,
        resolved: 0,
        suppressed,
      },
      auditTrail: [
        ...current.auditTrail,
        auditEvent("Save repository baseline", "complete", {
          baselineId: baseline.id,
          findings: baseline.findingCount,
        }),
      ],
    }))

    return NextResponse.json({ baseline, report: publicReport(report) }, { headers: apiHeaders() })
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
    }

    return NextResponse.json({ error: "Could not save scan baseline." }, { status: 500, headers: apiHeaders() })
  }
}
