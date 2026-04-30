import { NextResponse } from "next/server"
import { generateSarif } from "@/lib/scanner/sarif"
import { getScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  const report = await getScanReport(scanId)
  const identity = await getRequestIdentity(request)

  if (!report || !canAccessReport(report, identity)) {
    return NextResponse.json({ error: "Scan report not found." }, { status: 404, headers: apiHeaders() })
  }

  return NextResponse.json(generateSarif(publicReport(report)), {
    headers: apiHeaders({
      "Content-Disposition": `attachment; filename="vibeshield-${scanId}.sarif.json"`,
    }),
  })
}
