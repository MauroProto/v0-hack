import { NextResponse } from "next/server"
import { getScanReport } from "@/lib/scanner/store"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  const report = await getScanReport(scanId)
  const identity = await getRequestIdentity(request)

  if (!report || !canAccessReport(report, identity)) {
    return NextResponse.json({ error: "Scan report not found." }, { status: 404 })
  }

  return NextResponse.json({ report: publicReport(report) })
}
