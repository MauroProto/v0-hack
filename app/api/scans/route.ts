import { NextResponse } from "next/server"
import { listScanReports } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { getRequestIdentity, publicReport } from "@/lib/security/request"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  const identity = await getRequestIdentity(request)
  const reports = await listScanReports(identity.subjectHash)

  return NextResponse.json({
    reports: reports.map(publicReport),
  }, { headers: apiHeaders() })
}
