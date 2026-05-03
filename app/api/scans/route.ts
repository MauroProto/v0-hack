import { NextResponse } from "next/server"
import { listScanReports } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { getRequestIdentity, publicReport } from "@/lib/security/request"
import { isSecurityError, peekMonthlyScanQuota, rateLimitHeaders } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  try {
    const identity = await getRequestIdentity(request)
    const [reports, quota] = await Promise.all([
      listScanReports(identity.subjectHash),
      peekMonthlyScanQuota(identity),
    ])

    return NextResponse.json({
      reports: reports.map(publicReport),
      quota,
    }, { headers: apiHeaders(rateLimitHeaders(quota)) })
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json(
        { error: error.message, code: error.code },
        { status: error.status, headers: apiHeaders(error.headers) },
      )
    }

    return NextResponse.json(
      { error: "Could not load scan history." },
      { status: 500, headers: apiHeaders() },
    )
  }
}
