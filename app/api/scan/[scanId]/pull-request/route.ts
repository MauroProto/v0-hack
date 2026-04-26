import { NextResponse } from "next/server"
import { auditEvent } from "@/lib/scanner/scan"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"
import { createRemediationPullRequest, getGitHubTokenFromRequest } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    assertContentLengthAllowed(request, 1_000)

    const identity = await getRequestIdentity(request)
    await assertBurstAllowed(identity, "pull_request")

    const current = await getScanReport(scanId)
    if (!current || !canAccessReport(current, identity)) {
      return NextResponse.json({ error: "Scan report not found." }, { status: 404, headers: apiHeaders() })
    }

    if (current.pullRequest) {
      return NextResponse.json(
        { report: publicReport(current), pullRequest: current.pullRequest },
        { headers: apiHeaders() },
      )
    }

    const token = getGitHubTokenFromRequest(request)
    if (!token) {
      return NextResponse.json(
        { error: "GitHub login is required to create a pull request." },
        { status: 401, headers: apiHeaders() },
      )
    }

    const pullRequest = await createRemediationPullRequest({
      report: current,
      token,
    })

    const report = await saveScanReport({
      ...current,
      pullRequest,
      auditTrail: [
        ...current.auditTrail,
        auditEvent("Create GitHub remediation pull request", "complete", {
          url: pullRequest.url,
          branch: pullRequest.branch,
          filesChanged: pullRequest.filesChanged.length,
          appliedFixes: pullRequest.appliedFixes.length,
          reviewRequired: pullRequest.skippedFixes.length,
        }),
      ],
    })

    return NextResponse.json({ report: publicReport(report), pullRequest }, { headers: apiHeaders() })
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
    }

    const message = error instanceof Error ? error.message : "Could not create GitHub pull request."
    return NextResponse.json({ error: message }, { status: statusForPullRequestError(message), headers: apiHeaders() })
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: apiHeaders() })
}

function statusForPullRequestError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes("token") || normalized.includes("authorization")) return 401
  if (normalized.includes("permission") || normalized.includes("push a branch")) return 403
  if (normalized.includes("metadata") || normalized.includes("repository")) return 400
  return 502
}
