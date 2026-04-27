import { NextResponse } from "next/server"
import { z } from "zod"
import { auditEvent } from "@/lib/scanner/scan"
import { filterReportFindings } from "@/lib/scanner/patches"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import { readJsonBodyWithLimit } from "@/lib/security/body"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"
import { createRemediationPullRequest, getGitHubTokenFromRequest } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

const PullRequestSelectionSchema = z.object({
  findingIds: z.array(z.string().min(1).max(40)).max(100).optional(),
})

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    assertContentLengthAllowed(request, 4_000)
    const selection = await readPullRequestSelection(request)

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

    if (selection.findingIds && selection.findingIds.length === 0) {
      return NextResponse.json({ error: "Select at least one finding before creating a pull request." }, { status: 400, headers: apiHeaders() })
    }

    const scopedReport = filterReportFindings(current, selection.findingIds)
    if (selection.findingIds && scopedReport.findings.length === 0) {
      return NextResponse.json({ error: "Selected findings were not found in this report." }, { status: 400, headers: apiHeaders() })
    }

    const token = getGitHubTokenFromRequest(request)
    if (!token) {
      return NextResponse.json(
        { error: "GitHub login is required to create a pull request." },
        { status: 401, headers: apiHeaders() },
      )
    }

    const pullRequest = await createRemediationPullRequest({
      report: scopedReport,
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
          selectedFindings: scopedReport.findings.length,
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

async function readPullRequestSelection(request: Request) {
  const contentType = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()
  if (!contentType) return {}
  if (contentType !== "application/json") {
    throw new Error("Use application/json when selecting findings for a pull request.")
  }

  return PullRequestSelectionSchema.parse(await readJsonBodyWithLimit(request, 4_000))
}

function statusForPullRequestError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes("token") || normalized.includes("authorization")) return 401
  if (normalized.includes("permission") || normalized.includes("push a branch")) return 403
  if (normalized.includes("select") || normalized.includes("json")) return 400
  if (normalized.includes("metadata") || normalized.includes("repository")) return 400
  return 502
}
