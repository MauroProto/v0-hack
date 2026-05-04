import { NextResponse } from "next/server"
import { z } from "zod"
import { auditEvent } from "@/lib/scanner/scan"
import { filterReportFindings } from "@/lib/scanner/patches"
import { getScanReport, saveScanReport } from "@/lib/scanner/store"
import type { ScanReport } from "@/lib/scanner/types"
import { readJsonBodyWithLimit } from "@/lib/security/body"
import { apiHeaders } from "@/lib/security/headers"
import { canAccessReport, getRequestIdentity, publicReport } from "@/lib/security/request"
import { getGitHubSessionFromHeaders } from "@/lib/security/github-session"
import { assertBurstAllowed, assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"
import { createRemediationPullRequest, getGitHubTokenFromRequest } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 300

const PullRequestSelectionSchema = z.object({
  includeAllActive: z.boolean().optional(),
  findingIds: z.array(z.string().min(1).max(40)).max(1_000).optional(),
})

type PullRequestSelection = z.infer<typeof PullRequestSelectionSchema>

export async function POST(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params
    assertContentLengthAllowed(request, 60_000)
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

    const selectedFindingIds = resolveSelectedFindingIds(current, selection)
    if (selectedFindingIds.length === 0) {
      return NextResponse.json({ error: "Select at least one finding before creating a pull request." }, { status: 400, headers: apiHeaders() })
    }

    const scopedReport = filterReportFindings(current, selectedFindingIds)
    if (scopedReport.findings.length === 0) {
      return NextResponse.json({ error: "Selected findings were not found in this report." }, { status: 400, headers: apiHeaders() })
    }

    const selectedById = new Set(scopedReport.findings.map((finding) => finding.id))
    const rejected = current.findings.filter((finding) => selectedFindingIds.includes(finding.id) && finding.suppressed)
    if (rejected.length > 0 || selectedById.size !== selectedFindingIds.length) {
      return NextResponse.json(
        { error: "Pull requests can only include selected active findings." },
        { status: 400, headers: apiHeaders() },
      )
    }

    const token = getGitHubTokenFromRequest(request)
    if (!token) {
      return NextResponse.json(
        { error: "GitHub login is required to create a pull request.", code: "github_login_required" },
        { status: 401, headers: apiHeaders() },
      )
    }

    const githubSession = getGitHubSessionFromHeaders(request.headers)
    if (githubSession && !hasPublicPullRequestScope(githubSession.scopes)) {
      return NextResponse.json(
        {
          error: "GitHub PR permission is required before Badger can fork or push a remediation branch.",
          code: "github_pr_scope_required",
        },
        { status: 403, headers: apiHeaders() },
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
        auditEvent("Create GitHub scan follow-up pull request", "complete", {
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

  return PullRequestSelectionSchema.parse(await readJsonBodyWithLimit(request, 60_000))
}

function resolveSelectedFindingIds(report: ScanReport, selection: PullRequestSelection) {
  if (selection.includeAllActive) {
    return report.findings.filter((finding) => !finding.suppressed).map((finding) => finding.id)
  }

  return [...new Set(selection.findingIds ?? [])]
}

function statusForPullRequestError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes("token") || normalized.includes("authorization")) return 401
  if (normalized.includes("permission") || normalized.includes("push a branch")) return 403
  if (normalized.includes("not found") || normalized.includes("private")) return 404
  if (normalized.includes("no safe code changes")) return 400
  if (normalized.includes("claude") || normalized.includes("safety review")) return 400
  if (normalized.includes("select") || normalized.includes("json")) return 400
  if (normalized.includes("metadata") || normalized.includes("repository")) return 400
  return 502
}

function hasPublicPullRequestScope(scopes: string[]) {
  return scopes.some((scope) => scope === "public_repo" || scope === "repo")
}
