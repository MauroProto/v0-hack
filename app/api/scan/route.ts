import { NextResponse } from "next/server"
import { z } from "zod"
import { reviewProjectWithAi } from "@/lib/ai/reviewProject"
import { withReportDerivedFields } from "@/lib/scanner/enrich"
import { getScannerLimitsForMode } from "@/lib/scanner/extract"
import { appendScanEvent, backgroundJobsEnabled, createScanJob } from "@/lib/scanner/jobs"
import { applyReportPolicy } from "@/lib/scanner/reportPolicy"
import { scanProject } from "@/lib/scanner/scan"
import { getScanBaseline, saveScanReport } from "@/lib/scanner/store"
import type { ScanRepositoryRef } from "@/lib/scanner/types"
import { readJsonBodyWithLimit } from "@/lib/security/body"
import { apiHeaders } from "@/lib/security/headers"
import { attachReportOwner, getRequestIdentity, publicReport } from "@/lib/security/request"
import {
  assertBurstAllowed,
  consumeMonthlyScanQuota,
  isSecurityError,
  rateLimitHeaders,
  scanCreditCostForMode,
  type QuotaState,
} from "@/lib/security/quota"
import {
  extractProjectFromGitHubRepo,
  getGitHubTokenFromRequest,
  getPublicGitHubReadTokenFromRequest,
  parseGitHubFullName,
  parsePublicGitHubUrl,
} from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 300

const JsonScanSchema = z
  .object({
    githubUrl: z.string().trim().min(1).optional(),
    repoFullName: z.string().trim().min(1).optional(),
    ref: z.string().trim().min(1).max(120).optional(),
    analysisMode: z.enum(["rules", "normal", "max"]).default("normal"),
  })
  .refine((value) => value.githubUrl || value.repoFullName, {
    message: "Provide githubUrl or repoFullName.",
  })
  .refine((value) => Number(Boolean(value.githubUrl)) + Number(Boolean(value.repoFullName)) === 1, {
    message: "Choose exactly one scan source.",
  })

export async function POST(request: Request) {
  try {
    const identity = await getRequestIdentity(request)
    await assertBurstAllowed(identity, "scan")

    if (!isJsonContentType(request.headers.get("content-type"))) {
      return NextResponse.json({ error: "Use application/json. ZIP uploads are disabled for security." }, { status: 415, headers: apiHeaders() })
    }

    const body = JsonScanSchema.parse(await readJsonBodyWithLimit(request, 20_000))
    if (identity.kind === "anonymous" && body.repoFullName) {
      return NextResponse.json(
        { error: "Login with GitHub before scanning repositories from an account list.", code: "github_login_required" },
        { status: 401, headers: apiHeaders() },
      )
    }

    const token = body.githubUrl ? await getPublicGitHubReadTokenFromRequest(request) : getGitHubTokenFromRequest(request)
    const repo = body.repoFullName ? parseGitHubFullName(body.repoFullName) : parsePublicGitHubUrl(body.githubUrl ?? "")
    const creditsUsed = scanCreditCostForMode(body.analysisMode)
    const quota = await consumeMonthlyScanQuota(identity, creditsUsed)

    if (shouldQueueScan(body.analysisMode, token)) {
      const report = await createQueuedScanReport({
        repo,
        ref: body.ref,
        analysisMode: body.analysisMode,
        ownerHash: identity.subjectHash,
        ownerKind: identity.kind,
      })

      return jsonWithQuota({ scanId: report.id, report: publicReport(report), quota, creditsUsed }, quota)
    }

    const extracted = await extractProjectFromGitHubRepo({
      ...repo,
      ref: body.ref,
      token,
      limits: getScannerLimitsForMode(body.analysisMode),
    })

    const deterministicReport = await scanProject({
      ...extracted,
      sourceType: "github",
      sourceLabel: extracted.sourceLabel,
      analysisMode: body.analysisMode,
    })
    await appendScanEvent({ reportId: deterministicReport.id, label: "Scanner completed", status: "complete", metadata: { findings: deterministicReport.findings.length } })

    const reviewedReport = await reviewProjectWithAi(
      {
        ...deterministicReport,
        repository: {
          owner: repo.owner,
          repo: repo.repo,
          ref: extracted.ref,
          defaultBranch: extracted.defaultBranch,
          private: extracted.private,
          htmlUrl: extracted.htmlUrl,
        },
      },
      extracted.files,
    )
    await appendScanEvent({ reportId: reviewedReport.id, label: "AI review completed", status: "complete", metadata: { findings: reviewedReport.findings.length } })

    const ownedReport = attachReportOwner(reviewedReport, identity)
    const baseline = await getScanBaseline(ownedReport.sourceLabel, ownedReport.ownerHash)
    const policyReport = applyReportPolicy(
      {
        ...ownedReport,
        eventsAvailable: true,
      },
      extracted.files,
      baseline,
    )

    const report = await saveScanReport(
      policyReport,
    )

    return jsonWithQuota({ scanId: report.id, report: publicReport(report), quota, creditsUsed }, quota)
  } catch (error) {
    return errorResponse(error)
  }
}

function getErrorStatus(error: unknown) {
  if (isSecurityError(error)) return error.status
  if (error instanceof SyntaxError) return 400
  if (error instanceof z.ZodError) return 400
  const message = getErrorMessage(error).toLowerCase()
  if (message.includes("rate limit")) return 429
  if (message.includes("not found") || message.includes("private")) return 404
  if (message.includes("temporarily unavailable") || message.includes("could not be reached")) return 502
  if (message.includes("too large")) return 413
  if (message.includes("too many")) return 413
  if (message.includes("unsupported") || message.includes("github") || message.includes("repository")) return 400
  if (message.includes("provide either")) return 400
  if (message.includes("no supported text files")) return 400
  return 500
}

function isJsonContentType(contentType: string | null) {
  return contentType?.split(";")[0]?.trim().toLowerCase() === "application/json"
}

function getErrorMessage(error: unknown) {
  if (error instanceof SyntaxError) return "Invalid JSON body."
  if (error instanceof z.ZodError) return error.errors.map((issue) => issue.message).join(" ")
  if (error instanceof Error) return error.message
  return "Scan failed."
}

function errorResponse(error: unknown) {
  if (isSecurityError(error)) {
    return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
  }

  return NextResponse.json({ error: getErrorMessage(error) }, { status: getErrorStatus(error), headers: apiHeaders() })
}

function jsonWithQuota(body: Record<string, unknown>, quota: QuotaState) {
  return NextResponse.json(body, { headers: apiHeaders(rateLimitHeaders(quota)) })
}

function shouldQueueScan(analysisMode: "rules" | "normal" | "max", token?: string) {
  return backgroundJobsEnabled() && analysisMode === "max" && !token
}

async function createQueuedScanReport(input: {
  repo: { owner: string; repo: string }
  ref?: string
  analysisMode: "rules" | "normal" | "max"
  ownerHash: string
  ownerKind: "supabase_user" | "github_user" | "anonymous"
}) {
  const reportId = crypto.randomUUID()
  const sourceLabel = input.ref
    ? `github.com/${input.repo.owner}/${input.repo.repo}#${input.ref}`
    : `github.com/${input.repo.owner}/${input.repo.repo}`
  const repository: ScanRepositoryRef = {
    owner: input.repo.owner,
    repo: input.repo.repo,
    ref: input.ref ?? "",
    defaultBranch: input.ref ?? "",
    private: false,
    htmlUrl: `https://github.com/${input.repo.owner}/${input.repo.repo}`,
  }
  const job = await createScanJob({
    ownerHash: input.ownerHash,
    reportId,
    projectName: input.repo.repo,
    sourceLabel,
    analysisMode: input.analysisMode,
    repository,
  })

  return saveScanReport(withReportDerivedFields({
    id: reportId,
    createdAt: new Date().toISOString(),
    projectName: input.repo.repo,
    repository,
    ownerHash: input.ownerHash,
    ownerKind: input.ownerKind,
    sourceType: "github",
    sourceLabel,
    analysisMode: input.analysisMode,
    status: "queued",
    jobId: job.id,
    eventsAvailable: true,
    riskScore: 0,
    filesInspected: 0,
    apiRoutesInspected: 0,
    clientComponentsInspected: 0,
    aiEndpointsInspected: 0,
    findings: [],
    auditTrail: [
      {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        label: "Queue scan job",
        status: "complete",
        metadata: {
          source: sourceLabel,
          mode: input.analysisMode,
        },
      },
    ],
  }))
}
