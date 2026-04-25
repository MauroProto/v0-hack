import { NextResponse } from "next/server"
import { z } from "zod"
import { reviewProjectWithAi } from "@/lib/ai/reviewProject"
import { scanProject } from "@/lib/scanner/scan"
import { saveScanReport } from "@/lib/scanner/store"
import { apiHeaders } from "@/lib/security/headers"
import { attachReportOwner, getRequestIdentity, publicReport } from "@/lib/security/request"
import {
  assertBurstAllowed,
  assertContentLengthAllowed,
  consumeMonthlyScanQuota,
  isSecurityError,
  rateLimitHeaders,
  type QuotaState,
} from "@/lib/security/quota"
import {
  extractProjectFromGitHubRepo,
  getGitHubTokenFromRequest,
  parseGitHubFullName,
  parsePublicGitHubUrl,
} from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

const JsonScanSchema = z
  .object({
    githubUrl: z.string().trim().min(1).optional(),
    repoFullName: z.string().trim().min(1).optional(),
    ref: z.string().trim().min(1).max(120).optional(),
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

    assertContentLengthAllowed(request, 20_000)
    const body = JsonScanSchema.parse(await request.json())
    const token = getGitHubTokenFromRequest(request)
    const repo = body.repoFullName ? parseGitHubFullName(body.repoFullName) : parsePublicGitHubUrl(body.githubUrl ?? "")
    const quota = await consumeMonthlyScanQuota(identity)

    const extracted = await extractProjectFromGitHubRepo({
      ...repo,
      ref: body.ref,
      token,
    })

    const deterministicReport = scanProject({
      ...extracted,
      sourceType: "github",
      sourceLabel: extracted.sourceLabel,
    })
    const reviewedReport = await reviewProjectWithAi(deterministicReport, extracted.files)

    const report = await saveScanReport(
      attachReportOwner(
        reviewedReport,
        identity,
      ),
    )

    return jsonWithQuota({ scanId: report.id, report: publicReport(report), quota }, quota)
  } catch (error) {
    return errorResponse(error)
  }
}

function getErrorStatus(error: unknown) {
  if (isSecurityError(error)) return error.status
  if (error instanceof SyntaxError) return 400
  if (error instanceof z.ZodError) return 400
  const message = getErrorMessage(error).toLowerCase()
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
