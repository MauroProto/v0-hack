import { createHash, timingSafeEqual } from "node:crypto"
import { NextResponse } from "next/server"
import { reviewProjectWithAi } from "@/lib/ai/reviewProject"
import { badgerEnv } from "@/lib/config/env"
import { getScannerLimitsForMode } from "@/lib/scanner/extract"
import { appendScanEvent, claimNextScanJob, completeScanJob, failScanJob } from "@/lib/scanner/jobs"
import { applyReportPolicy } from "@/lib/scanner/reportPolicy"
import { auditEvent, scanProject } from "@/lib/scanner/scan"
import { getScanBaseline, saveScanReport, updateScanReport } from "@/lib/scanner/store"
import type { ScanJob, ScanReport } from "@/lib/scanner/types"
import { apiHeaders } from "@/lib/security/headers"
import { publicReport } from "@/lib/security/request"
import { assertContentLengthAllowed, isSecurityError } from "@/lib/security/quota"
import { extractProjectFromGitHubRepo } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 300

export async function POST(request: Request) {
  try {
    assertContentLengthAllowed(request, 1_000)
    if (!isAuthorizedWorker(request)) {
      return NextResponse.json({ error: "Worker authorization failed." }, { status: 401, headers: apiHeaders() })
    }

    const job = await claimNextScanJob()
    if (!job) return NextResponse.json({ processed: false }, { headers: apiHeaders() })

    try {
      const report = await processScanJob(job)
      await completeScanJob(job.id, report.id)
      return NextResponse.json({ processed: true, report: publicReport(report) }, { headers: apiHeaders() })
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan job failed."
      await failScanJob(job.id, message)
      const failedReport = await markReportFailed(job, message)
      return NextResponse.json(
        { processed: true, error: message, report: failedReport ? publicReport(failedReport) : undefined },
        { status: 500, headers: apiHeaders() },
      )
    }
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
    }

    return NextResponse.json({ error: "Could not drain scan jobs." }, { status: 500, headers: apiHeaders() })
  }
}

async function processScanJob(job: ScanJob) {
  if (job.repository.private) {
    throw new Error("Background scans require a public repository or a GitHub App installation token.")
  }

  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "Extraction started", status: "running" })
  const extracted = await extractProjectFromGitHubRepo({
    owner: job.repository.owner,
    repo: job.repository.repo,
    ref: job.repository.ref || undefined,
    limits: getScannerLimitsForMode(job.analysisMode),
  })
  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "Extraction completed", status: "complete", metadata: { files: extracted.files.length } })

  const deterministicReport = await scanProject({
    ...extracted,
    sourceType: "github",
    sourceLabel: extracted.sourceLabel,
    analysisMode: job.analysisMode,
  })
  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "Scanner completed", status: "complete", metadata: { findings: deterministicReport.findings.length } })

  const reviewedReport = await reviewProjectWithAi(
    {
      ...deterministicReport,
      id: job.reportId,
      repository: {
        owner: job.repository.owner,
        repo: job.repository.repo,
        ref: extracted.ref,
        defaultBranch: extracted.defaultBranch,
        private: extracted.private,
        htmlUrl: extracted.htmlUrl,
      },
      ownerHash: job.ownerHash,
      sourceLabel: extracted.sourceLabel,
      jobId: job.id,
      status: "completed",
      eventsAvailable: true,
    },
    extracted.files,
  )
  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "AI review completed", status: "complete", metadata: { findings: reviewedReport.findings.length } })

  const baseline = await getScanBaseline(reviewedReport.sourceLabel, job.ownerHash)
  return saveScanReport(applyReportPolicy({
    ...reviewedReport,
    id: job.reportId,
    ownerHash: job.ownerHash,
    jobId: job.id,
    status: "completed",
    eventsAvailable: true,
  }, extracted.files, baseline))
}

async function markReportFailed(job: ScanJob, message: string): Promise<ScanReport | undefined> {
  const error = message.slice(0, 500)
  return updateScanReport(job.reportId, (report) => ({
    ...report,
    status: "failed",
    error,
    auditTrail: [
      ...report.auditTrail,
      auditEvent("Drain scan job", "failed", {
        jobId: job.id,
        error,
      }),
    ],
  }))
}

function isAuthorizedWorker(request: Request) {
  const expected = badgerEnv("WORKER_SECRET")
  if (!expected) return false

  const authorization = request.headers.get("authorization") ?? ""
  const bearer = authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim()
  const provided = bearer || request.headers.get("x-badger-worker-secret")?.trim() || request.headers.get("x-vibeshield-worker-secret")?.trim()
  if (!provided) return false

  return safeEqual(provided, expected)
}

function safeEqual(a: string, b: string) {
  const left = createHash("sha256").update(a).digest()
  const right = createHash("sha256").update(b).digest()
  return timingSafeEqual(left, right)
}
