import "server-only"

import { createHash } from "node:crypto"
import { calculateRiskScore } from "@/lib/scanner/patches"
import { withReportDerivedFields } from "@/lib/scanner/enrich"
import { getSupabaseServiceClient } from "@/lib/supabase/server"
import { getGitHubSessionFromHeaders } from "@/lib/security/github-session"
import type { AuditTrailEvent, ScanFinding, ScanReport } from "@/lib/scanner/types"

export interface RequestIdentity {
  subjectHash: string
  kind: "supabase_user" | "github_user" | "anonymous"
  label: string
}

type HeaderSource = {
  get(name: string): string | null
}

export async function getRequestIdentity(request: Request): Promise<RequestIdentity> {
  return getRequestIdentityFromHeaders(request.headers)
}

export async function getRequestIdentityFromHeaders(headers: HeaderSource): Promise<RequestIdentity> {
  const githubSession = getGitHubSessionFromHeaders(headers)
  if (githubSession) {
    return {
      subjectHash: hashSubject(`github_user:${githubSession.id}`),
      kind: "github_user",
      label: "GitHub user",
    }
  }

  const userId = await getSupabaseUserId(headers)
  if (userId) {
    return {
      subjectHash: hashSubject(`supabase_user:${userId}`),
      kind: "supabase_user",
      label: "authenticated user",
    }
  }

  const ip = getClientIp(headers)

  return {
    subjectHash: hashSubject(`anonymous_ip:${ip}`),
    kind: "anonymous",
    label: "anonymous IP",
  }
}

export function attachReportOwner(report: ScanReport, identity: RequestIdentity): ScanReport {
  return {
    ...report,
    ownerHash: identity.subjectHash,
    ownerKind: identity.kind,
  }
}

export function canAccessReport(report: ScanReport, identity: RequestIdentity) {
  if (report.ownerHash) return report.ownerHash === identity.subjectHash
  return process.env.VIBESHIELD_ALLOW_LEGACY_REPORT_ACCESS === "true"
}

export function publicReport(report: ScanReport): ScanReport {
  const findings = report.findings.filter((finding) => !isLegacyCoverageFinding(finding))
  const removedLegacyFindings = report.findings.length - findings.length
  const safeReport = withReportDerivedFields({
    ...report,
    findings,
    auditTrail:
      removedLegacyFindings > 0
        ? normalizeLegacyCoverageAuditTrail(report.auditTrail, findings)
        : report.auditTrail,
    riskScore: calculateRiskScore(findings),
  })
  delete safeReport.ownerHash
  delete safeReport.ownerKind
  return safeReport
}

function normalizeLegacyCoverageAuditTrail(events: AuditTrailEvent[], findings: ScanFinding[]) {
  const patchable = findings.filter((finding) => finding.patchable).length

  return events.map((event) => {
    if (!event.metadata) return event

    const metadata = { ...event.metadata }
    if (typeof metadata.findings === "number") metadata.findings = findings.length
    if (typeof metadata.confirmedRuleFindings === "number") metadata.confirmedRuleFindings = findings.length
    if (typeof metadata.patchable === "number") metadata.patchable = patchable

    return { ...event, metadata }
  })
}

function isLegacyCoverageFinding(finding: ScanFinding) {
  return (
    finding.category === "dependency_signal" &&
    finding.severity === "info" &&
    finding.title === "Repository is outside primary Next.js/React coverage" &&
    /^Detected framework:/i.test(finding.evidence ?? "")
  )
}

async function getSupabaseUserId(headers: HeaderSource) {
  const token = getBearerToken(headers.get("authorization"))
  if (!token) return null

  const supabase = getSupabaseServiceClient()
  if (!supabase) return null

  const { data, error } = await supabase.auth.getUser(token)
  if (error || !data.user?.id) return null

  return data.user.id
}

function getBearerToken(header: string | null) {
  const match = /^Bearer\s+(.+)$/i.exec(header ?? "")
  return match?.[1]?.trim() || null
}

function getClientIp(headers: HeaderSource) {
  const candidate =
    normalizeHeader(headers.get("x-vercel-forwarded-for"), 80) ||
    normalizeHeader(headers.get("cf-connecting-ip"), 80) ||
    normalizeHeader(headers.get("x-real-ip"), 80) ||
    firstForwardedIp(headers.get("x-forwarded-for"))

  return candidate || "unknown-ip"
}

function firstForwardedIp(value: string | null) {
  const [first] = (value ?? "").split(",")
  return normalizeHeader(first, 80)
}

function normalizeHeader(value: string | null | undefined, maxLength: number) {
  return value?.trim().replace(/[^\w.:/-]/g, "").slice(0, maxLength) || null
}

function hashSubject(raw: string) {
  const salt =
    process.env.VIBESHIELD_IDENTITY_SALT ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SECRET_KEY ||
    "vibeshield-local-development"

  return createHash("sha256").update(`${salt}:${raw}`).digest("hex")
}
