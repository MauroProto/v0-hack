import "server-only"

import { createHash } from "node:crypto"
import { getSupabaseServiceClient } from "@/lib/supabase/server"
import type { ScanReport } from "@/lib/scanner/types"

export interface RequestIdentity {
  subjectHash: string
  kind: "supabase_user" | "anonymous"
  label: string
}

type HeaderSource = {
  get(name: string): string | null
}

export async function getRequestIdentity(request: Request): Promise<RequestIdentity> {
  return getRequestIdentityFromHeaders(request.headers)
}

export async function getRequestIdentityFromHeaders(headers: HeaderSource): Promise<RequestIdentity> {
  const userId = await getSupabaseUserId(headers)
  if (userId) {
    return {
      subjectHash: hashSubject(`supabase_user:${userId}`),
      kind: "supabase_user",
      label: "authenticated user",
    }
  }

  const ip = getClientIp(headers)
  const userAgent = normalizeHeader(headers.get("user-agent"), 180) || "unknown-user-agent"

  return {
    subjectHash: hashSubject(`anonymous:${ip}:${userAgent}`),
    kind: "anonymous",
    label: "anonymous session",
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
  const safeReport = { ...report }
  delete safeReport.ownerHash
  delete safeReport.ownerKind
  return safeReport
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
    firstForwardedIp(headers.get("x-forwarded-for")) ||
    normalizeHeader(headers.get("x-real-ip"), 80) ||
    normalizeHeader(headers.get("cf-connecting-ip"), 80) ||
    normalizeHeader(headers.get("x-vercel-forwarded-for"), 80)

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
