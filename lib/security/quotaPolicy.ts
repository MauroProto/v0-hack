import { badgerEnv } from "@/lib/config/env"

export type MonthlyQuotaIdentity = {
  kind: "clerk_user" | "supabase_user" | "github_user" | "anonymous"
  quotaSubjectHash: string
  linkedQuotaSubjectHash?: string
}

export type LinkedQuotaPlan = {
  allowed: boolean
  primaryCost: number
  remaining: number
  effectiveCount: number
}

const ANONYMOUS_MONTHLY_SCAN_QUOTA = 5
const AUTHENTICATED_MONTHLY_SCAN_QUOTA = 7

export function monthlyScanQuotaLimit(identity: MonthlyQuotaIdentity) {
  if (identity.kind === "anonymous") {
    return readPositiveInt(badgerEnv("ANONYMOUS_MONTHLY_SCAN_QUOTA"), ANONYMOUS_MONTHLY_SCAN_QUOTA)
  }

  return readPositiveInt(badgerEnv("AUTHENTICATED_MONTHLY_SCAN_QUOTA"), AUTHENTICATED_MONTHLY_SCAN_QUOTA)
}

export function monthlyQuotaPrimarySubject(identity: MonthlyQuotaIdentity) {
  return identity.quotaSubjectHash
}

export function monthlyQuotaLinkedSubject(identity: MonthlyQuotaIdentity) {
  const linked = identity.linkedQuotaSubjectHash
  if (!linked || linked === identity.quotaSubjectHash) return null
  return linked
}

export function planLinkedMonthlyQuotaConsumption(input: {
  primaryCount: number
  linkedCount?: number
  limit: number
  requestCost: number
}): LinkedQuotaPlan {
  const primaryCount = normalizeCount(input.primaryCount)
  const linkedCount = normalizeCount(input.linkedCount ?? 0)
  const requestCost = normalizeCount(input.requestCost) || 1
  const limit = Math.max(1, Math.floor(input.limit))
  const baseline = Math.max(primaryCount, linkedCount)
  const effectiveCount = baseline + requestCost

  if (effectiveCount > limit) {
    return {
      allowed: false,
      primaryCost: 0,
      remaining: 0,
      effectiveCount: baseline,
    }
  }

  return {
    allowed: true,
    primaryCost: Math.max(1, effectiveCount - primaryCount),
    remaining: Math.max(0, limit - effectiveCount),
    effectiveCount,
  }
}

export function remainingLinkedMonthlyQuota(input: { primaryCount: number; linkedCount?: number; limit: number }) {
  const limit = Math.max(1, Math.floor(input.limit))
  const used = Math.max(normalizeCount(input.primaryCount), normalizeCount(input.linkedCount ?? 0))
  return Math.max(0, limit - used)
}

function normalizeCount(value: number) {
  if (!Number.isFinite(value) || value <= 0) return 0
  return Math.floor(value)
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
