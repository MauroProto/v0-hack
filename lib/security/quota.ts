import "server-only"

import { getSupabaseServiceClient } from "@/lib/supabase/server"
import type { RequestIdentity } from "./request"

type Counter = {
  count: number
  resetAt: number
}

type SecurityGlobal = typeof globalThis & {
  __vibeshieldBurstCounters?: Map<string, Counter>
  __vibeshieldMonthlyCounters?: Map<string, Counter>
}

export type QuotaState = {
  limit: number
  remaining: number
  resetAt: string
  period: "monthly"
}

type RateLimitHeaderState = {
  limit: number
  remaining: number
  resetAt: string
  period?: "monthly" | "burst"
}

type QuotaRpcRow = {
  allowed: boolean
  remaining: number
  scan_count: number
}

const securityGlobal = globalThis as SecurityGlobal

export class SecurityError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly headers: Record<string, string> = {},
  ) {
    super(message)
  }
}

export async function assertBurstAllowed(identity: RequestIdentity, action: "scan" | "explain" | "pull_request") {
  if (localRateLimitsDisabled()) return

  const limit = readPositiveInt(
    action === "scan"
      ? process.env.VIBESHIELD_SCAN_BURST_LIMIT
      : action === "pull_request"
        ? process.env.VIBESHIELD_PULL_REQUEST_BURST_LIMIT
        : process.env.VIBESHIELD_EXPLAIN_BURST_LIMIT,
    action === "scan" ? 6 : action === "pull_request" ? 3 : 10,
  )
  const windowSeconds = readPositiveInt(process.env.VIBESHIELD_BURST_WINDOW_SECONDS, 60)
  const resetAt = Date.now() + windowSeconds * 1000
  const key = `${action}:${identity.subjectHash}`
  const result = consumeMemoryCounter(getBurstCounters(), key, limit, resetAt)

  if (!result.allowed) {
    throw new SecurityError(
      "Too many requests. Wait a minute and try again.",
      429,
      "burst_rate_limited",
      rateLimitHeaders({
        limit,
        remaining: 0,
        resetAt: new Date(result.resetAt).toISOString(),
        period: "burst",
      }),
    )
  }
}

export async function consumeMonthlyScanQuota(identity: RequestIdentity): Promise<QuotaState> {
  const limit = readPositiveInt(process.env.VIBESHIELD_MONTHLY_SCAN_QUOTA, 20)
  const windowStart = getUtcMonthStart()
  const resetAt = getNextUtcMonthStart()

  if (localRateLimitsDisabled()) {
    return {
      limit,
      remaining: limit,
      resetAt: resetAt.toISOString(),
      period: "monthly",
    }
  }

  const supabase = getSupabaseServiceClient()

  if (!supabase && persistentQuotaRequired()) {
    throw persistentQuotaUnavailable()
  }

  if (supabase) {
    const { data, error } = await supabase.rpc("vibeshield_consume_scan_quota", {
      p_subject_hash: identity.subjectHash,
      p_window_start: windowStart,
      p_limit: limit,
    })

    if (!error) {
      const row = (Array.isArray(data) ? data[0] : data) as QuotaRpcRow | null
      if (row?.allowed) {
        return {
          limit,
          remaining: Math.max(0, Number(row.remaining) || 0),
          resetAt: resetAt.toISOString(),
          period: "monthly",
        }
      }

      throw quotaExceeded(limit, resetAt)
    }

    console.error("VibeShield Supabase quota failed", error.message)
    if (persistentQuotaRequired()) throw persistentQuotaUnavailable()
  }

  const result = consumeMemoryCounter(getMonthlyCounters(), `monthly:${windowStart}:${identity.subjectHash}`, limit, resetAt.getTime())
  if (!result.allowed) throw quotaExceeded(limit, resetAt)

  return {
    limit,
    remaining: result.remaining,
    resetAt: new Date(result.resetAt).toISOString(),
    period: "monthly",
  }
}

export function assertContentLengthAllowed(request: Request, maxBytes: number) {
  const rawLength = request.headers.get("content-length")
  if (!rawLength) return

  const contentLength = Number(rawLength)
  if (!Number.isFinite(contentLength) || contentLength < 0) {
    throw new SecurityError("Invalid Content-Length header.", 400, "invalid_content_length")
  }

  if (contentLength > maxBytes) {
    throw new SecurityError(`Request is too large. Maximum is ${maxBytes} bytes.`, 413, "request_too_large")
  }
}

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError
}

export function rateLimitHeaders(quota: RateLimitHeaderState) {
  return {
    "X-RateLimit-Limit": String(quota.limit),
    "X-RateLimit-Remaining": String(quota.remaining),
    "X-RateLimit-Reset": quota.resetAt,
    ...(quota.period ? { "X-RateLimit-Period": quota.period } : {}),
  }
}

function quotaExceeded(limit: number, resetAt: Date) {
  return new SecurityError(
    "Monthly scan quota reached. VibeShield allows 20 scans per user per UTC month.",
    429,
    "monthly_quota_reached",
    rateLimitHeaders({
      limit,
      remaining: 0,
      resetAt: resetAt.toISOString(),
      period: "monthly",
    }),
  )
}

function persistentQuotaRequired() {
  const value = process.env.VIBESHIELD_REQUIRE_PERSISTENT_QUOTA?.trim().toLowerCase()
  if (value === "true") return true
  if (value === "false") return false
  return process.env.NODE_ENV === "production"
}

function persistentQuotaUnavailable() {
  return new SecurityError(
    "Persistent monthly scan quota is not configured. Connect Supabase and run the migration before accepting production scans.",
    503,
    "persistent_quota_unavailable",
  )
}

function localRateLimitsDisabled() {
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") return false

  const value = process.env.VIBESHIELD_DISABLE_LOCAL_RATE_LIMITS?.trim().toLowerCase()
  if (value === "true") return true
  if (value === "false") return false

  return true
}

function consumeMemoryCounter(counters: Map<string, Counter>, key: string, limit: number, resetAt: number) {
  const now = Date.now()
  const current = counters.get(key)
  const next = !current || current.resetAt <= now ? { count: 0, resetAt } : current

  if (next.count >= limit) {
    counters.set(key, next)
    return { allowed: false, remaining: 0, resetAt: next.resetAt }
  }

  next.count += 1
  counters.set(key, next)
  return { allowed: true, remaining: Math.max(0, limit - next.count), resetAt: next.resetAt }
}

function getBurstCounters() {
  securityGlobal.__vibeshieldBurstCounters ??= new Map<string, Counter>()
  return securityGlobal.__vibeshieldBurstCounters
}

function getMonthlyCounters() {
  securityGlobal.__vibeshieldMonthlyCounters ??= new Map<string, Counter>()
  return securityGlobal.__vibeshieldMonthlyCounters
}

function getUtcMonthStart() {
  const now = new Date()
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-01`
}

function getNextUtcMonthStart() {
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1))
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
