import "server-only"

import { getSupabaseServiceClient } from "@/lib/supabase/server"
import type { RequestIdentity } from "./request"

type Counter = {
  count: number
  resetAt: number
}

type SecurityGlobal = typeof globalThis & {
  __vibeshieldBurstCounters?: Map<string, Counter>
  __vibeshieldDailyCounters?: Map<string, Counter>
}

export type QuotaState = {
  limit: number
  remaining: number
  resetAt: string
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

export async function assertBurstAllowed(identity: RequestIdentity, action: "scan" | "explain") {
  const limit = readPositiveInt(
    action === "scan" ? process.env.VIBESHIELD_SCAN_BURST_LIMIT : process.env.VIBESHIELD_EXPLAIN_BURST_LIMIT,
    action === "scan" ? 6 : 10,
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
      }),
    )
  }
}

export async function consumeDailyScanQuota(identity: RequestIdentity): Promise<QuotaState> {
  const limit = readPositiveInt(process.env.VIBESHIELD_DAILY_SCAN_QUOTA, 20)
  const windowStart = getUtcDay()
  const resetAt = getNextUtcDayStart()
  const supabase = getSupabaseServiceClient()

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
        }
      }

      throw quotaExceeded(limit, resetAt)
    }

    console.error("VibeShield Supabase quota failed", error.message)
    if (process.env.VIBESHIELD_REQUIRE_PERSISTENT_QUOTA === "true") {
      throw new SecurityError(
        "Scan quota is not configured. Run the Supabase migration before accepting production scans.",
        503,
        "persistent_quota_unavailable",
      )
    }
  }

  const result = consumeMemoryCounter(getDailyCounters(), `daily:${windowStart}:${identity.subjectHash}`, limit, resetAt.getTime())
  if (!result.allowed) throw quotaExceeded(limit, resetAt)

  return {
    limit,
    remaining: result.remaining,
    resetAt: new Date(result.resetAt).toISOString(),
  }
}

export function assertContentLengthAllowed(request: Request, maxBytes: number) {
  const rawLength = request.headers.get("content-length")
  if (!rawLength) return

  const contentLength = Number(rawLength)
  if (!Number.isFinite(contentLength)) {
    throw new SecurityError("Invalid Content-Length header.", 400, "invalid_content_length")
  }

  if (contentLength > maxBytes) {
    throw new SecurityError(`Request is too large. Maximum is ${maxBytes} bytes.`, 413, "request_too_large")
  }
}

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError
}

export function rateLimitHeaders(quota: QuotaState) {
  return {
    "X-RateLimit-Limit": String(quota.limit),
    "X-RateLimit-Remaining": String(quota.remaining),
    "X-RateLimit-Reset": quota.resetAt,
  }
}

function quotaExceeded(limit: number, resetAt: Date) {
  return new SecurityError(
    "Daily scan quota reached. This MVP allows 20 scans per user per UTC day.",
    429,
    "daily_quota_reached",
    rateLimitHeaders({
      limit,
      remaining: 0,
      resetAt: resetAt.toISOString(),
    }),
  )
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

function getDailyCounters() {
  securityGlobal.__vibeshieldDailyCounters ??= new Map<string, Counter>()
  return securityGlobal.__vibeshieldDailyCounters
}

function getUtcDay() {
  return new Date().toISOString().slice(0, 10)
}

function getNextUtcDayStart() {
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1))
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
