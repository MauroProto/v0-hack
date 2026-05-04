import "server-only"

import { badgerEnv } from "@/lib/config/env"
import { BADGER_SUPABASE_BURST_RPC, BADGER_SUPABASE_QUOTA_RPC, BADGER_SUPABASE_TABLES } from "@/lib/supabase/schema"
import { getSupabaseServiceClient } from "@/lib/supabase/server"
import type { RequestIdentity } from "./request"
import { SecurityError } from "./errors"
import {
  monthlyQuotaLinkedSubject,
  monthlyQuotaPrimarySubject,
  monthlyScanQuotaLimit,
  planLinkedMonthlyQuotaConsumption,
  remainingLinkedMonthlyQuota,
} from "./quotaPolicy"
export { scanCreditCostForMode, type ScanCreditMode } from "./scanCredits"
export { SecurityError, isSecurityError } from "./errors"

type Counter = {
  count: number
  resetAt: number
}

type SecurityGlobal = typeof globalThis & {
  __badgerBurstCounters?: Map<string, Counter>
  __badgerMonthlyCounters?: Map<string, Counter>
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

type BurstRpcRow = {
  allowed: boolean
  remaining: number
  request_count: number
}

type QuotaUsageRow = {
  subject_hash?: string | null
  scan_count: number | string | null
}

type SupabaseServiceClient = NonNullable<ReturnType<typeof getSupabaseServiceClient>>

const securityGlobal = globalThis as SecurityGlobal
const MAX_SCAN_CREDIT_COST = 10

export async function assertBurstAllowed(identity: RequestIdentity, action: "scan" | "explain" | "pull_request") {
  if (localRateLimitsDisabled()) return

  const limit = readPositiveInt(
    action === "scan"
      ? badgerEnv("SCAN_BURST_LIMIT")
      : action === "pull_request"
        ? badgerEnv("PULL_REQUEST_BURST_LIMIT")
        : badgerEnv("EXPLAIN_BURST_LIMIT"),
    action === "scan" ? 6 : action === "pull_request" ? 3 : 10,
  )
  const windowSeconds = readPositiveInt(badgerEnv("BURST_WINDOW_SECONDS"), 60)
  const windowStart = getBurstWindowStart(windowSeconds)
  const resetAt = windowStart.getTime() + windowSeconds * 1000
  const subjectHash = identity.rateLimitSubjectHash || identity.subjectHash
  const key = `${action}:${subjectHash}`

  const supabase = getSupabaseServiceClient()
  if (supabase) {
    const { data, error } = await supabase.rpc(BADGER_SUPABASE_BURST_RPC, {
      p_subject_hash: subjectHash,
      p_action: action,
      p_window_start: windowStart.toISOString(),
      p_limit: limit,
      p_cost: 1,
    })

    if (!error) {
      const row = (Array.isArray(data) ? data[0] : data) as BurstRpcRow | null
      if (row?.allowed) return
      throw burstRateLimited(limit, resetAt)
    }

    console.error("Badger Supabase burst limit failed", error.message)
    if (distributedBurstRequired()) throw distributedBurstUnavailable()
  } else if (distributedBurstRequired()) {
    throw distributedBurstUnavailable()
  }

  const result = consumeMemoryCounter(getBurstCounters(), key, limit, resetAt)

  if (!result.allowed) {
    throw burstRateLimited(limit, result.resetAt)
  }
}

export async function consumeMonthlyScanQuota(identity: RequestIdentity, credits = 1): Promise<QuotaState> {
  const limit = monthlyScanQuotaLimit(identity)
  const cost = normalizeCreditCost(credits)
  const windowStart = getUtcMonthStart()
  const resetAt = getNextUtcMonthStart()
  const subjectHash = monthlyQuotaPrimarySubject(identity)
  const linkedSubjectHash = monthlyQuotaLinkedSubject(identity)
  const memoryKey = monthlyCounterKey(windowStart, subjectHash)
  const linkedMemoryKey = linkedSubjectHash ? monthlyCounterKey(windowStart, linkedSubjectHash) : null

  if (localRateLimitsDisabled()) {
    const result = consumeLinkedMemoryCounter(getMonthlyCounters(), memoryKey, linkedMemoryKey, limit, resetAt.getTime(), cost)
    return {
      limit,
      remaining: result.remaining,
      resetAt: new Date(result.resetAt).toISOString(),
      period: "monthly",
    }
  }

  const supabase = getSupabaseServiceClient()

  if (!supabase && persistentQuotaRequired()) {
    throw persistentQuotaUnavailable()
  }

  if (supabase) {
    const usage = await readPersistentQuotaUsage(supabase, subjectHash, linkedSubjectHash, windowStart)
    if (usage.error) {
      console.error("Badger Supabase quota read failed", usage.error)
      if (persistentQuotaRequired()) throw persistentQuotaUnavailable()
    } else {
      const plan = planLinkedMonthlyQuotaConsumption({
        primaryCount: usage.primaryCount,
        linkedCount: usage.linkedCount,
        limit,
        requestCost: cost,
      })

      if (!plan.allowed) throw quotaExceeded(limit, resetAt)

      const { data, error } = await supabase.rpc(
        BADGER_SUPABASE_QUOTA_RPC,
        quotaRpcArgs({
          subjectHash,
          windowStart,
          limit,
          cost: plan.primaryCost,
        }),
      )

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

      console.error("Badger Supabase quota failed", error.message)
      if (persistentQuotaRequired()) throw persistentQuotaUnavailable()
    }
  }

  const result = consumeLinkedMemoryCounter(getMonthlyCounters(), memoryKey, linkedMemoryKey, limit, resetAt.getTime(), cost)
  if (!result.allowed) throw quotaExceeded(limit, resetAt)

  return {
    limit,
    remaining: result.remaining,
    resetAt: new Date(result.resetAt).toISOString(),
    period: "monthly",
  }
}

export async function peekMonthlyScanQuota(identity: RequestIdentity): Promise<QuotaState> {
  const limit = monthlyScanQuotaLimit(identity)
  const windowStart = getUtcMonthStart()
  const resetAt = getNextUtcMonthStart()
  const subjectHash = monthlyQuotaPrimarySubject(identity)
  const linkedSubjectHash = monthlyQuotaLinkedSubject(identity)
  const memoryKey = monthlyCounterKey(windowStart, subjectHash)
  const linkedMemoryKey = linkedSubjectHash ? monthlyCounterKey(windowStart, linkedSubjectHash) : null

  if (localRateLimitsDisabled()) {
    const result = peekLinkedMemoryCounter(getMonthlyCounters(), memoryKey, linkedMemoryKey, limit, resetAt.getTime())
    return {
      limit,
      remaining: result.remaining,
      resetAt: new Date(result.resetAt).toISOString(),
      period: "monthly",
    }
  }

  const supabase = getSupabaseServiceClient()

  if (!supabase && persistentQuotaRequired()) {
    throw persistentQuotaUnavailable()
  }

  if (supabase) {
    const usage = await readPersistentQuotaUsage(supabase, subjectHash, linkedSubjectHash, windowStart)
    if (!usage.error) {
      return {
        limit,
        remaining: remainingLinkedMonthlyQuota({
          primaryCount: usage.primaryCount,
          linkedCount: usage.linkedCount,
          limit,
        }),
        resetAt: resetAt.toISOString(),
        period: "monthly",
      }
    }

    console.error("Badger Supabase quota read failed", usage.error)
    if (persistentQuotaRequired()) throw persistentQuotaUnavailable()
  }

  const result = peekLinkedMemoryCounter(getMonthlyCounters(), memoryKey, linkedMemoryKey, limit, resetAt.getTime())
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
    `Monthly scan credit quota reached. Badger allows ${limit} credits per user per UTC month.`,
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
  const value = badgerEnv("REQUIRE_PERSISTENT_QUOTA")?.toLowerCase()
  if (value === "true") return true
  if (value === "false") return false
  return process.env.NODE_ENV === "production"
}

function distributedBurstRequired() {
  const value = badgerEnv("REQUIRE_DISTRIBUTED_BURST_LIMIT")?.toLowerCase()
  if (value === "true") return true
  if (value === "false") return false
  return process.env.NODE_ENV === "production"
}

function persistentQuotaUnavailable() {
  return new SecurityError(
    "Persistent monthly scan credits are not configured. Connect Supabase and run the latest migration before accepting production scans.",
    503,
    "persistent_quota_unavailable",
  )
}

function distributedBurstUnavailable() {
  return new SecurityError(
    "Persistent burst rate limits are not configured. Connect Supabase and run the latest migration before accepting production requests.",
    503,
    "persistent_burst_unavailable",
  )
}

function burstRateLimited(limit: number, resetAt: number) {
  return new SecurityError(
    "Too many requests. Wait a minute and try again.",
    429,
    "burst_rate_limited",
    rateLimitHeaders({
      limit,
      remaining: 0,
      resetAt: new Date(resetAt).toISOString(),
      period: "burst",
    }),
  )
}

function localRateLimitsDisabled() {
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") return false

  const value = badgerEnv("DISABLE_LOCAL_RATE_LIMITS")?.toLowerCase()
  if (value === "true") return true
  if (value === "false") return false

  return true
}

function consumeMemoryCounter(counters: Map<string, Counter>, key: string, limit: number, resetAt: number, amount = 1) {
  const now = Date.now()
  const cost = normalizeCreditCost(amount)
  const current = counters.get(key)
  const next = !current || current.resetAt <= now ? { count: 0, resetAt } : current

  if (next.count + cost > limit) {
    counters.set(key, next)
    return { allowed: false, remaining: 0, resetAt: next.resetAt }
  }

  next.count += cost
  counters.set(key, next)
  return { allowed: true, remaining: Math.max(0, limit - next.count), resetAt: next.resetAt }
}

function consumeLinkedMemoryCounter(
  counters: Map<string, Counter>,
  primaryKey: string,
  linkedKey: string | null,
  limit: number,
  resetAt: number,
  amount = 1,
) {
  const primaryCount = readMemoryCounter(counters, primaryKey)
  const linkedCount = linkedKey ? readMemoryCounter(counters, linkedKey) : 0
  const plan = planLinkedMonthlyQuotaConsumption({
    primaryCount,
    linkedCount,
    limit,
    requestCost: normalizeCreditCost(amount),
  })

  if (!plan.allowed) {
    ensureMemoryCounter(counters, primaryKey, primaryCount, resetAt)
    return { allowed: false, remaining: 0, resetAt }
  }

  counters.set(primaryKey, {
    count: primaryCount + plan.primaryCost,
    resetAt,
  })
  return {
    allowed: true,
    remaining: plan.remaining,
    resetAt,
  }
}

function peekLinkedMemoryCounter(counters: Map<string, Counter>, primaryKey: string, linkedKey: string | null, limit: number, resetAt: number) {
  return {
    remaining: remainingLinkedMonthlyQuota({
      primaryCount: readMemoryCounter(counters, primaryKey),
      linkedCount: linkedKey ? readMemoryCounter(counters, linkedKey) : 0,
      limit,
    }),
    resetAt,
  }
}

function readMemoryCounter(counters: Map<string, Counter>, key: string) {
  const current = counters.get(key)
  if (!current || current.resetAt <= Date.now()) return 0
  return current.count
}

function ensureMemoryCounter(counters: Map<string, Counter>, key: string, count: number, resetAt: number) {
  const current = counters.get(key)
  if (!current || current.resetAt <= Date.now()) {
    counters.set(key, { count, resetAt })
  }
}

async function readPersistentQuotaUsage(
  supabase: SupabaseServiceClient,
  subjectHash: string,
  linkedSubjectHash: string | null,
  windowStart: string,
): Promise<{ primaryCount: number; linkedCount: number; error?: string }> {
  const subjects = linkedSubjectHash ? [subjectHash, linkedSubjectHash] : [subjectHash]
  const { data, error } = await supabase
    .from(BADGER_SUPABASE_TABLES.usage)
    .select("subject_hash, scan_count")
    .eq("window_start", windowStart)
    .in("subject_hash", subjects)

  if (error) return { primaryCount: 0, linkedCount: 0, error: error.message }

  let primaryCount = 0
  let linkedCount = 0
  for (const row of (data ?? []) as QuotaUsageRow[]) {
    const scanCount = Math.max(0, Number(row.scan_count ?? 0) || 0)
    if (row.subject_hash === subjectHash) primaryCount = scanCount
    if (linkedSubjectHash && row.subject_hash === linkedSubjectHash) linkedCount = scanCount
  }

  return { primaryCount, linkedCount }
}

function getBurstCounters() {
  securityGlobal.__badgerBurstCounters ??= new Map<string, Counter>()
  return securityGlobal.__badgerBurstCounters
}

function getMonthlyCounters() {
  securityGlobal.__badgerMonthlyCounters ??= new Map<string, Counter>()
  return securityGlobal.__badgerMonthlyCounters
}

function getUtcMonthStart() {
  const now = new Date()
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-01`
}

function getNextUtcMonthStart() {
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1))
}

function monthlyCounterKey(windowStart: string, subjectHash: string) {
  return `monthly:${windowStart}:${subjectHash}`
}

function getBurstWindowStart(windowSeconds: number) {
  const windowMs = Math.max(1, windowSeconds) * 1000
  return new Date(Math.floor(Date.now() / windowMs) * windowMs)
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}

function quotaRpcArgs(input: { subjectHash: string; windowStart: string; limit: number; cost: number }) {
  const baseArgs = {
    p_subject_hash: input.subjectHash,
    p_window_start: input.windowStart,
    p_limit: input.limit,
  }

  // The original production migration supports one-credit operations with the
  // three-argument RPC. Only multi-credit scans require the newer p_cost
  // migration. This keeps Generate fixes and Normal scans working on older
  // Supabase projects while Max scans still fail closed until the latest
  // migration is applied.
  if (input.cost === 1) return baseArgs

  return {
    ...baseArgs,
    p_cost: input.cost,
  }
}

function normalizeCreditCost(value: number) {
  if (!Number.isFinite(value) || value <= 0) return 1
  return Math.min(Math.floor(value), MAX_SCAN_CREDIT_COST)
}
