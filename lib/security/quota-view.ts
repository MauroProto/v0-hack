export type PublicQuotaState = {
  limit: number
  remaining: number
  resetAt: string
  period: "monthly"
}

export type QuotaDisplay = {
  known: boolean
  limit: number
  remaining: number
  used: number
  percentRemaining: number
  label: string
  resetLabel: string
  tone: "ok" | "low" | "empty" | "unknown"
}

export function normalizePublicQuota(value: unknown): PublicQuotaState | null {
  if (!value || typeof value !== "object") return null

  const quota = value as Record<string, unknown>
  if (quota.period !== "monthly") return null

  const limit = numberValue(quota.limit)
  const remaining = numberValue(quota.remaining)
  const resetAt = typeof quota.resetAt === "string" ? quota.resetAt : null

  if (!limit || remaining === null || !resetAt) return null

  return {
    limit,
    remaining,
    resetAt,
    period: "monthly",
  }
}

export function deriveQuotaDisplay(quota: PublicQuotaState | null | undefined, fallbackLimit = 10): QuotaDisplay {
  if (!quota) {
    const limit = Math.max(1, Math.floor(fallbackLimit))
    return {
      known: false,
      limit,
      remaining: limit,
      used: 0,
      percentRemaining: 100,
      label: `-- / ${limit} left`,
      resetLabel: "Loading quota",
      tone: "unknown",
    }
  }

  const limit = Math.max(1, Math.floor(quota.limit))
  const remaining = clamp(Math.floor(quota.remaining), 0, limit)
  const used = Math.max(0, limit - remaining)
  const percentRemaining = Math.round((remaining / limit) * 100)

  return {
    known: true,
    limit,
    remaining,
    used,
    percentRemaining,
    label: `${remaining} / ${limit} left`,
    resetLabel: formatResetLabel(quota.resetAt),
    tone: remaining === 0 ? "empty" : percentRemaining <= 25 ? "low" : "ok",
  }
}

function numberValue(value: unknown) {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN
  if (!Number.isFinite(number)) return null
  return Math.floor(number)
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}

function formatResetLabel(resetAt: string) {
  const date = new Date(resetAt)
  if (!Number.isFinite(date.getTime())) return "Resets monthly"

  const label = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(date)

  return `Resets ${label} UTC`
}
