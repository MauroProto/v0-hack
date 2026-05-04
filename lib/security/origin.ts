import { badgerEnv } from "@/lib/config/env"
import { SecurityError } from "./errors"

export function assertSameOriginRequest(request: Request) {
  const origin = request.headers.get("origin")?.trim()
  if (!origin) return

  const requestOrigin = originForUrl(request.url)
  const allowedOrigins = new Set([requestOrigin, ...configuredAllowedOrigins()].filter(Boolean))
  const normalizedOrigin = originForUrl(origin)

  if (normalizedOrigin && allowedOrigins.has(normalizedOrigin)) return

  throw new SecurityError(
    "Cross-origin state-changing requests are not allowed.",
    403,
    "cross_origin_request_blocked",
  )
}

function configuredAllowedOrigins() {
  return (badgerEnv("ALLOWED_ORIGINS") ?? "")
    .split(",")
    .map((value) => originForUrl(value.trim()))
    .filter((value): value is string => Boolean(value))
}

function originForUrl(value: string) {
  try {
    return new URL(value).origin
  } catch {
    return null
  }
}
