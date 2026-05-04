import { createHash, randomBytes } from "node:crypto"
import { badgerEnv } from "@/lib/config/env"

export type AnonymousGuestIdentity = {
  subjectHash: string
  quotaSubjectHash: string
  rateLimitSubjectHash: string
  setCookie?: string
}

type HeaderSource = {
  get(name: string): string | null
}

const GUEST_COOKIE = "badger_guest_id"
const GUEST_MAX_AGE_SECONDS = 60 * 60 * 24 * 90

export function ensureAnonymousGuestIdentity(headers: HeaderSource, rateLimitSubjectHash: string): AnonymousGuestIdentity {
  const existing = readAnonymousGuestId(headers)
  const guestId = existing ?? randomBytes(18).toString("base64url")
  const subjectHash = hashSubject(`anonymous_guest:${guestId}`)

  return {
    subjectHash,
    quotaSubjectHash: subjectHash,
    rateLimitSubjectHash,
    ...(existing ? {} : { setCookie: createAnonymousGuestCookie(guestId) }),
  }
}

export function anonymousGuestResponseHeaders(identity: { setCookie?: string }): Record<string, string> {
  return identity.setCookie ? { "Set-Cookie": identity.setCookie } : {}
}

function readAnonymousGuestId(headers: HeaderSource) {
  const raw = getCookie(headers, GUEST_COOKIE)
  if (!raw) return null
  return /^[A-Za-z0-9_-]{20,80}$/.test(raw) ? raw : null
}

function createAnonymousGuestCookie(guestId: string) {
  const parts = [
    `${GUEST_COOKIE}=${encodeURIComponent(guestId)}`,
    "Path=/",
    `Max-Age=${GUEST_MAX_AGE_SECONDS}`,
    "SameSite=Lax",
    "HttpOnly",
  ]

  if (shouldUseSecureCookies()) parts.push("Secure")
  return parts.join("; ")
}

function getCookie(headers: HeaderSource, name: string) {
  const cookieHeader = headers.get("cookie")
  if (!cookieHeader) return null

  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=")
    if (rawName === name) return decodeURIComponent(rawValue.join("="))
  }

  return null
}

function shouldUseSecureCookies() {
  return process.env.NODE_ENV === "production" || Boolean(process.env.VERCEL)
}

function hashSubject(raw: string) {
  const salt =
    badgerEnv("IDENTITY_SALT") ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SECRET_KEY ||
    "badger-local-development"

  return createHash("sha256").update(`${salt}:${raw}`).digest("hex")
}
