import "server-only"

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto"

export type GitHubSession = {
  token: string
  id: number
  login: string
  name?: string
  avatarUrl?: string
  scopes: string[]
  createdAt: string
}

export type PublicGitHubSession = {
  authenticated: boolean
  id?: number
  login?: string
  name?: string
  avatarUrl?: string
  scopes?: string[]
}

type HeaderSource = {
  get(name: string): string | null
}

const GITHUB_SESSION_COOKIE = "vibeshield_gh_session"
const OAUTH_STATE_COOKIE = "vibeshield_gh_state"
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30
const STATE_MAX_AGE_SECONDS = 60 * 10

export function createGitHubOAuthState() {
  return base64Url(randomBytes(24))
}

export function createGitHubOAuthStateCookie(state: string) {
  return serializeCookie(OAUTH_STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(),
    path: "/",
    maxAge: STATE_MAX_AGE_SECONDS,
  })
}

export function readGitHubOAuthState(headers: HeaderSource) {
  return getCookie(headers, OAUTH_STATE_COOKIE)
}

export function clearGitHubOAuthStateCookie() {
  return serializeCookie(OAUTH_STATE_COOKIE, "", {
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(),
    path: "/",
    maxAge: 0,
  })
}

export function createGitHubSessionCookie(session: GitHubSession) {
  return serializeCookie(GITHUB_SESSION_COOKIE, encryptJson(session), {
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(),
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  })
}

export function clearGitHubSessionCookie() {
  return serializeCookie(GITHUB_SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "Lax",
    secure: shouldUseSecureCookies(),
    path: "/",
    maxAge: 0,
  })
}

export function getGitHubSessionFromHeaders(headers: HeaderSource): GitHubSession | null {
  const value = getCookie(headers, GITHUB_SESSION_COOKIE)
  if (!value) return null

  try {
    const session = decryptJson(value) as Partial<GitHubSession>
    if (!isGitHubSession(session)) return null

    const createdAt = Date.parse(session.createdAt)
    if (!Number.isFinite(createdAt)) return null
    if (Date.now() - createdAt > SESSION_MAX_AGE_SECONDS * 1000) return null

    return session
  } catch {
    return null
  }
}

export function publicGitHubSession(session: GitHubSession | null): PublicGitHubSession {
  if (!session) return { authenticated: false }

  return {
    authenticated: true,
    id: session.id,
    login: session.login,
    name: session.name,
    avatarUrl: session.avatarUrl,
    scopes: session.scopes,
  }
}

export function hasGitHubSessionSecret() {
  return Boolean(readSessionSecret(false))
}

function encryptJson(value: GitHubSession) {
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", sessionKey(), iv)
  const plaintext = Buffer.from(JSON.stringify(value), "utf8")
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return ["v1", base64Url(iv), base64Url(encrypted), base64Url(tag)].join(".")
}

function decryptJson(value: string) {
  const [version, rawIv, rawEncrypted, rawTag] = value.split(".")
  if (version !== "v1" || !rawIv || !rawEncrypted || !rawTag) {
    throw new Error("Unsupported GitHub session cookie.")
  }

  const iv = fromBase64Url(rawIv)
  const encrypted = fromBase64Url(rawEncrypted)
  const tag = fromBase64Url(rawTag)
  const decipher = createDecipheriv("aes-256-gcm", sessionKey(), iv)
  decipher.setAuthTag(tag)

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
  return JSON.parse(decrypted.toString("utf8")) as unknown
}

function sessionKey() {
  const secret = readSessionSecret(true)
  return createHash("sha256").update(secret).digest()
}

function readSessionSecret(required: true): string
function readSessionSecret(required: false): string | null
function readSessionSecret(required: boolean) {
  const configured =
    process.env.VIBESHIELD_GITHUB_SESSION_SECRET ||
    process.env.VIBESHIELD_IDENTITY_SALT ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SECRET_KEY

  if (configured) return configured
  if (process.env.NODE_ENV !== "production") return "vibeshield-local-development"
  if (required) throw new Error("VIBESHIELD_GITHUB_SESSION_SECRET is required in production.")
  return null
}

function isGitHubSession(value: Partial<GitHubSession>): value is GitHubSession {
  return Boolean(
    value &&
      typeof value.token === "string" &&
      value.token.length >= 20 &&
      typeof value.id === "number" &&
      Number.isFinite(value.id) &&
      typeof value.login === "string" &&
      value.login.length > 0 &&
      typeof value.createdAt === "string" &&
      Array.isArray(value.scopes),
  )
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

function serializeCookie(
  name: string,
  value: string,
  options: {
    httpOnly: boolean
    sameSite: "Lax" | "Strict"
    secure: boolean
    path: string
    maxAge: number
  },
) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${options.path}`,
    `Max-Age=${options.maxAge}`,
    `SameSite=${options.sameSite}`,
  ]

  if (options.httpOnly) parts.push("HttpOnly")
  if (options.secure) parts.push("Secure")

  return parts.join("; ")
}

function shouldUseSecureCookies() {
  return process.env.NODE_ENV === "production" || Boolean(process.env.VERCEL)
}

function base64Url(value: Buffer) {
  return value.toString("base64url")
}

function fromBase64Url(value: string) {
  return Buffer.from(value, "base64url")
}
