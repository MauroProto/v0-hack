import "server-only"

import { auth, clerkClient } from "@clerk/nextjs/server"
import type { GitHubSession } from "@/lib/security/github-session"

type ClerkGitHubAccessToken = {
  token: string
  scopes: string[]
}

type GitHubUserApi = {
  id?: number
  login?: string
  name?: string | null
  avatar_url?: string | null
}

export async function getClerkGitHubAccessToken(): Promise<ClerkGitHubAccessToken | null> {
  try {
    const { userId } = await auth()
    if (!userId) return null

    const client = await clerkClient()
    const response = await client.users.getUserOauthAccessToken(userId, "github")
    const accessToken = response.data.find((token) => typeof token.token === "string" && token.token.length > 0)

    if (!accessToken) return null

    return {
      token: accessToken.token,
      scopes: normalizeScopes(accessToken.scopes),
    }
  } catch {
    return null
  }
}

export async function getClerkGitHubSession(): Promise<GitHubSession | null> {
  const accessToken = await getClerkGitHubAccessToken()
  if (!accessToken) return null

  try {
    const response = await fetch("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${accessToken.token}`,
        "User-Agent": "Badger",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      cache: "no-store",
    })

    if (!response.ok) return null

    const user = (await response.json()) as GitHubUserApi
    if (!isFiniteNumber(user.id) || !user.login) return null

    return {
      token: accessToken.token,
      id: user.id,
      login: user.login,
      name: user.name ?? undefined,
      avatarUrl: user.avatar_url ?? undefined,
      scopes: normalizeScopes([
        ...accessToken.scopes,
        ...parseGitHubScopeHeader(response.headers.get("x-oauth-scopes")),
      ]),
      createdAt: new Date().toISOString(),
    }
  } catch {
    return null
  }
}

function parseGitHubScopeHeader(value: string | null) {
  if (!value) return []
  return value
    .split(",")
    .map((scope) => scope.trim())
    .filter(Boolean)
}

function normalizeScopes(scopes: readonly string[] | undefined) {
  return [...new Set((scopes ?? []).map((scope) => scope.trim()).filter(Boolean))]
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value)
}
