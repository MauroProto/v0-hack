import { NextResponse } from "next/server"
import {
  clearGitHubOAuthStateCookie,
  clearGitHubOAuthReturnCookie,
  createGitHubSessionCookie,
  readGitHubOAuthState,
  readGitHubOAuthReturn,
  type GitHubSession,
} from "@/lib/security/github-session"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

type GitHubTokenResponse = {
  access_token?: string
  token_type?: string
  scope?: string
  error?: string
  error_description?: string
}

type GitHubUserResponse = {
  id?: number
  login?: string
  name?: string | null
  avatar_url?: string | null
}

export async function GET(request: Request) {
  const url = new URL(request.url)
  const code = url.searchParams.get("code")
  const state = url.searchParams.get("state")
  const expectedState = readGitHubOAuthState(request.headers)
  const redirectTo = new URL(readGitHubOAuthReturn(request.headers), url.origin)

  if (!code || !state || !expectedState || state !== expectedState) {
    redirectTo.searchParams.set("authError", "github_state")
    return redirectWithClearedState(redirectTo)
  }

  try {
    const token = await exchangeCodeForToken(code, request)
    const user = await fetchGitHubUser(token.accessToken)
    const session: GitHubSession = {
      token: token.accessToken,
      id: user.id,
      login: user.login,
      name: user.name || user.login,
      avatarUrl: user.avatarUrl,
      scopes: token.scopes,
      createdAt: new Date().toISOString(),
    }

    const response = NextResponse.redirect(redirectTo)
    response.headers.append("Set-Cookie", createGitHubSessionCookie(session))
    response.headers.append("Set-Cookie", clearGitHubOAuthStateCookie())
    response.headers.append("Set-Cookie", clearGitHubOAuthReturnCookie())
    return response
  } catch {
    redirectTo.searchParams.set("authError", "github_oauth")
    return redirectWithClearedState(redirectTo)
  }
}

async function exchangeCodeForToken(code: string, request: Request) {
  const clientId = process.env.GITHUB_CLIENT_ID
  const clientSecret = process.env.GITHUB_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    throw new Error("GitHub OAuth is not configured.")
  }

  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "VibeShield",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: process.env.GITHUB_REDIRECT_URI || `${new URL(request.url).origin}/api/auth/github/callback`,
    }),
    cache: "no-store",
  })

  if (!response.ok) throw new Error("GitHub OAuth token exchange failed.")
  const data = (await response.json()) as GitHubTokenResponse
  if (!data.access_token || data.error) {
    throw new Error(data.error_description || data.error || "GitHub OAuth token exchange failed.")
  }

  return {
    accessToken: data.access_token,
    scopes: (data.scope ?? "").split(",").map((scope) => scope.trim()).filter(Boolean),
  }
}

async function fetchGitHubUser(token: string) {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "VibeShield",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    cache: "no-store",
  })

  if (!response.ok) throw new Error("GitHub user lookup failed.")
  const data = (await response.json()) as GitHubUserResponse
  if (!data.id || !data.login) throw new Error("GitHub user lookup failed.")

  return {
    id: data.id,
    login: data.login,
    name: data.name ?? undefined,
    avatarUrl: data.avatar_url ?? undefined,
  }
}

function redirectWithClearedState(url: URL) {
  const response = NextResponse.redirect(url)
  response.headers.append("Set-Cookie", clearGitHubOAuthStateCookie())
  response.headers.append("Set-Cookie", clearGitHubOAuthReturnCookie())
  return response
}
