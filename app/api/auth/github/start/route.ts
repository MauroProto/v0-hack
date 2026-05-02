import { NextResponse } from "next/server"
import { apiHeaders } from "@/lib/security/headers"
import {
  createGitHubOAuthReturnCookie,
  createGitHubOAuthState,
  createGitHubOAuthStateCookie,
  hasGitHubSessionSecret,
} from "@/lib/security/github-session"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  const clientId = process.env.GITHUB_CLIENT_ID
  if (!clientId || !process.env.GITHUB_CLIENT_SECRET || !hasGitHubSessionSecret()) {
    return NextResponse.json(
      { error: "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and VIBESHIELD_GITHUB_SESSION_SECRET." },
      { status: 503, headers: apiHeaders() },
    )
  }

  const state = createGitHubOAuthState()
  const returnTo = new URL(request.url).searchParams.get("returnTo") ?? "/scan"
  const authorizeUrl = new URL("https://github.com/login/oauth/authorize")
  authorizeUrl.searchParams.set("client_id", clientId)
  authorizeUrl.searchParams.set("redirect_uri", githubRedirectUri(request))
  authorizeUrl.searchParams.set("scope", "repo read:user user:email")
  authorizeUrl.searchParams.set("state", state)
  authorizeUrl.searchParams.set("allow_signup", "true")

  const response = NextResponse.redirect(authorizeUrl)
  response.headers.append("Set-Cookie", createGitHubOAuthStateCookie(state))
  response.headers.append("Set-Cookie", createGitHubOAuthReturnCookie(returnTo))
  response.headers.set("Referrer-Policy", "no-referrer")
  response.headers.set("X-Content-Type-Options", "nosniff")
  return response
}

function githubRedirectUri(request: Request) {
  return process.env.GITHUB_REDIRECT_URI || `${new URL(request.url).origin}/api/auth/github/callback`
}
