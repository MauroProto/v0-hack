import { NextResponse } from "next/server"
import { z } from "zod"
import { apiHeaders } from "@/lib/security/headers"
import { getClerkGitHubSession } from "@/lib/security/clerk-github"
import { clearGitHubSessionCookie, getGitHubSessionFromHeaders, publicGitHubSession } from "@/lib/security/github-session"
import { assertSameOriginRequest } from "@/lib/security/origin"
import { isSecurityError } from "@/lib/security/quota"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

const DisconnectBodySchema = z.object({
  disconnect: z.boolean().optional(),
})

export async function GET(request: Request) {
  const legacySession = getGitHubSessionFromHeaders(request.headers)
  if (legacySession) {
    return NextResponse.json(
      { session: { ...publicGitHubSession(legacySession), source: "legacy" } },
      { headers: apiHeaders() },
    )
  }

  const clerkSession = await getClerkGitHubSession()
  return NextResponse.json(
    { session: { ...publicGitHubSession(clerkSession), source: clerkSession ? "clerk" : undefined } },
    { headers: apiHeaders() },
  )
}

export async function DELETE(request: Request) {
  try {
    assertSameOriginRequest(request)
    const disconnect = await shouldDisconnectGitHub(request)

    if (disconnect) {
      const session = getGitHubSessionFromHeaders(request.headers)
      if (session) {
        try {
          await deleteGitHubAppAuthorization(session.token)
        } catch {
          return NextResponse.json(
            {
              error:
                "Could not disconnect GitHub from this account. Try again, or remove the app from GitHub Authorized OAuth Apps.",
            },
            { status: 502, headers: apiHeaders() },
          )
        }
      }
    }

    return NextResponse.json(
      { session: { authenticated: false }, disconnected: disconnect },
      {
        headers: apiHeaders({
          "Set-Cookie": clearGitHubSessionCookie(),
        }),
      },
    )
  } catch (error) {
    if (isSecurityError(error)) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: error.status, headers: apiHeaders(error.headers) })
    }

    return NextResponse.json({ error: "Could not clear the GitHub session." }, { status: 500, headers: apiHeaders() })
  }
}

async function shouldDisconnectGitHub(request: Request) {
  const url = new URL(request.url)
  if (url.searchParams.get("disconnect") === "1") return true

  if (!request.headers.get("content-type")?.includes("application/json")) return false

  try {
    const body = DisconnectBodySchema.parse(await request.json())
    return body.disconnect === true
  } catch {
    return false
  }
}

async function deleteGitHubAppAuthorization(accessToken: string) {
  const clientId = process.env.GITHUB_CLIENT_ID
  const clientSecret = process.env.GITHUB_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    throw new Error("GitHub OAuth is not configured.")
  }

  const response = await fetch(`https://api.github.com/applications/${encodeURIComponent(clientId)}/grant`, {
    method: "DELETE",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64")}`,
      "Content-Type": "application/json",
      "User-Agent": "Badger",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({ access_token: accessToken }),
    cache: "no-store",
  })

  if (response.status === 204) return

  throw new Error("GitHub authorization revoke failed.")
}
