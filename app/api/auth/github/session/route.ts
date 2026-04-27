import { NextResponse } from "next/server"
import { apiHeaders } from "@/lib/security/headers"
import { clearGitHubSessionCookie, getGitHubSessionFromHeaders, publicGitHubSession } from "@/lib/security/github-session"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  const session = getGitHubSessionFromHeaders(request.headers)
  return NextResponse.json({ session: publicGitHubSession(session) }, { headers: apiHeaders() })
}

export async function DELETE() {
  return NextResponse.json(
    { session: { authenticated: false } },
    {
      headers: apiHeaders({
        "Set-Cookie": clearGitHubSessionCookie(),
      }),
    },
  )
}
