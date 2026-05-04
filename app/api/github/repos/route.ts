import { NextResponse } from "next/server"
import { apiHeaders } from "@/lib/security/headers"
import { getGitHubTokenFromRequest, listAuthenticatedGitHubRepos } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  try {
    const token = await getGitHubTokenFromRequest(request)
    if (!token) {
      return NextResponse.json({ error: "GitHub login token is required." }, { status: 401, headers: apiHeaders() })
    }

    const repos = await listAuthenticatedGitHubRepos(token)
    return NextResponse.json({ repos }, { headers: apiHeaders() })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not list GitHub repositories."
    return NextResponse.json({ error: message }, { status: statusForError(message), headers: apiHeaders() })
  }
}

function statusForError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes("authorization") || normalized.includes("token")) return 401
  if (normalized.includes("github")) return 502
  return 500
}
