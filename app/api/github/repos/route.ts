import { NextResponse } from "next/server"
import { getGitHubTokenFromRequest, listAuthenticatedGitHubRepos } from "@/lib/utils/github"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  try {
    const token = getGitHubTokenFromRequest(request)
    if (!token) {
      return NextResponse.json({ error: "GitHub login token is required." }, { status: 401 })
    }

    const repos = await listAuthenticatedGitHubRepos(token)
    return NextResponse.json({ repos })
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not list GitHub repositories."
    return NextResponse.json({ error: message }, { status: statusForError(message) })
  }
}

function statusForError(message: string) {
  const normalized = message.toLowerCase()
  if (normalized.includes("authorization") || normalized.includes("token")) return 401
  if (normalized.includes("github")) return 502
  return 500
}
