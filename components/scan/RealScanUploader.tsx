"use client"

import { useEffect, useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import type { Session } from "@supabase/supabase-js"
import { Icon } from "@/app/(app)/_components/icons"
import { createBrowserSupabaseClient } from "@/lib/supabase/client"

type Mode = "public" | "github"

type GitHubRepo = {
  id: number
  fullName: string
  private: boolean
  defaultBranch: string
  htmlUrl: string
  updatedAt: string
  language?: string | null
}

export function RealScanUploader({ initialMode = "public" }: { initialMode?: Mode }) {
  const router = useRouter()
  const supabase = useMemo(() => createBrowserSupabaseClient(), [])
  const [mode, setMode] = useState<Mode>(initialMode)
  const [githubUrl, setGithubUrl] = useState("")
  const [session, setSession] = useState<Session | null>(null)
  const [repos, setRepos] = useState<GitHubRepo[]>([])
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null)
  const [loading, setLoading] = useState<"scan" | "login" | "repos" | null>(null)
  const [error, setError] = useState<string | null>(null)

  const githubToken = session?.provider_token ?? undefined
  const accessToken = session?.access_token

  useEffect(() => {
    if (!supabase) return

    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session)
      if (data.session?.provider_token) void loadRepos(data.session.access_token, data.session.provider_token)
    })

    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession)
      if (nextSession?.provider_token) void loadRepos(nextSession.access_token, nextSession.provider_token)
      if (!nextSession) {
        setRepos([])
        setSelectedRepo(null)
      }
    })

    return () => data.subscription.unsubscribe()
  }, [supabase])

  const startPublicScan = async () => {
    setError(null)
    setLoading("scan")

    try {
      if (!githubUrl.trim()) throw new Error("Paste a public GitHub repository URL first.")

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: requestHeaders(githubToken, accessToken),
        body: JSON.stringify({ githubUrl: normalizeGithubInput(githubUrl) }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Scan failed.")
      router.push(`/report/${data.scanId}`)
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed.")
    } finally {
      setLoading(null)
    }
  }

  const startRepoScan = async (repo: GitHubRepo) => {
    setError(null)
    setLoading("scan")

    try {
      if (!githubToken) throw new Error("Reconnect GitHub before scanning private or account repositories.")

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: requestHeaders(githubToken, accessToken),
        body: JSON.stringify({ repoFullName: repo.fullName, ref: repo.defaultBranch }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Scan failed.")
      router.push(`/report/${data.scanId}`)
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed.")
    } finally {
      setLoading(null)
    }
  }

  const signInWithGitHub = async () => {
    setError(null)
    setLoading("login")

    try {
      if (!supabase) throw new Error("Supabase browser auth is not configured yet.")

      const { error: authError } = await supabase.auth.signInWithOAuth({
        provider: "github",
        options: {
          scopes: "repo read:user user:email",
          redirectTo: `${window.location.origin}/scan`,
        },
      })

      if (authError) throw authError
    } catch (authError) {
      setLoading(null)
      setError(authError instanceof Error ? authError.message : "GitHub login failed.")
    }
  }

  const signOut = async () => {
    await supabase?.auth.signOut()
    setSession(null)
    setRepos([])
    setSelectedRepo(null)
  }

  async function loadRepos(authToken?: string, providerToken?: string) {
    setLoading("repos")
    setError(null)

    try {
      if (!providerToken) throw new Error("GitHub provider token is missing. Sign in with GitHub again.")

      const response = await fetch("/api/github/repos", {
        headers: requestHeaders(providerToken, authToken),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Could not list repositories.")
      setRepos(data.repos)
      setSelectedRepo(data.repos?.[0] ?? null)
    } catch (repoError) {
      setError(repoError instanceof Error ? repoError.message : "Could not list repositories.")
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="scan-live-shell">
      <section className="onboard-hero">
        <span className="onboard-eyebrow">GitHub-native security harness</span>
        <h1 className="onboard-title">
          Scan your AI-built app <em>before you ship.</em>
        </h1>
        <p className="onboard-sub">
          VibeShield reads repositories server-side through GitHub APIs, runs deterministic static-analysis passes,
          and uses AI only to explain verified findings and generate review-required patch previews.
        </p>
      </section>

      <div className="surface scan-card real-scan-card">
        <div className="scan-tabs">
          <button className="scan-tab" data-active={mode === "public"} onClick={() => setMode("public")} type="button">
            <Icon.branch /> Public repo URL
          </button>
          <button className="scan-tab" data-active={mode === "github"} onClick={() => setMode("github")} type="button">
            <Icon.branch /> GitHub login
          </button>
          <div style={{ flex: 1 }} />
          <div className="scan-tab scan-tab-static">
            <Icon.lock /> No ZIP uploads
          </div>
        </div>

        <div className="scan-body">
          {mode === "public" ? (
            <div className="scan-input real-github-input">
              <span className="prefix">https://github.com/</span>
              <input
                value={githubUrl.replace(/^https:\/\/github\.com\//, "")}
                onChange={(event) => setGithubUrl(normalizeGithubInput(event.target.value))}
                placeholder="owner/repo"
              />
              <span className="hint mono">server-side</span>
            </div>
          ) : (
            <div className="github-repo-panel">
              <div className="github-repo-head">
                <div>
                  <b>{session?.user?.email ?? "Connect GitHub"}</b>
                  <span>{session ? "Choose a repository from your GitHub account." : "Login lists repositories through GitHub API metadata."}</span>
                </div>
                {session ? (
                  <button className="btn btn-outline" type="button" onClick={signOut}>
                    Sign out
                  </button>
                ) : (
                  <button className="btn btn-accent" type="button" onClick={signInWithGitHub} disabled={loading === "login"}>
                    <Icon.branch style={{ width: 14, height: 14 }} />
                    {loading === "login" ? "Redirecting..." : "Login with GitHub"}
                  </button>
                )}
              </div>

              {session && (
                <>
                  <div className="repo-toolbar">
                    <button
                      className="btn btn-outline"
                      type="button"
                      onClick={() => loadRepos(accessToken, githubToken)}
                      disabled={loading === "repos"}
                    >
                      <Icon.scan style={{ width: 14, height: 14 }} />
                      {loading === "repos" ? "Refreshing..." : "Refresh repos"}
                    </button>
                  </div>
                  <div className="repo-list">
                    {repos.map((repo) => (
                      <button
                        key={repo.id}
                        type="button"
                        className="repo-choice"
                        data-active={selectedRepo?.id === repo.id}
                        onClick={() => setSelectedRepo(repo)}
                      >
                        <span>
                          <b>{repo.fullName}</b>
                          <em>{repo.language ?? "repository"} · {repo.defaultBranch}</em>
                        </span>
                        <small>{repo.private ? "private" : "public"}</small>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

          {error && (
            <div className="scan-error" role="alert">
              <Icon.focus style={{ width: 14, height: 14 }} />
              <span>{error}</span>
            </div>
          )}

          <div className="scan-actions-row">
            {mode === "public" ? (
              <button className="btn btn-accent btn-lg" onClick={startPublicScan} disabled={loading !== null} type="button">
                <Icon.bolt style={{ width: 14, height: 14 }} />
                {loading === "scan" ? "Scanning..." : "Scan public repository"}
              </button>
            ) : (
              <button
                className="btn btn-accent btn-lg"
                onClick={() => selectedRepo && startRepoScan(selectedRepo)}
                disabled={loading !== null || !selectedRepo}
                type="button"
              >
                <Icon.bolt style={{ width: 14, height: 14 }} />
                {loading === "scan" ? "Scanning..." : "Scan selected repository"}
              </button>
            )}
          </div>

          <div className="scan-meta">
            <span>
              <b>Limits:</b> 20 scans/month · 500 files · 500 KB/file · 10 MB text
            </span>
            <span>
              <b>Harness:</b> GitHub metadata · tree API · blob API · deterministic rules
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function normalizeGithubInput(value: string) {
  const trimmed = value.trim()
  if (trimmed.startsWith("https://github.com/")) return trimmed
  return `https://github.com/${trimmed}`
}

function requestHeaders(githubToken?: string, accessToken?: string) {
  return {
    "Content-Type": "application/json",
    ...(githubToken ? { "X-GitHub-Token": githubToken } : {}),
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
  }
}
