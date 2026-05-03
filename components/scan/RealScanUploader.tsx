"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Icon } from "@/app/(app)/_components/icons"
import { ScanProgress } from "@/app/(app)/_components/scan-progress"
import { normalizePublicQuota, type PublicQuotaState } from "@/lib/security/quota-view"

type Mode = "public" | "github"
type AnalysisMode = "rules" | "normal" | "max"

const ANALYSIS_MODES: Array<{
  id: AnalysisMode
  label: string
  detail: string
}> = [
  { id: "rules", label: "Rules", detail: "no agent" },
  { id: "normal", label: "Normal", detail: "rules + agent" },
  { id: "max", label: "Max", detail: "deeper agent" },
]

type GitHubRepo = {
  id: number
  fullName: string
  private: boolean
  defaultBranch: string
  htmlUrl: string
  updatedAt: string
  language?: string | null
}

type GitHubAuthSession = {
  authenticated: boolean
  id?: number
  login?: string
  name?: string
  avatarUrl?: string
}

export function RealScanUploader({ initialMode = "public" }: { initialMode?: Mode }) {
  const router = useRouter()
  const [mode, setMode] = useState<Mode>(initialMode)
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("normal")
  const [githubUrl, setGithubUrl] = useState("")
  const [githubSession, setGitHubSession] = useState<GitHubAuthSession>({ authenticated: false })
  const [repos, setRepos] = useState<GitHubRepo[]>([])
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [loginLoading, setLoginLoading] = useState(false)
  const [reposLoading, setReposLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pendingScanId, setPendingScanId] = useState<string | null>(null)
  const [scanFinished, setScanFinished] = useState(false)
  const [scanKey, setScanKey] = useState(0)

  const githubConnected = githubSession.authenticated

  const loadRepos = useCallback(async () => {
    setReposLoading(true)
    setError(null)

    try {
      const response = await fetch("/api/github/repos", { cache: "no-store" })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Could not list repositories.")
      setRepos(data.repos)
      setSelectedRepo(data.repos?.[0] ?? null)
    } catch (repoError) {
      setError(repoError instanceof Error ? repoError.message : "Could not list repositories.")
    } finally {
      setReposLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!scanFinished || !pendingScanId) return

    const reportPath = `/report/${pendingScanId}`
    let fallbackTimer: number | undefined
    const redirectTimer = window.setTimeout(() => {
      router.push(reportPath)

      fallbackTimer = window.setTimeout(() => {
        if (window.location.pathname !== reportPath) {
          window.location.assign(reportPath)
        }
      }, 1000)
    }, 650)

    return () => {
      window.clearTimeout(redirectTimer)
      if (fallbackTimer) window.clearTimeout(fallbackTimer)
    }
  }, [pendingScanId, router, scanFinished])

  useEffect(() => {
    let cancelled = false

    fetch("/api/auth/github/session", { cache: "no-store" })
      .then((response) => response.json())
      .then((data) => {
        if (cancelled) return
        const nextSession = (data.session ?? { authenticated: false }) as GitHubAuthSession
        setGitHubSession(nextSession)
        if (nextSession.authenticated) void loadRepos()
      })
      .catch(() => {
        if (!cancelled) setGitHubSession({ authenticated: false })
      })

    return () => {
      cancelled = true
    }
  }, [loadRepos])

  const beginScan = () => {
    setError(null)
    setPendingScanId(null)
    setScanFinished(false)
    setScanKey((k) => k + 1)
    setScanLoading(true)
  }

  const handleScanFailure = (message: string) => {
    setError(message)
    setScanLoading(false)
    setScanFinished(false)
    setPendingScanId(null)
  }

  const startPublicScan = async () => {
    if (!githubUrl.trim()) {
      handleScanFailure("Paste a public GitHub repository URL first.")
      return
    }
    beginScan()

    try {
      const { response, data } = await fetchJsonWithTimeout("/api/scan", {
        method: "POST",
        headers: requestHeaders(),
        body: JSON.stringify({ githubUrl: normalizeGithubInput(githubUrl), analysisMode }),
      }, scanTimeoutMs(analysisMode))
      notifyQuotaFromResponse(data, response.headers)
      if (!response.ok) throw new Error(data.error ?? "Scan failed.")
      setPendingScanId(data.scanId)
      setScanFinished(true)
    } catch (scanError) {
      handleScanFailure(errorMessageForScan(scanError, analysisMode))
    }
  }

  const startRepoScan = async (repo: GitHubRepo) => {
    if (!githubConnected) {
      handleScanFailure("Reconnect GitHub before scanning private or account repositories.")
      return
    }
    beginScan()

    try {
      const { response, data } = await fetchJsonWithTimeout("/api/scan", {
        method: "POST",
        headers: requestHeaders(),
        body: JSON.stringify({ repoFullName: repo.fullName, ref: repo.defaultBranch, analysisMode }),
      }, scanTimeoutMs(analysisMode))
      notifyQuotaFromResponse(data, response.headers)
      if (!response.ok) throw new Error(data.error ?? "Scan failed.")
      setPendingScanId(data.scanId)
      setScanFinished(true)
    } catch (scanError) {
      handleScanFailure(errorMessageForScan(scanError, analysisMode))
    }
  }

  const signInWithGitHub = async () => {
    setError(null)
    setLoginLoading(true)
    window.location.assign("/api/auth/github/start")
  }

  const signOut = async () => {
    await fetch("/api/auth/github/session", { method: "DELETE" })
    setGitHubSession({ authenticated: false })
    setRepos([])
    setSelectedRepo(null)
  }

  return (
    <div className="scan-live-shell">
      <section className="onboard-hero">
        <span className="onboard-eyebrow">Evidence-first security review</span>
        <h1 className="onboard-title">
          Review an AI-built repo <em>before it becomes your risk.</em>
        </h1>
        <p className="onboard-sub">
          VibeShield reads GitHub repositories server-side, runs deterministic AppSec analyzers,
          and uses AI to triage evidence, explain impact and prepare review-required fixes.
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
          <fieldset className="analysis-mode-field" aria-label="Analysis depth">
            <legend>Mode</legend>
            <div className="analysis-mode-grid">
              {ANALYSIS_MODES.map((option) => (
                <button
                  className="analysis-mode-choice"
                  data-active={analysisMode === option.id}
                  key={option.id}
                  type="button"
                  onClick={() => setAnalysisMode(option.id)}
                >
                  <b>{option.label}</b>
                  <span>{option.detail}</span>
                </button>
              ))}
            </div>
          </fieldset>

          {mode === "public" ? (
            <div className="scan-input real-github-input">
              <input
                value={githubUrl}
                onChange={(event) => setGithubUrl(event.target.value)}
                placeholder="https://github.com/owner/repo"
              />
              <span className="hint mono">server-side</span>
            </div>
          ) : (
            <div className="github-repo-panel">
              <div className="github-repo-head">
                <div>
                  <b>{githubSession.name ?? githubSession.login ?? "Connect GitHub"}</b>
                  <span>{githubConnected ? "Choose a repository from your GitHub account." : "Login lists repositories through GitHub API metadata."}</span>
                </div>
                {githubConnected ? (
                  <button className="btn btn-outline" type="button" onClick={signOut}>
                    Sign out
                  </button>
                ) : (
                  <button className="btn btn-accent" type="button" onClick={signInWithGitHub} disabled={loginLoading}>
                    <Icon.branch style={{ width: 14, height: 14 }} />
                    {loginLoading ? "Redirecting..." : "Login with GitHub"}
                  </button>
                )}
              </div>

              {githubConnected && (
                <>
                  <div className="repo-toolbar">
                    <button
                      className="btn btn-outline"
                      type="button"
                      onClick={() => loadRepos()}
                      disabled={reposLoading}
                    >
                      <Icon.scan style={{ width: 14, height: 14 }} />
                      {reposLoading ? "Refreshing..." : "Refresh repos"}
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

          {scanLoading && (
            <ScanProgress
              key={scanKey}
              done={scanFinished}
            />
          )}

          <div className="scan-actions-row">
            {mode === "public" ? (
              <button className="btn btn-outline" onClick={startPublicScan} disabled={scanLoading} type="button">
                <Icon.bolt style={{ width: 14, height: 14 }} />
                {scanLoading ? "Scanning..." : "Scan public repository"}
              </button>
            ) : (
              <button
                className="btn btn-outline"
                onClick={() => selectedRepo && startRepoScan(selectedRepo)}
                disabled={scanLoading || !selectedRepo}
                type="button"
              >
                <Icon.bolt style={{ width: 14, height: 14 }} />
                {scanLoading ? "Scanning..." : "Scan selected repository"}
              </button>
            )}
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

function requestHeaders() {
  return {
    "Content-Type": "application/json",
  }
}

async function fetchJsonWithTimeout(url: string, init: RequestInit, timeoutMs: number) {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    })
    const data = await response.json()
    return { response, data }
  } finally {
    window.clearTimeout(timeout)
  }
}

function scanTimeoutMs(mode: AnalysisMode) {
  if (mode === "max") return 390_000
  if (mode === "normal") return 150_000
  return 90_000
}

function notifyQuotaFromResponse(data: unknown, headers: Headers) {
  const quota = normalizePublicQuota((data as { quota?: unknown } | null)?.quota) ?? quotaFromHeaders(headers)
  if (!quota) return

  window.dispatchEvent(new CustomEvent<PublicQuotaState>("vibeshield:quota", { detail: quota }))
}

function quotaFromHeaders(headers: Headers) {
  const period = headers.get("X-RateLimit-Period")
  if (period !== "monthly") return null

  return normalizePublicQuota({
    period,
    limit: headers.get("X-RateLimit-Limit"),
    remaining: headers.get("X-RateLimit-Remaining"),
    resetAt: headers.get("X-RateLimit-Reset"),
  })
}

function errorMessageForScan(error: unknown, mode: AnalysisMode) {
  if (error instanceof Error && error.name === "AbortError") {
    return mode === "max"
      ? "Max scan is taking longer than expected. Try Normal mode for this repository, or retry Max after narrowing the project."
      : "Scan is taking longer than expected. Retry in a moment or use Rules mode for a faster deterministic pass."
  }

  return error instanceof Error ? error.message : "Scan failed."
}
