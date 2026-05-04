"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { SignInButton, useUser } from "@clerk/nextjs"
import { useRouter } from "next/navigation"
import { Icon } from "@/app/(app)/_components/icons"
import { ScanProgress } from "@/app/(app)/_components/scan-progress"
import { publishGitHubSessionChange, subscribeGitHubSessionChange } from "@/lib/client/github-session-events"
import { normalizePublicQuota, type PublicQuotaState } from "@/lib/security/quota-view"

type Mode = "public" | "github"
type AnalysisMode = "rules" | "normal" | "max"

const ANALYSIS_MODES: Array<{
  id: Exclude<AnalysisMode, "rules">
  label: string
  detail: string
}> = [
  { id: "normal", label: "Normal", detail: "Opus low reasoning · 1 credit" },
  { id: "max", label: "Max", detail: "Opus max reasoning · 2 credits" },
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
  scopes?: string[]
}

type ScanNoticeKind = "error" | "busy"

export function RealScanUploader({ initialMode = "public" }: { initialMode?: Mode }) {
  const router = useRouter()
  const { isLoaded: clerkLoaded, isSignedIn } = useUser()
  const [mode, setMode] = useState<Mode>(initialMode)
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("normal")
  const [githubUrl, setGithubUrl] = useState("")
  const [githubSession, setGitHubSession] = useState<GitHubAuthSession>({ authenticated: false })
  const [repos, setRepos] = useState<GitHubRepo[]>([])
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [loginLoading, setLoginLoading] = useState(false)
  const [sessionLoading, setSessionLoading] = useState(true)
  const [reposLoading, setReposLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [noticeKind, setNoticeKind] = useState<ScanNoticeKind>("error")
  const [pendingScanId, setPendingScanId] = useState<string | null>(null)
  const [scanFinished, setScanFinished] = useState(false)
  const [scanKey, setScanKey] = useState(0)
  const sessionVersion = useRef(0)

  const githubConnected = githubSession.authenticated
  const badgerSignedIn = clerkLoaded && Boolean(isSignedIn)

  const loadRepos = useCallback(async () => {
    const activeSessionVersion = sessionVersion.current
    setReposLoading(true)
    setError(null)

    try {
      const response = await fetch("/api/github/repos", { cache: "no-store" })
      const data = await response.json()
      if (sessionVersion.current !== activeSessionVersion) return
      if (!response.ok) throw new Error(data.error ?? "Could not list repositories.")
      setRepos(data.repos)
      setSelectedRepo(data.repos?.[0] ?? null)
    } catch (repoError) {
      if (sessionVersion.current !== activeSessionVersion) return
      setError(repoError instanceof Error ? repoError.message : "Could not list repositories.")
    } finally {
      if (sessionVersion.current === activeSessionVersion) setReposLoading(false)
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
    const activeSessionVersion = sessionVersion.current

    fetch("/api/auth/github/session", { cache: "no-store" })
      .then((response) => response.json())
      .then((data) => {
        if (cancelled || sessionVersion.current !== activeSessionVersion) return
        const nextSession = (data.session ?? { authenticated: false }) as GitHubAuthSession
        setGitHubSession(nextSession)
        if (nextSession.authenticated) void loadRepos()
      })
      .catch(() => {
        if (!cancelled && sessionVersion.current === activeSessionVersion) setGitHubSession({ authenticated: false })
      })
      .finally(() => {
        if (!cancelled && sessionVersion.current === activeSessionVersion) setSessionLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [loadRepos])

  useEffect(() => {
    return subscribeGitHubSessionChange(() => {
      sessionVersion.current += 1
      setGitHubSession({ authenticated: false })
      setRepos([])
      setSelectedRepo(null)
      setMode("public")
      setLoginLoading(false)
      setSessionLoading(false)
      setReposLoading(false)
      setScanLoading(false)
      setScanFinished(false)
      setPendingScanId(null)
      setError(null)
      setNoticeKind("error")
    })
  }, [])

  const beginScan = () => {
    setError(null)
    setNoticeKind("error")
    setPendingScanId(null)
    setScanFinished(false)
    setScanKey((k) => k + 1)
    setScanLoading(true)
  }

  const handleScanFailure = (message: string, kind: ScanNoticeKind = "error") => {
    setError(message)
    setNoticeKind(kind)
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
    const activeSessionVersion = sessionVersion.current

    try {
      const { response, data } = await fetchJsonWithTimeout("/api/scan", {
        method: "POST",
        headers: requestHeaders(),
        body: JSON.stringify({ githubUrl: normalizeGithubInput(githubUrl), analysisMode }),
      }, scanTimeoutMs(analysisMode))
      if (sessionVersion.current !== activeSessionVersion) return
      notifyQuotaFromResponse(data, response.headers)
      if (!response.ok) throw scanErrorFromResponse(data)
      setPendingScanId(data.scanId)
      setScanFinished(true)
    } catch (scanError) {
      if (sessionVersion.current !== activeSessionVersion) return
      handleScanFailure(errorMessageForScan(scanError, analysisMode), scanNoticeKind(scanError))
    }
  }

  const startRepoScan = async (repo: GitHubRepo) => {
    if (!githubConnected) {
      handleScanFailure("Reconnect GitHub before scanning private or account repositories.")
      return
    }
    beginScan()
    const activeSessionVersion = sessionVersion.current

    try {
      const { response, data } = await fetchJsonWithTimeout("/api/scan", {
        method: "POST",
        headers: requestHeaders(),
        body: JSON.stringify({ repoFullName: repo.fullName, ref: repo.defaultBranch, analysisMode }),
      }, scanTimeoutMs(analysisMode))
      if (sessionVersion.current !== activeSessionVersion) return
      notifyQuotaFromResponse(data, response.headers)
      if (!response.ok) throw scanErrorFromResponse(data)
      setPendingScanId(data.scanId)
      setScanFinished(true)
    } catch (scanError) {
      if (sessionVersion.current !== activeSessionVersion) return
      handleScanFailure(errorMessageForScan(scanError, analysisMode), scanNoticeKind(scanError))
    }
  }

  const connectGitHub = async () => {
    setError(null)
    setLoginLoading(true)
    window.location.assign("/api/auth/github/start")
  }

  const signOut = async () => {
    const confirmed = window.confirm(
      "Sign out of GitHub in this browser? This will not revoke the GitHub authorization. Use the dashboard profile menu if you want to disconnect GitHub completely.",
    )
    if (!confirmed) return

    const response = await fetch("/api/auth/github/session", { method: "DELETE" })
    if (!response.ok) {
      setError("Could not sign out of GitHub. Try again.")
      return
    }

    setGitHubSession({ authenticated: false })
    setRepos([])
    setSelectedRepo(null)
    setMode("public")
    publishGitHubSessionChange("signed_out")
  }

  return (
    <div className="scan-live-shell">
      <section className="onboard-hero">
        <span className="onboard-eyebrow">AI-built code needs real review</span>
        <h1 className="onboard-title">
          Turn a GitHub repo into <em>security evidence.</em>
        </h1>
        <p className="onboard-sub">
          Badger scans AI-built projects without running their code, separates real risk from
          noisy findings, and uses AI to explain evidence-backed issues before you ship or open a PR.
        </p>
      </section>

      <div className="surface scan-card real-scan-card">
        <div className="scan-tabs">
          <button className="scan-tab" data-active={mode === "public"} onClick={() => setMode("public")} type="button">
            <Icon.branch /> Public repo URL
          </button>
          <button className="scan-tab" data-active={mode === "github"} onClick={() => setMode("github")} type="button">
            <Icon.branch /> {githubConnected ? "Your repositories" : "Connect GitHub"}
          </button>
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
            <>
              <div className="scan-input real-github-input">
                <input
                  value={githubUrl}
                  onChange={(event) => setGithubUrl(event.target.value)}
                  placeholder="https://github.com/owner/repo"
                />
                <span className="hint mono">no login</span>
              </div>
              <p className="scan-trust-note">
                Public scans do not require GitHub login. Badger reads supported public repository files server-side and only asks for GitHub write access if you choose PR creation.
              </p>
            </>
          ) : sessionLoading || !clerkLoaded ? (
            <div className="scan-auth-gate">
              <div className="auth-gate-icon">
                <Icon.branch style={{ width: 20, height: 20 }} />
              </div>
              <div>
                <b>Checking account session</b>
                <span>Public scans still work without signing in.</span>
              </div>
            </div>
          ) : !badgerSignedIn ? (
            <div className="scan-auth-gate">
              <div className="auth-gate-icon">
                <Icon.branch style={{ width: 20, height: 20 }} />
              </div>
              <div>
                <b>Log in to use your account dashboard</b>
                <span>This uses the same Clerk login flow as the landing page. Public scans still work without an account.</span>
              </div>
              <SignInButton mode="modal">
                <button className="btn btn-accent btn-lg btn-shine" type="button">
                  <Icon.branch style={{ width: 14, height: 14 }} />
                  Sign in with GitHub
                </button>
              </SignInButton>
            </div>
          ) : !githubConnected ? (
            <div className="scan-auth-gate">
              <div className="auth-gate-icon">
                <Icon.branch style={{ width: 20, height: 20 }} />
              </div>
              <div>
                <b>Connect GitHub for your account repositories</b>
                <span>This starts with read-only profile access. Badger asks for PR permission only if you choose to open a pull request.</span>
              </div>
              <button className="btn btn-accent btn-lg btn-shine" type="button" onClick={connectGitHub} disabled={loginLoading}>
                <Icon.branch style={{ width: 14, height: 14 }} />
                {loginLoading ? "Redirecting..." : "Connect GitHub"}
              </button>
            </div>
          ) : (
            <div className="github-repo-panel">
              <div className="github-repo-head">
                <div>
                  <b>{githubSession.name ?? githubSession.login ?? "GitHub account"}</b>
                  <span>Choose a repository from your GitHub account. PR permission is requested later only when needed.</span>
                </div>
                <button className="btn btn-outline" type="button" onClick={signOut}>
                  Sign out
                </button>
              </div>

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
            </div>
          )}

          {error && (
            <div className="scan-error" data-kind={noticeKind} role="alert">
              <Icon.focus style={{ width: 14, height: 14 }} />
              <span>{error}</span>
              {noticeKind === "busy" && !githubConnected && (
                badgerSignedIn ? (
                  <button className="btn btn-outline scan-error-action" type="button" onClick={connectGitHub} disabled={loginLoading}>
                    {loginLoading ? "Redirecting..." : "Connect GitHub"}
                  </button>
                ) : (
                  <SignInButton mode="modal">
                    <button className="btn btn-outline scan-error-action" type="button">
                      Sign in
                    </button>
                  </SignInButton>
                )
              )}
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
                disabled={scanLoading || !selectedRepo || !githubConnected}
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

function scanErrorFromResponse(data: unknown) {
  const body = data as { error?: unknown; code?: unknown } | null
  const error = new Error(typeof body?.error === "string" ? body.error : "Scan failed.") as Error & { code?: string }
  if (typeof body?.code === "string") error.code = body.code
  return error
}

function scanNoticeKind(error: unknown): ScanNoticeKind {
  if (error instanceof Error && (error as Error & { code?: string }).code === "github_rate_limited") return "busy"
  return "error"
}

function scanTimeoutMs(mode: AnalysisMode) {
  if (mode === "max") return 390_000
  if (mode === "normal") return 150_000
  return 90_000
}

function notifyQuotaFromResponse(data: unknown, headers: Headers) {
  const quota = normalizePublicQuota((data as { quota?: unknown } | null)?.quota) ?? quotaFromHeaders(headers)
  if (!quota) return

  window.dispatchEvent(new CustomEvent<PublicQuotaState>("badger:quota", { detail: quota }))
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
      : "Scan is taking longer than expected. Retry in a moment or try Max for deeper review after this scan finishes."
  }

  return error instanceof Error ? error.message : "Scan failed."
}
