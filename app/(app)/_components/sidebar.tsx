"use client"

import Link from "next/link"
import Image from "next/image"
import { useEffect, useRef, useState } from "react"
import { useClerk, useUser } from "@clerk/nextjs"
import { usePathname, useRouter } from "next/navigation"
import type { ScanReport } from "@/lib/scanner/types"
import { publishGitHubSessionChange, subscribeGitHubSessionChange } from "@/lib/client/github-session-events"
import { type GuestSession, useGuestSession } from "@/lib/client/guest-session"
import { deriveQuotaDisplay, normalizePublicQuota, type PublicQuotaState } from "@/lib/security/quota-view"
import { Icon } from "./icons"

type Item = {
  key: string
  label: string
  icon: keyof typeof Icon
  href: string
  count?: number
  live?: boolean
  match?: (path: string) => boolean
}

type GitHubAuthSession = {
  authenticated: boolean
  login?: string
  name?: string
  avatarUrl?: string
  source?: "legacy" | "clerk"
}

const PRIMARY: Item[] = [
  {
    key: "current",
    label: "New scan",
    icon: "focus",
    href: "/scan",
    match: (p) => p === "/scan" || p.startsWith("/report/"),
  },
  { key: "scans", label: "Scan history", icon: "scan", href: "/scans" },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname() || ""
  const router = useRouter()
  const clerk = useUser()
  const clerkClient = useClerk()
  const [githubSession, setGitHubSession] = useState<GitHubAuthSession>({ authenticated: false })
  const guestSession = useGuestSession()
  const [reports, setReports] = useState<ScanReport[]>([])
  const [quota, setQuota] = useState<PublicQuotaState | null>(null)
  const [historyState, setHistoryState] = useState<"idle" | "loading" | "error">("loading")
  const [accountDialogOpen, setAccountDialogOpen] = useState(false)
  const [accountAction, setAccountAction] = useState<"signout" | "disconnect" | null>(null)
  const [accountError, setAccountError] = useState<string | null>(null)
  const profile = getProfile(githubSession, guestSession, {
    authenticated: clerk.isLoaded && Boolean(clerk.isSignedIn),
    name:
      clerk.user?.fullName ||
      clerk.user?.username ||
      clerk.user?.primaryEmailAddress?.emailAddress ||
      null,
    username: clerk.user?.username || null,
  })
  const accountBusy = accountAction !== null
  const clerkSignedIn = clerk.isLoaded && Boolean(clerk.isSignedIn)
  const canManageAccount = clerkSignedIn || githubSession.authenticated
  const sessionVersion = useRef(0)

  const isActive = (it: Item) => {
    if (it.match) return it.match(pathname)
    return pathname === it.href
  }

  useEffect(() => {
    if (!clerk.isLoaded) return

    async function loadGitHubSession() {
      const activeSessionVersion = sessionVersion.current
      try {
        const response = await fetch("/api/auth/github/session", { cache: "no-store" })
        const data = await response.json()
        if (sessionVersion.current !== activeSessionVersion) return
        setGitHubSession(data.session ?? { authenticated: false })
      } catch {
        if (sessionVersion.current !== activeSessionVersion) return
        setGitHubSession({ authenticated: false })
      }
    }

    void loadGitHubSession()
  }, [clerk.isLoaded, clerk.isSignedIn, pathname])

  useEffect(() => {
    const controller = new AbortController()

    async function loadRecentReports() {
      const activeSessionVersion = sessionVersion.current
      setHistoryState("loading")

      try {
        const response = await fetch("/api/scans", {
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (sessionVersion.current !== activeSessionVersion) return
        if (!response.ok) throw new Error(data.error ?? "Could not load reports.")
        setReports(data.reports ?? [])
        setQuota(normalizePublicQuota(data.quota))
        setHistoryState("idle")
      } catch {
        if (controller.signal.aborted) return
        if (sessionVersion.current !== activeSessionVersion) return
        setHistoryState("error")
      }
    }

    void loadRecentReports()

    return () => controller.abort()
  }, [pathname])

  useEffect(() => {
    function handleQuotaUpdate(event: Event) {
      const nextQuota = normalizePublicQuota((event as CustomEvent).detail)
      if (nextQuota) setQuota(nextQuota)
    }

    window.addEventListener("badger:quota", handleQuotaUpdate)
    return () => {
      window.removeEventListener("badger:quota", handleQuotaUpdate)
    }
  }, [])

  useEffect(() => {
    return subscribeGitHubSessionChange(() => {
      sessionVersion.current += 1
      setGitHubSession({ authenticated: false })
      setReports([])
      setQuota(null)
      setHistoryState("idle")
      setAccountDialogOpen(false)
      setAccountError(null)
    })
  }, [])

  useEffect(() => {
    if (!accountDialogOpen) return

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !accountBusy) {
        setAccountDialogOpen(false)
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [accountDialogOpen, accountBusy])

  const endAccountSession = async (disconnect: boolean) => {
    if (!canManageAccount || accountBusy) return

    setAccountAction(disconnect ? "disconnect" : "signout")
    setAccountError(null)
    try {
      if (githubSession.authenticated) {
        const canDisconnectLegacyGitHub = disconnect && githubSession.source === "legacy"
        const response = await fetch(`/api/auth/github/session${canDisconnectLegacyGitHub ? "?disconnect=1" : ""}`, {
          method: "DELETE",
          headers: canDisconnectLegacyGitHub ? { "Content-Type": "application/json" } : undefined,
          body: canDisconnectLegacyGitHub ? JSON.stringify({ disconnect: true }) : undefined,
        })
        const data = (await response.json().catch(() => ({}))) as { error?: string }
        if (!response.ok) throw new Error(data.error ?? "Could not update the GitHub connection.")
      }

      if (clerkSignedIn) {
        await clerkClient.signOut()
      }

      setGitHubSession({ authenticated: false })
      setReports([])
      setQuota(null)
      setAccountDialogOpen(false)
      publishGitHubSessionChange(disconnect ? "disconnected" : "signed_out")
      if (pathname !== "/scan") {
        router.replace("/scan")
      }
      router.refresh()
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : "Could not update the account session.")
    } finally {
      setAccountAction(null)
    }
  }

  return (
    <>
      <aside className="app-side" data-open={open}>
        <div className="app-side-scroll">
          <div className="brand-row">
            <button type="button" className="brand" onClick={() => router.push("/")}>
              <span>Badger</span>
            </button>
          </div>

          <QuotaCard quota={quota} />

          <nav className="side-nav">
            {PRIMARY.map((it) => {
              const I = Icon[it.icon]
              const active = isActive(it)
              return (
                <Link key={it.key} href={it.href} className="side-link" data-active={active} onClick={onClose}>
                  <I />
                  <span className="label">{it.label}</span>
                  {it.live && <span className="live-dot" aria-label="live" />}
                  {typeof it.count === "number" && <span className="count">{it.count}</span>}
                </Link>
              )
            })}
          </nav>

          <ReportHistoryNav
            reports={reports}
            state={historyState}
            pathname={pathname}
            onClose={onClose}
          />
        </div>

        <div className="app-side-bottom">
          <button
            type="button"
            className="user-card"
            data-clickable={canManageAccount}
            disabled={!canManageAccount || accountBusy}
            onClick={() => {
              setAccountError(null)
              setAccountDialogOpen(true)
            }}
            title={canManageAccount ? "Manage account" : "Public scans do not require login"}
          >
            {profile.avatarUrl ? (
              <Image
                className="avatar avatar-image"
                src={profile.avatarUrl}
                alt=""
                width={30}
                height={30}
              />
            ) : (
              <div
                className="avatar"
                style={profile.gradient ? { background: profile.gradient } : undefined}
              >
                {profile.initials}
              </div>
            )}
            <div className="info">
              <b>{profile.name}</b>
              <span>{accountBusy ? "updating..." : profile.subtitle}</span>
            </div>
          </button>
        </div>
      </aside>

      {accountDialogOpen && canManageAccount ? (
        <div
          className="account-dialog-backdrop"
          role="presentation"
          onMouseDown={() => {
            if (!accountBusy) setAccountDialogOpen(false)
          }}
        >
          <section
            className="account-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="account-dialog-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="account-dialog-head">
              <div>
                <h3 id="account-dialog-title">Account</h3>
                <p>Choose what should happen to this browser session.</p>
              </div>
              <button
                type="button"
                aria-label="Close GitHub connection dialog"
                onClick={() => setAccountDialogOpen(false)}
                disabled={accountBusy}
              >
                ×
              </button>
            </div>

            <div className="account-dialog-profile">
              {profile.avatarUrl ? (
                <Image
                  className="avatar avatar-image"
                  src={profile.avatarUrl}
                  alt=""
                  width={34}
                  height={34}
                />
              ) : (
                <div
                  className="avatar"
                  style={profile.gradient ? { background: profile.gradient } : undefined}
                >
                  {profile.initials}
                </div>
              )}
              <div>
                <b>{profile.name}</b>
                <span>{profile.subtitle}</span>
              </div>
            </div>

            {accountError ? <div className="account-dialog-error">{accountError}</div> : null}

            <div className="account-dialog-actions">
              {clerkSignedIn ? (
                <button
                  className="btn btn-outline"
                  type="button"
                  disabled={accountBusy}
                  onClick={() => clerkClient.openUserProfile()}
                >
                  Manage profile
                </button>
              ) : null}
              <button
                className="btn btn-outline"
                type="button"
                disabled={accountBusy}
                onClick={() => void endAccountSession(false)}
              >
                {accountAction === "signout" ? "Signing out..." : "Sign out"}
              </button>
              {githubSession.source === "legacy" ? (
                <button
                  className="btn btn-outline account-danger"
                  type="button"
                  disabled={accountBusy}
                  onClick={() => void endAccountSession(true)}
                >
                  {accountAction === "disconnect" ? "Disconnecting..." : "Disconnect GitHub"}
                </button>
              ) : (
                <a className="btn btn-outline" href="https://github.com/settings/applications" target="_blank" rel="noreferrer">
                  Review GitHub access
                </a>
              )}
            </div>

            <p className="account-dialog-note">
              Sign out clears this browser session. GitHub access for Clerk sign-ins is managed by Clerk and GitHub, so you can also review access in{" "}
              <a href="https://github.com/settings/applications" target="_blank" rel="noreferrer">
                GitHub settings
              </a>
              .
            </p>
          </section>
        </div>
      ) : null}

      <div
        className="app-side-overlay"
        data-open={open}
        onClick={onClose}
        aria-hidden="true"
      />
    </>
  )
}

function QuotaCard({ quota }: { quota: PublicQuotaState | null }) {
  const display = deriveQuotaDisplay(quota)

  return (
    <div className="quota-card" data-tone={display.tone} title={display.resetLabel} aria-busy={!display.known}>
      <div className="quota-row">
        <span className="quota-label">Monthly credits</span>
        <span className="quota-value">
          {display.known ? (
            <>
              <b>{display.remaining}</b> / {display.limit} left
            </>
          ) : (
            display.label
          )}
        </span>
      </div>
      <div className="quota-bar" aria-label={display.label}>
        <span style={{ width: `${display.percentRemaining}%` }} />
      </div>
    </div>
  )
}

function ReportHistoryNav({
  reports,
  state,
  pathname,
  onClose,
}: {
  reports: ScanReport[]
  state: "idle" | "loading" | "error"
  pathname: string
  onClose: () => void
}) {
  return (
    <>
      <div className="side-section-head">
        <span>Report history</span>
        <Link href="/scans" onClick={onClose}>All</Link>
      </div>

      <div className="side-report-list">
        {state === "loading" && reports.length === 0 ? (
          <div className="side-report-empty">Loading reports...</div>
        ) : state === "error" ? (
          <div className="side-report-empty">History unavailable</div>
        ) : reports.length === 0 ? (
          <div className="side-report-empty">No reports yet</div>
        ) : (
          reports.map((report) => (
            <Link
              key={report.id}
              href={`/report/${report.id}`}
              className="side-report-link"
              data-active={pathname === `/report/${report.id}`}
              onClick={onClose}
            >
              <span className="side-report-score" data-tone={scoreTone(report.riskScore)}>
                {report.riskScore}
              </span>
              <span className="side-report-copy">
                <b>{report.projectName}</b>
                <em>{report.findings.length} findings · {formatShortDate(report.createdAt)}</em>
              </span>
            </Link>
          ))
        )}
      </div>
    </>
  )
}

function scoreTone(score: number) {
  if (score >= 50) return "danger"
  if (score >= 20) return "warn"
  return "ok"
}

function formatShortDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
  }).format(new Date(value))
}

function getProfile(
  session: GitHubAuthSession,
  guest: GuestSession | null,
  clerk: {
    authenticated: boolean
    name: string | null
    username: string | null
  },
) {
  if (session.authenticated) {
    const name = session.name || session.login || "GitHub user"
    const username = session.login

    return {
      name,
      subtitle: username ? `@${username}` : "GitHub connected",
      initials: initialsForName(name),
      avatarUrl: stringValue(session.avatarUrl),
      gradient: null,
    }
  }

  if (clerk.authenticated) {
    const name = clerk.name || "Badger account"

    return {
      name,
      subtitle: clerk.username ? `@${clerk.username} · signed in` : "signed in",
      initials: initialsForName(name),
      avatarUrl: null,
      gradient: null,
    }
  }

  if (guest) {
    return {
      name: guest.name,
      subtitle: `@${guest.handle} · guest mode`,
      initials: guest.initials,
      avatarUrl: null,
      gradient: `linear-gradient(135deg, ${guest.colorA}, ${guest.colorB})`,
    }
  }

  return {
    name: "Public mode",
    subtitle: "paste a public repo",
    initials: "GH",
    avatarUrl: null,
    gradient: null,
  }
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : null
}

function initialsForName(name: string) {
  const [first, second] = name
    .replace(/@.+$/, "")
    .split(/\s+/)
    .filter(Boolean)

  return `${first?.[0] ?? "G"}${second?.[0] ?? ""}`.toUpperCase()
}
