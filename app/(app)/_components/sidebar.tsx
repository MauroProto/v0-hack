"use client"

import Link from "next/link"
import Image from "next/image"
import { useEffect, useState } from "react"
import { usePathname, useRouter } from "next/navigation"
import type { ScanReport } from "@/lib/scanner/types"
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
  const [githubSession, setGitHubSession] = useState<GitHubAuthSession>({ authenticated: false })
  const [reports, setReports] = useState<ScanReport[]>([])
  const [quota, setQuota] = useState<PublicQuotaState | null>(null)
  const [historyState, setHistoryState] = useState<"idle" | "loading" | "error">("loading")
  const [signingOut, setSigningOut] = useState(false)
  const profile = getGitHubProfile(githubSession)

  const isActive = (it: Item) => {
    if (it.match) return it.match(pathname)
    return pathname === it.href
  }

  useEffect(() => {
    async function loadGitHubSession() {
      try {
        const response = await fetch("/api/auth/github/session", { cache: "no-store" })
        const data = await response.json()
        setGitHubSession(data.session ?? { authenticated: false })
      } catch {
        setGitHubSession({ authenticated: false })
      }
    }

    void loadGitHubSession()
  }, [pathname])

  useEffect(() => {
    const controller = new AbortController()

    async function loadRecentReports() {
      setHistoryState("loading")

      try {
        const response = await fetch("/api/scans", {
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error ?? "Could not load reports.")
        setReports(data.reports ?? [])
        setQuota(normalizePublicQuota(data.quota))
        setHistoryState("idle")
      } catch {
        if (controller.signal.aborted) return
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

    window.addEventListener("vibeshield:quota", handleQuotaUpdate)
    return () => window.removeEventListener("vibeshield:quota", handleQuotaUpdate)
  }, [])

  const signOut = async () => {
    if (!githubSession.authenticated || signingOut) return

    setSigningOut(true)
    try {
      await fetch("/api/auth/github/session", { method: "DELETE" })
      setGitHubSession({ authenticated: false })
      setReports([])
      setQuota(null)
      router.refresh()
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <>
      <aside className="app-side" data-open={open}>
        <div className="app-side-scroll">
          <div className="brand-row">
            <button type="button" className="brand" onClick={() => router.push("/")}>
              <span>VibeShield</span>
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
            data-clickable={githubSession.authenticated}
            disabled={!githubSession.authenticated || signingOut}
            onClick={signOut}
            title={githubSession.authenticated ? "Sign out of GitHub" : "Public scans do not require login"}
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
              <div className="avatar">{profile.initials}</div>
            )}
            <div className="info">
              <b>{profile.name}</b>
              <span>{signingOut ? "signing out..." : profile.subtitle}</span>
            </div>
          </button>
        </div>
      </aside>

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

function getGitHubProfile(session: GitHubAuthSession) {
  if (!session.authenticated) {
    return {
      name: "Public mode",
      subtitle: "paste a public repo",
      initials: "GH",
      avatarUrl: null,
    }
  }

  const name = session.name || session.login || "GitHub user"
  const username = session.login

  return {
    name,
    subtitle: username ? `@${username}` : "GitHub connected",
    initials: initialsForName(name),
    avatarUrl: stringValue(session.avatarUrl),
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
