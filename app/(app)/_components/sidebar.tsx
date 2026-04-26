"use client"

import Link from "next/link"
import Image from "next/image"
import { useEffect, useMemo, useState } from "react"
import { usePathname, useRouter } from "next/navigation"
import type { Session } from "@supabase/supabase-js"
import type { ScanReport } from "@/lib/scanner/types"
import { createBrowserSupabaseClient } from "@/lib/supabase/client"
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
  const supabase = useMemo(() => createBrowserSupabaseClient(), [])
  const [session, setSession] = useState<Session | null>(null)
  const [sessionChecked, setSessionChecked] = useState(!supabase)
  const [reports, setReports] = useState<ScanReport[]>([])
  const [historyState, setHistoryState] = useState<"idle" | "loading" | "error">("loading")
  const profile = getGitHubProfile(session)

  const isActive = (it: Item) => {
    if (it.match) return it.match(pathname)
    return pathname === it.href
  }

  useEffect(() => {
    if (!supabase) return

    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session)
      setSessionChecked(true)
    })

    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession)
      setSessionChecked(true)
    })

    return () => data.subscription.unsubscribe()
  }, [supabase])

  useEffect(() => {
    if (!sessionChecked) return

    const controller = new AbortController()

    async function loadRecentReports() {
      setHistoryState("loading")

      try {
        const response = await fetch("/api/scans", {
          headers: authHeaders(session?.access_token),
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error ?? "Could not load reports.")
        setReports(data.reports ?? [])
        setHistoryState("idle")
      } catch {
        if (controller.signal.aborted) return
        setHistoryState("error")
      }
    }

    void loadRecentReports()

    return () => controller.abort()
  }, [pathname, session?.access_token, sessionChecked])

  return (
    <>
      <aside className="app-side" data-open={open}>
        <div className="app-side-scroll">
          <div className="brand-row">
            <button type="button" className="brand" onClick={() => router.push("/")}>
              <span className="brand-mark"><Icon.shield /></span>
              <span>VibeShield</span>
            </button>
          </div>

          <div className="quota-card">
            <div className="quota-row">
              <span className="quota-label">Monthly limit</span>
              <span className="quota-value"><b>20</b> scans</span>
            </div>
            <div className="quota-bar"><span style={{ width: "100%" }} /></div>
          </div>

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
          <div className="user-card">
            {profile.avatarUrl ? (
              <Image
                className="avatar avatar-image"
                src={profile.avatarUrl}
                alt=""
                width={30}
                height={30}
                unoptimized
              />
            ) : (
              <div className="avatar">{profile.initials}</div>
            )}
            <div className="info">
              <b>{profile.name}</b>
              <span>{profile.subtitle}</span>
            </div>
          </div>
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

function authHeaders(accessToken?: string | null) {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined
}

function getGitHubProfile(session: Session | null) {
  if (!session) {
    return {
      name: "Public mode",
      subtitle: "paste a public repo",
      initials: "GH",
      avatarUrl: null,
    }
  }

  const metadata = session.user.user_metadata ?? {}
  const name =
    stringValue(metadata.full_name) ||
    stringValue(metadata.name) ||
    stringValue(metadata.user_name) ||
    stringValue(metadata.preferred_username) ||
    session.user.email ||
    "GitHub user"
  const username =
    stringValue(metadata.user_name) ||
    stringValue(metadata.preferred_username) ||
    stringValue(metadata.userName)

  return {
    name,
    subtitle: username ? `@${username}` : "GitHub connected",
    initials: initialsForName(name),
    avatarUrl: stringValue(metadata.avatar_url) || stringValue(metadata.picture),
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
