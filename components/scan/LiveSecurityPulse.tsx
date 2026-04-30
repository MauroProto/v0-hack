"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import type { FindingCategory, ScanFinding, ScanReport, Severity } from "@/lib/scanner/types"

type PulseEventKind =
  | "scan_started"
  | "scan_completed"
  | "critical_finding"
  | "patch_preview"
  | "pull_request"
  | "low_risk"
  | "scan_failed"

type EventFlavor = "critical" | "patch" | "pr" | "scan" | "scan-pending" | "low"
type TabKey = "all" | "critical" | "patches" | "prs"

interface PulseEvent {
  id: string
  kind: PulseEventKind
  flavor: EventFlavor
  label: string
  preposition: "on" | "for"
  repo: string
  summary: string
  source: string
  scanRef: string
  timestamp: string
  href?: string
  external?: boolean
  severity?: Severity
}

const REFRESH_MS = 20_000
const NOW_TICK_MS = 30_000
const MAX_EVENTS = 14

export function LiveSecurityPulse({ reports: initialReports }: { reports?: ScanReport[] }) {
  const [reports, setReports] = useState<ScanReport[]>(initialReports ?? [])
  const [state, setState] = useState<"loading" | "ready" | "error">(initialReports ? "ready" : "loading")
  const [tab, setTab] = useState<TabKey>("all")
  const [now, setNow] = useState(0)
  const [initialized, setInitialized] = useState(false)
  const [seenIds, setSeenIds] = useState<Set<string>>(() => new Set())

  useEffect(() => {
    if (initialReports !== undefined) return

    let cancelled = false
    let controller: AbortController | null = null

    async function loadReports() {
      controller?.abort()
      controller = new AbortController()

      try {
        const response = await fetch("/api/scans", {
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error ?? "Could not load live activity.")
        if (cancelled) return

        setReports(data.reports ?? [])
        setState("ready")
        setNow(Date.now())
      } catch {
        if (cancelled || controller?.signal.aborted) return
        setState("error")
      }
    }

    void loadReports()
    const interval = window.setInterval(loadReports, REFRESH_MS)

    return () => {
      cancelled = true
      controller?.abort()
      window.clearInterval(interval)
    }
  }, [initialReports])

  useEffect(() => {
    const timeout = window.setTimeout(() => setNow(Date.now()), 0)
    const id = window.setInterval(() => setNow(Date.now()), NOW_TICK_MS)
    return () => {
      window.clearTimeout(timeout)
      window.clearInterval(id)
    }
  }, [])

  const visibleReports = initialReports ?? reports
  const allEvents = useMemo(() => buildEvents(visibleReports), [visibleReports])

  useEffect(() => {
    const id = window.setTimeout(() => {
      setSeenIds((current) => {
        const next = new Set(current)
        for (const event of allEvents) next.add(event.id)
        return next
      })
      setInitialized(true)
    }, 0)

    return () => window.clearTimeout(id)
  }, [allEvents])

  const counts = useMemo(
    () => ({
      all: allEvents.length,
      critical: allEvents.filter((event) => event.kind === "critical_finding").length,
      patches: allEvents.filter((event) => event.kind === "patch_preview").length,
      prs: allEvents.filter((event) => event.kind === "pull_request").length,
    }),
    [allEvents],
  )

  const filtered = useMemo(() => {
    if (tab === "critical") return allEvents.filter((event) => event.kind === "critical_finding")
    if (tab === "patches") return allEvents.filter((event) => event.kind === "patch_preview")
    if (tab === "prs") return allEvents.filter((event) => event.kind === "pull_request")
    return allEvents
  }, [tab, allEvents])

  const flagged = useMemo(
    () =>
      filtered.map((event) => ({
        event,
        isNew: initialized && !seenIds.has(event.id),
      })),
    [filtered, initialized, seenIds],
  )

  return (
    <section className="pulse-feed" aria-label="Live security activity">
      <header className="pulse-feed-head">
        <h1 className="pulse-feed-title">Pulse</h1>
        <nav className="pulse-feed-tabs" role="tablist" aria-label="Pulse filters">
          <PulseTab label="All" tab="all" current={tab} count={counts.all} onSelect={setTab} />
          <PulseTab
            label="Critical"
            tab="critical"
            current={tab}
            count={counts.critical}
            flavor="critical"
            onSelect={setTab}
          />
          <PulseTab
            label="Patches"
            tab="patches"
            current={tab}
            count={counts.patches}
            flavor="patch"
            onSelect={setTab}
          />
          <PulseTab label="PRs" tab="prs" current={tab} count={counts.prs} flavor="pr" onSelect={setTab} />
        </nav>
      </header>

      {state === "loading" && flagged.length === 0 ? (
        <div className="pulse-feed-empty" role="status">
          Syncing repository activity...
        </div>
      ) : state === "error" ? (
        <div className="pulse-feed-empty" role="status">
          History unavailable. Retrying soon.
        </div>
      ) : flagged.length === 0 ? (
        <div className="pulse-feed-empty" role="status">
          {tab === "all"
            ? "No scans yet. Run a scan to populate the live pulse."
            : `No ${tabFilterLabel(tab)} events yet.`}
        </div>
      ) : (
        <ol className="pulse-feed-list" aria-live="polite">
          {flagged.map(({ event, isNew }) => (
            <li
              key={event.id}
              className="pulse-feed-item"
              data-new={isNew ? "true" : "false"}
              data-flavor={event.flavor}
            >
              <PulseEventContent event={event} now={now} />
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}

function PulseEventContent({ event, now }: { event: PulseEvent; now: number }) {
  const body = (
    <div className="pulse-feed-item-inner">
      <div className="pulse-feed-time" aria-hidden="false">
        <span className="pulse-feed-time-abs mono">{formatAbsolute(event.timestamp)}</span>
        <span className="pulse-feed-time-rel mono">{formatRelative(event.timestamp, now)}</span>
      </div>
      <div className="pulse-feed-body">
        <p className="pulse-feed-headline">
          <span className="pulse-feed-label" data-flavor={event.flavor}>
            {event.label}
          </span>
          <span className="pulse-feed-prep"> {event.preposition} </span>
          <code className="pulse-feed-repo" data-flavor={event.flavor}>
            {event.repo}
          </code>
          <span className="pulse-feed-divider"> - </span>
          <span className="pulse-feed-summary">{event.summary}</span>
        </p>
        <p className="pulse-feed-meta">
          <span className="pulse-feed-source mono">{event.source}</span>
          <span className="pulse-feed-meta-dot mono" aria-hidden="true">
            /
          </span>
          <code className="pulse-feed-scan-ref mono">{event.scanRef}</code>
        </p>
      </div>
    </div>
  )

  if (!event.href) return body

  if (event.external) {
    return (
      <a className="pulse-feed-link" href={event.href} rel="noreferrer" target="_blank">
        {body}
      </a>
    )
  }

  return (
    <Link className="pulse-feed-link" href={event.href}>
      {body}
    </Link>
  )
}

function PulseTab({
  label,
  tab,
  current,
  count,
  flavor,
  onSelect,
}: {
  label: string
  tab: TabKey
  current: TabKey
  count: number
  flavor?: EventFlavor
  onSelect: (next: TabKey) => void
}) {
  const active = current === tab
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      data-active={active}
      data-flavor={flavor ?? "neutral"}
      className="pulse-feed-tab"
      onClick={() => onSelect(tab)}
    >
      <span>{label}</span>
      <span className="pulse-feed-tab-count">{count}</span>
    </button>
  )
}

function buildEvents(reports: ScanReport[]): PulseEvent[] {
  const events: PulseEvent[] = []
  const sorted = [...reports].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())

  for (const report of sorted) {
    const repo = pickRepoName(report)
    const scanRef = pickScanRef(report)
    const source = pickSource(report)
    const baseTs = report.createdAt
    const reportHref = `/report/${report.id}`

    if (report.status === "running" || report.status === "queued") {
      events.push({
        id: `${report.id}-scan-started`,
        kind: "scan_started",
        flavor: "scan-pending",
        label: "Scan started",
        preposition: "on",
        repo,
        summary: `${report.analysisMode} mode`,
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
      continue
    }

    if (report.status === "failed") {
      events.push({
        id: `${report.id}-scan-failed`,
        kind: "scan_failed",
        flavor: "critical",
        label: "Scan failed",
        preposition: "on",
        repo,
        summary: report.error ? trimSummary(report.error) : "review required",
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
      continue
    }

    const findings = (report.findings ?? []).filter((finding) => !finding.suppressed)
    const criticals = findings.filter((finding) => finding.severity === "critical")
    const highs = findings.filter((finding) => finding.severity === "high")
    const mediums = findings.filter((finding) => finding.severity === "medium")
    const lows = findings.filter((finding) => finding.severity === "low")
    const patchable = findings.filter((finding) => finding.patchable)
    const aboveLow = criticals.length + highs.length + mediums.length

    if (criticals.length > 0) {
      const firstCritical = criticals[0]
      events.push({
        id: `${report.id}-critical`,
        kind: "critical_finding",
        flavor: "critical",
        label: "Critical finding detected",
        preposition: "on",
        repo,
        summary: summariseCriticals(criticals),
        source,
        scanRef,
        timestamp: baseTs,
        href: firstCritical ? `${reportHref}#${firstCritical.id}` : reportHref,
        severity: "critical",
      })
    }

    if (patchable.length > 0) {
      events.push({
        id: `${report.id}-patches`,
        kind: "patch_preview",
        flavor: "patch",
        label: "Patch preview available",
        preposition: "for",
        repo,
        summary: `${patchable.length} ${patchable.length === 1 ? "fix" : "fixes"} ready for review`,
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
    }

    if (report.pullRequest) {
      events.push({
        id: `${report.id}-pr`,
        kind: "pull_request",
        flavor: "pr",
        label: "GitHub PR created",
        preposition: "on",
        repo,
        summary: report.pullRequest.branch,
        source,
        scanRef,
        timestamp: report.pullRequest.createdAt,
        href: report.pullRequest.url,
        external: true,
      })
    }

    if (aboveLow === 0 && lows.length > 0) {
      events.push({
        id: `${report.id}-low-risk`,
        kind: "low_risk",
        flavor: "low",
        label: "Low-risk report completed",
        preposition: "on",
        repo,
        summary: "no findings above low",
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
    } else if (aboveLow === 0 && lows.length === 0) {
      events.push({
        id: `${report.id}-clean`,
        kind: "low_risk",
        flavor: "low",
        label: "Scan completed",
        preposition: "on",
        repo,
        summary: "no active findings",
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
    } else {
      const breakdown = [
        criticals.length ? `${criticals.length} critical` : null,
        highs.length ? `${highs.length} high` : null,
        mediums.length ? `${mediums.length} medium` : null,
        lows.length ? `${lows.length} low` : null,
      ]
        .filter(Boolean)
        .join(" / ")

      events.push({
        id: `${report.id}-scan-completed`,
        kind: "scan_completed",
        flavor: "scan",
        label: "Scan completed",
        preposition: "on",
        repo,
        summary: breakdown || "no active findings",
        source,
        scanRef,
        timestamp: baseTs,
        href: reportHref,
      })
    }
  }

  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  return events.slice(0, MAX_EVENTS)
}

function summariseCriticals(findings: ScanFinding[]) {
  const counts = new Map<FindingCategory, number>()
  for (const finding of findings) {
    counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1)
  }

  const fragments: string[] = []
  for (const [category, count] of counts) {
    fragments.push(`${count} ${labelForCategory(category, count)}`)
    if (fragments.length >= 3) break
  }

  return fragments.join(", ")
}

function labelForCategory(category: FindingCategory, count: number): string {
  const single = singularLabel(category)
  if (count === 1) return single
  return pluralizeLabel(single)
}

function singularLabel(category: FindingCategory): string {
  switch (category) {
    case "secret_exposure":
      return "secret"
    case "public_env_misuse":
      return "public env misuse"
    case "dependency_vulnerability":
      return "dependency vulnerability"
    case "broken_access_control":
      return "access control issue"
    case "missing_auth":
    case "missing_authentication":
      return "unauthenticated route"
    case "missing_authorization":
      return "authorization issue"
    case "ai_endpoint_risk":
      return "exposed AI endpoint"
    case "ai_prompt_injection_risk":
      return "prompt injection risk"
    case "ai_excessive_agency":
      return "excessive agency risk"
    case "ai_unbounded_consumption":
      return "unbounded AI consumption risk"
    case "unsafe_tool_calling":
      return "unsafe tool call"
    case "mcp_risk":
      return "MCP risk"
    case "input_validation":
      return "input validation issue"
    case "sql_injection":
      return "SQL injection risk"
    case "command_injection":
      return "command injection risk"
    case "ssrf":
      return "SSRF risk"
    case "xss":
      return "XSS risk"
    case "unsafe_redirect":
      return "unsafe redirect"
    case "csrf":
      return "CSRF risk"
    case "insecure_cookie":
      return "insecure cookie"
    case "client_data_exposure":
      return "client data exposure"
    case "dangerous_code":
      return "dangerous code path"
    case "server_action_risk":
      return "server action risk"
    case "supabase_rls_risk":
      return "Supabase RLS risk"
    case "repo_security_posture":
      return "repo posture issue"
    case "supply_chain_posture":
      return "supply-chain posture issue"
    case "platform_hardening":
    case "vercel_hardening":
      return "hardening gap"
    case "dependency_signal":
      return "dependency signal"
    default:
      return String(category).replace(/_/g, " ")
  }
}

function pluralizeLabel(label: string): string {
  if (/(s|x|z|ch|sh)$/.test(label)) return `${label}es`
  if (label.endsWith("y") && !/[aeiou]y$/.test(label)) return `${label.slice(0, -1)}ies`
  return `${label}s`
}

function pickRepoName(report: ScanReport): string {
  if (report.repository) return `${report.repository.owner}/${report.repository.repo}`
  if (report.projectName) return report.projectName
  return "repository"
}

function pickScanRef(report: ScanReport): string {
  const ref = report.repository?.ref || report.repository?.defaultBranch
  if (ref && ref.length <= 18) return ref
  return `scan ${report.id.replace(/-/g, "").slice(0, 7)}`
}

function pickSource(report: ScanReport): string {
  const mode = report.analysisMode === "max" ? "max" : report.analysisMode === "rules" ? "rules" : "normal"
  if (report.repository?.private) return `${mode} / private repo`
  return `${mode} / GitHub API`
}

function tabFilterLabel(tab: TabKey): string {
  if (tab === "critical") return "critical"
  if (tab === "patches") return "patch"
  if (tab === "prs") return "pull request"
  return "activity"
}

function trimSummary(value: string): string {
  if (value.length <= 96) return value
  return `${value.slice(0, 93)}...`
}

function formatAbsolute(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return "--:--"
  return date.toISOString().slice(11, 16)
}

function formatRelative(iso: string, nowMs: number): string {
  const ts = new Date(iso).getTime()
  if (Number.isNaN(ts)) return "live"

  const diffMs = Math.max(0, nowMs - ts)
  const seconds = Math.floor(diffMs / 1000)
  if (seconds < 30) return "just now"
  if (seconds < 60) return `${seconds}s ago`

  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`

  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`

  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`

  const weeks = Math.floor(days / 7)
  return `${weeks}w ago`
}
