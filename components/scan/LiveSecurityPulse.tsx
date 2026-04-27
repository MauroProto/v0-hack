"use client"

import Link from "next/link"
import { useEffect, useMemo, useState, type CSSProperties } from "react"
import { Icon } from "@/app/(app)/_components/icons"
import type { ScanFinding, ScanReport, Severity } from "@/lib/scanner/types"

type PulseEventKind = "scan" | "finding" | "patch" | "pull_request" | "idle"

type PulseEvent = {
  id: string
  kind: PulseEventKind
  repo: string
  message: string
  detail: string
  href?: string
  filePath?: string
  severity?: Severity
  timestamp?: string
}

const MAX_EVENTS = 8
const MIN_STREAM_LINES = 8

export function LiveSecurityPulse({ reports: initialReports }: { reports?: ScanReport[] }) {
  const [reports, setReports] = useState<ScanReport[]>(initialReports ?? [])
  const [state, setState] = useState<"loading" | "ready" | "error">(initialReports ? "ready" : "loading")
  const visibleReports = initialReports ?? reports

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
        if (!response.ok) throw new Error(data.error ?? "Could not load live scan activity.")
        if (cancelled) return
        setReports(data.reports ?? [])
        setState("ready")
      } catch {
        if (cancelled || controller?.signal.aborted) return
        setState("error")
      }
    }

    void loadReports()
    const interval = window.setInterval(loadReports, 45000)

    return () => {
      cancelled = true
      controller?.abort()
      window.clearInterval(interval)
    }
  }, [initialReports])

  const events = useMemo(() => buildPulseEvents(visibleReports), [visibleReports])
  const stream = useMemo(() => expandStream(events), [events])
  const criticalCount = visibleReports.reduce(
    (count, report) => count + report.findings.filter((finding) => finding.severity === "critical").length,
    0,
  )

  return (
    <section className="live-pulse" aria-label="Live security activity">
      <div className="live-pulse-head">
        <div>
          <span className="live-pulse-kicker">
            <span className="live-pulse-dot" />
            Live pulse
          </span>
          <h2>
            Repository activity <em>stream</em>
          </h2>
        </div>
        <div className="live-pulse-meta" aria-label="Pulse status">
          <span>{state === "loading" ? "syncing" : state === "error" ? "history unavailable" : `${visibleReports.length} reports`}</span>
          <span>{criticalCount} critical</span>
        </div>
      </div>

      <div className="pulse-stage" aria-live="off">
        {stream.map((event, index) => (
          <PulseLine event={event} index={index} key={`${event.id}-${index}`} />
        ))}
      </div>
    </section>
  )
}

function PulseLine({ event, index }: { event: PulseEvent; index: number }) {
  const row = index % 8
  const duration = 36 + (index % 5) * 5
  const style = {
    "--pulse-row": row,
    "--pulse-delay": `${index * -4.2}s`,
    "--pulse-duration": `${duration}s`,
    "--pulse-width": `${64 + (index % 3) * 9}%`,
    "--pulse-nudge": `${(index % 4) * 2}%`,
  } as CSSProperties

  const content = (
    <>
      <span className="pulse-line-glow" aria-hidden="true" />
      <span className="pulse-kind">
        <PulseIcon kind={event.kind} />
      </span>
      <span className="pulse-time mono">{formatTime(event.timestamp)}</span>
      <span className="pulse-copy">
        <b>{event.repo}</b>
        <span>{event.message}</span>
      </span>
      <span className="pulse-detail mono">{event.filePath ?? event.detail}</span>
    </>
  )

  if (event.href?.startsWith("http")) {
    return (
      <a
        className="pulse-line"
        data-kind={event.kind}
        data-severity={event.severity ?? "info"}
        href={event.href}
        rel="noreferrer"
        style={style}
        target="_blank"
      >
        {content}
      </a>
    )
  }

  if (event.href) {
    return (
      <Link
        className="pulse-line"
        data-kind={event.kind}
        data-severity={event.severity ?? "info"}
        href={event.href}
        style={style}
      >
        {content}
      </Link>
    )
  }

  return (
    <div className="pulse-line" data-kind={event.kind} data-severity={event.severity ?? "info"} style={style}>
      {content}
    </div>
  )
}

function PulseIcon({ kind }: { kind: PulseEventKind }) {
  if (kind === "pull_request") return <Icon.branch />
  if (kind === "patch") return <Icon.code />
  if (kind === "finding") return <Icon.focus />
  if (kind === "scan") return <Icon.scan />
  return <Icon.shield />
}

function buildPulseEvents(reports: ScanReport[]) {
  const events: PulseEvent[] = []
  const sortedReports = [...reports].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())

  for (const report of sortedReports) {
    const href = `/report/${report.id}`
    const repo = report.projectName || report.repository?.repo || "Repository"
    const topFindings = [...report.findings]
      .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
      .slice(0, 3)

    events.push({
      id: `${report.id}-scan`,
      kind: "scan",
      repo,
      message: `${report.riskScore}/100 risk score`,
      detail: `${report.filesInspected} files · ${report.analysisMode} mode`,
      href,
      timestamp: report.createdAt,
    })

    for (const finding of topFindings) {
      events.push(findingToPulseEvent(report, finding, href, repo))
    }

    const patchableCount = report.findings.filter((finding) => finding.patchable).length
    if (patchableCount > 0) {
      events.push({
        id: `${report.id}-patches`,
        kind: "patch",
        repo,
        message: `${patchableCount} review-required fixes ready`,
        detail: "patch preview",
        href,
        timestamp: report.createdAt,
      })
    }

    if (report.pullRequest) {
      events.push({
        id: `${report.id}-pr`,
        kind: "pull_request",
        repo,
        message: `pull request #${report.pullRequest.number} created`,
        detail: report.pullRequest.branch,
        href: report.pullRequest.url,
        timestamp: report.pullRequest.createdAt,
      })
    }
  }

  if (events.length === 0) {
    return [
      {
        id: "waiting-for-real-scans",
        kind: "idle",
        repo: "VibeShield",
        message: "waiting for the first real scan",
        detail: "no synthetic findings",
      },
    ] satisfies PulseEvent[]
  }

  return events.slice(0, MAX_EVENTS)
}

function findingToPulseEvent(report: ScanReport, finding: ScanFinding, href: string, repo: string): PulseEvent {
  const severity = finding.severity
  const category = finding.category.replace(/_/g, " ")
  const line = finding.lineStart ? `:${finding.lineStart}` : ""

  return {
    id: `${report.id}-${finding.id}`,
    kind: "finding",
    repo,
    message: `${severity} ${category}`,
    detail: finding.title,
    href: `${href}#${finding.id}`,
    filePath: `${finding.filePath}${line}`,
    severity,
    timestamp: report.createdAt,
  }
}

function expandStream(events: PulseEvent[]) {
  if (events.length >= MIN_STREAM_LINES) return events
  const expanded: PulseEvent[] = []

  while (expanded.length < MIN_STREAM_LINES) {
    expanded.push(...events)
  }

  return expanded.slice(0, MIN_STREAM_LINES)
}

function severityWeight(severity: Severity) {
  if (severity === "critical") return 5
  if (severity === "high") return 4
  if (severity === "medium") return 3
  if (severity === "low") return 2
  return 1
}

function formatTime(value?: string) {
  if (!value) return "live"

  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value))
}
