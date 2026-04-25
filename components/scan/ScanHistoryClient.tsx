"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import type { Session } from "@supabase/supabase-js"
import { Icon } from "@/app/(app)/_components/icons"
import { createBrowserSupabaseClient } from "@/lib/supabase/client"
import type { ScanReport } from "@/lib/scanner/types"

export function ScanHistoryClient() {
  const supabase = useMemo(() => createBrowserSupabaseClient(), [])
  const [session, setSession] = useState<Session | null>(null)
  const [sessionChecked, setSessionChecked] = useState(!supabase)
  const [reports, setReports] = useState<ScanReport[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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

    async function loadReports() {
      setLoading(true)
      setError(null)

      try {
        const response = await fetch("/api/scans", {
          headers: authHeaders(session?.access_token),
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error ?? "Could not load scan history.")
        setReports(data.reports ?? [])
      } catch (loadError) {
        if (controller.signal.aborted) return
        setError(loadError instanceof Error ? loadError.message : "Could not load scan history.")
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadReports()

    return () => controller.abort()
  }, [session?.access_token, sessionChecked])

  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>
            <b>Scans</b>
          </span>
        </div>
        <div className="actions">
          <Link className="btn btn-accent" href="/scan">
            <Icon.bolt style={{ width: 14, height: 14 }} /> <span>Start new scan</span>
          </Link>
        </div>
      </div>

      {loading || error || reports.length === 0 ? (
        <ScanHistoryState loading={loading} error={error} />
      ) : (
        <ScanHistoryTable reports={reports} />
      )}
    </>
  )
}

function ScanHistoryState({ loading, error }: { loading: boolean; error: string | null }) {
  return (
    <div className="page-pad">
      <div className="empty-state">
        <div className="empty-icon">
          <Icon.scan style={{ width: 28, height: 28 }} />
        </div>
        <h2 className="empty-title">{loading ? "Loading scans" : error ? "Could not load scans" : "No scans yet"}</h2>
        <p className="empty-sub">
          {loading
            ? "Fetching reports for your current browser session."
            : error ?? "Login with GitHub or scan a public GitHub repo to create your first report."}
        </p>
        {!loading && (
          <div className="empty-actions">
            <Link href="/scan" className="btn btn-accent btn-lg">
              <Icon.bolt style={{ width: 14, height: 14 }} /> Start security scan
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}

function ScanHistoryTable({ reports }: { reports: ScanReport[] }) {
  return (
    <div className="page-pad">
      <h1 className="page-title">
        Scans <em>history</em>
      </h1>
      <div className="page-sub">
        <span>
          <b>{reports.length}</b> available for this identity
        </span>
        <span>·</span>
        <span>static analysis only</span>
      </div>

      <div className="scan-table">
        <div className="scan-table-head">
          <div>Project</div>
          <div>Source</div>
          <div>Risk</div>
          <div>Findings</div>
          <div>When</div>
        </div>
        {reports.map((report) => {
          const counts = countSeverities(report)
          return (
            <Link key={report.id} href={`/report/${report.id}`} className="scan-row">
              <div className="scan-cell-repo">
                <div className="scan-repo">{report.projectName}</div>
                <div className="scan-branch mono">{report.framework ?? report.sourceType}</div>
              </div>
              <div className="scan-cell-commit mono">{report.sourceLabel}</div>
              <div className="scan-cell-score">
                <span className="dt-score" data-tone={scoreTone(report.riskScore)}>
                  {report.riskScore}
                </span>
              </div>
              <div className="scan-cell-counts">
                {counts.critical > 0 && <SeverityCount severity="critical" count={counts.critical} />}
                {counts.high > 0 && <SeverityCount severity="high" count={counts.high} />}
                {counts.medium > 0 && <SeverityCount severity="medium" count={counts.medium} />}
                {counts.low + counts.info > 0 && <SeverityCount severity="low" count={counts.low + counts.info} />}
                {report.findings.length === 0 && <SeverityCount severity="low" count="clean" />}
              </div>
              <div className="scan-cell-time">
                <span className="mono dim">{formatDate(report.createdAt)}</span>
              </div>
            </Link>
          )
        })}
      </div>
    </div>
  )
}

function SeverityCount({ severity, count }: { severity: "critical" | "high" | "medium" | "low"; count: number | string }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span className="dot" />
      {count}
    </span>
  )
}

function countSeverities(report: ScanReport) {
  return report.findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1
      return counts
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  )
}

function scoreTone(score: number) {
  if (score >= 50) return "danger"
  if (score >= 20) return "warn"
  return "ok"
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value))
}

function authHeaders(accessToken?: string | null) {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined
}
