import Link from "next/link"
import { headers } from "next/headers"
import { Icon } from "../_components/icons"
import { listScanReports } from "@/lib/scanner/store"
import { getRequestIdentityFromHeaders } from "@/lib/security/request"
import type { ScanReport } from "@/lib/scanner/types"

export const dynamic = "force-dynamic"

export default async function ScansPage() {
  const identity = await getRequestIdentityFromHeaders(await headers())
  const reports = await listScanReports(identity.subjectHash)

  if (reports.length === 0) {
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
        </div>
        <div className="page-pad">
          <div className="empty-state">
            <div className="empty-icon">
              <Icon.scan style={{ width: 28, height: 28 }} />
            </div>
            <h2 className="empty-title">No scans yet</h2>
            <p className="empty-sub">Login with GitHub, scan a public GitHub repo, or run the bundled vulnerable demo.</p>
            <div className="empty-actions">
              <Link href="/scan" className="btn btn-accent btn-lg">
                <Icon.bolt style={{ width: 14, height: 14 }} /> Start security scan
              </Link>
              <Link href="/report/demo" className="btn btn-outline btn-lg">
                View demo report
              </Link>
            </div>
          </div>
        </div>
      </>
    )
  }

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

      <div className="page-pad">
        <h1 className="page-title">
          Scans <em>history</em>
        </h1>
        <div className="page-sub">
          <span>
            <b>{reports.length}</b> stored in this demo session
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
                  {counts.critical > 0 && (
                    <span className="sev sev-critical">
                      <span className="dot" />
                      {counts.critical}
                    </span>
                  )}
                  {counts.high > 0 && (
                    <span className="sev sev-high">
                      <span className="dot" />
                      {counts.high}
                    </span>
                  )}
                  {counts.medium > 0 && (
                    <span className="sev sev-medium">
                      <span className="dot" />
                      {counts.medium}
                    </span>
                  )}
                  {counts.low + counts.info > 0 && (
                    <span className="sev sev-low">
                      <span className="dot" />
                      {counts.low + counts.info}
                    </span>
                  )}
                  {report.findings.length === 0 && (
                    <span className="sev sev-low">
                      <span className="dot" />
                      clean
                    </span>
                  )}
                </div>
                <div className="scan-cell-time">
                  <span className="mono dim">{formatDate(report.createdAt)}</span>
                </div>
              </Link>
            )
          })}
        </div>
      </div>
    </>
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
