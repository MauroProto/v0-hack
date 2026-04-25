"use client"

import { useMemo, useState } from "react"
import { Icon } from "@/app/(app)/_components/icons"
import { generateIssueBody, getRiskLabel } from "@/lib/scanner/patches"
import type { AuditTrailEvent, FindingCategory, ScanFinding, ScanReport, Severity } from "@/lib/scanner/types"

export function ScanResultsClient({ initialReport, authToken }: { initialReport: ScanReport; authToken?: string | null }) {
  const [report, setReport] = useState(initialReport)
  const [loadingAi, setLoadingAi] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const counts = useMemo(() => countSeverities(report.findings), [report.findings])

  const generateFixes = async () => {
    setError(null)
    setLoadingAi(true)
    try {
      const response = await fetch(`/api/scan/${report.id}/explain`, {
        method: "POST",
        headers: authHeaders(authToken),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Could not generate AI explanations.")
      setReport(data.report)
    } catch (aiError) {
      setError(aiError instanceof Error ? aiError.message : "Could not generate AI explanations.")
    } finally {
      setLoadingAi(false)
    }
  }

  const copyIssueBody = async () => {
    await navigator.clipboard.writeText(generateIssueBody(report))
    setCopied("issue")
    window.setTimeout(() => setCopied(null), 1600)
  }

  const copyShareLink = async () => {
    await navigator.clipboard.writeText(window.location.href)
    setCopied("share")
    window.setTimeout(() => setCopied(null), 1600)
  }

  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>{report.projectName}</span>
          <span className="sep">/</span>
          <span>
            <b>scan {report.id}</b>
          </span>
        </div>
        <div className="actions">
          <button className="btn btn-outline" onClick={copyShareLink} type="button">
            <Icon.share style={{ width: 14, height: 14 }} /> <span>{copied === "share" ? "Copied" : "Copy report link"}</span>
          </button>
          <button className="btn btn-outline" onClick={copyIssueBody} type="button">
            <Icon.doc style={{ width: 14, height: 14 }} /> <span>{copied === "issue" ? "Copied" : "Copy GitHub issue body"}</span>
          </button>
          <button className="btn btn-accent" onClick={generateFixes} disabled={loadingAi} type="button">
            <Icon.wand style={{ width: 14, height: 14 }} /> <span>{loadingAi ? "Generating..." : "Generate AI fixes"}</span>
          </button>
        </div>
      </div>

      <div className="page-pad">
        <div className="page-grid">
          <div className="page-main">
            <h1 className="page-title">
              Security report <em>{report.framework ?? "static project"}</em>
            </h1>
            <div className="page-sub">
              <span>
                <b>{report.sourceType}</b>
              </span>
              <span>·</span>
              <span>{report.sourceLabel}</span>
              <span>·</span>
              <span>{formatDate(report.createdAt)}</span>
              <span>·</span>
              <span className="accent">{report.filesInspected} files inspected</span>
            </div>

            {error && (
              <div className="scan-error scan-error-report" role="alert">
                <Icon.focus style={{ width: 14, height: 14 }} />
                <span>{error}</span>
              </div>
            )}

            <div className="app-score-row">
              <div className="score-card score-main app-score-card">
                <div className="lbl">Risk score</div>
                <div className="score-main-body">
                  <div>
                    <div className="val val-lg">
                      {report.riskScore} <small>/ 100</small>
                    </div>
                    <div className="sub">{getRiskLabel(report.riskScore)}</div>
                  </div>
                  <ScoreRing value={report.riskScore} tone={scoreTone(report.riskScore)} />
                </div>
              </div>
              <div className="score-card sev-crit app-score-card">
                <div className="lbl">Critical</div>
                <div className="val val-lg">{counts.critical}</div>
                <div className="sub">Secrets and deploy blockers</div>
              </div>
              <div className="score-card sev-med app-score-card">
                <div className="lbl">High · Medium</div>
                <div className="val val-lg">
                  {counts.high} <small>/ {counts.medium}</small>
                </div>
                <div className="sub">Auth, AI endpoint and validation gaps</div>
              </div>
              <div className="score-card sev-low app-score-card">
                <div className="lbl">Low · Info</div>
                <div className="val val-lg">{counts.low + counts.info}</div>
                <div className="sub">Production hardening notes</div>
              </div>
            </div>

            <div className="app-findings-head">
              <h4>Findings</h4>
              <div className="filter">
                <span className="chip" data-active="true">
                  All <span className="n">{report.findings.length}</span>
                </span>
                <span className="chip">
                  Critical <span className="n">{counts.critical}</span>
                </span>
                <span className="chip">
                  AI risks <span className="n">{countCategory(report.findings, "ai_endpoint_risk")}</span>
                </span>
                <span className="chip">
                  Secrets <span className="n">{countCategory(report.findings, "secret_exposure")}</span>
                </span>
                <span className="chip">
                  Routes <span className="n">{report.apiRoutesInspected}</span>
                </span>
              </div>
            </div>

            <div className="findings real-findings">
              {report.findings.length === 0 ? (
                <div className="finding-empty">
                  <Icon.shield style={{ width: 22, height: 22 }} />
                  <div>
                    <b>No deterministic findings.</b>
                    <span>Static rules did not find obvious issues in the supported files.</span>
                  </div>
                </div>
              ) : (
                report.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)
              )}
            </div>
          </div>

          <aside className="right-rail">
            <div className="agent-head">
              <h4>Scan agent</h4>
              <span className="live">
                <span className="dot" /> {report.status}
              </span>
            </div>

            <div className="scan-side-stats">
              <div>
                <span>API routes</span>
                <b>{report.apiRoutesInspected}</b>
              </div>
              <div>
                <span>Client components</span>
                <b>{report.clientComponentsInspected}</b>
              </div>
              <div>
                <span>AI endpoints</span>
                <b>{report.aiEndpointsInspected}</b>
              </div>
            </div>

            <div className="timeline">
              {report.auditTrail.map((event) => (
                <TimelineItem key={event.id} event={event} />
              ))}
            </div>
          </aside>
        </div>
      </div>
    </>
  )
}

function FindingCard({ finding }: { finding: ScanFinding }) {
  const findingIcon = renderFindingIcon(finding)

  return (
    <div className="finding real-finding" id={finding.id}>
      <div className="ico">
        {findingIcon}
      </div>
      <div className={`sev sev-${finding.severity === "info" ? "low" : finding.severity}`}>
        <span className="dot" />
        {finding.severity}
      </div>
      <div className="real-finding-body">
        <div className="msg">{finding.title}</div>
        <div className="path">
          {finding.filePath}
          {finding.lineStart && <b>:{finding.lineStart}</b>}
        </div>
        <div className="finding-facts">
          <span>{labelForCategory(finding.category)}</span>
          <span>{Math.round(finding.confidence * 100)}% confidence</span>
          <span>{finding.source}</span>
        </div>
        {finding.evidence && (
          <div className="finding-evidence">
            <b>Evidence</b>
            <code>{finding.evidence}</code>
          </div>
        )}
        <p className="finding-recommendation">{finding.recommendation}</p>
        {finding.explanation && (
          <div className="finding-ai">
            <b>AI explanation</b>
            <span>{finding.explanation.summary}</span>
            <span>{finding.explanation.impact}</span>
          </div>
        )}
        {finding.patch && (
          <div className="patch-preview">
            <div className="patch-preview-head">
              <span>{finding.patch.title}</span>
              <em>review required</em>
            </div>
            <p>{finding.patch.summary}</p>
            {finding.patch.unifiedDiff && <pre>{finding.patch.unifiedDiff}</pre>}
          </div>
        )}
      </div>
      <div className="meta">{finding.id}</div>
    </div>
  )
}

function ScoreRing({ value, tone }: { value: number; tone: "ok" | "warn" | "danger" }) {
  const radius = 26
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - value / 100)
  const stroke = tone === "danger" ? "var(--danger)" : tone === "warn" ? "var(--warn)" : "var(--accent)"

  return (
    <svg width="68" height="68" viewBox="0 0 68 68" aria-hidden="true">
      <circle cx="34" cy="34" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="4" />
      <circle
        cx="34"
        cy="34"
        r={radius}
        fill="none"
        stroke={stroke}
        strokeWidth="4"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 34 34)"
      />
      <text x="34" y="38" textAnchor="middle" fill={stroke} fontSize="14" fontFamily="var(--font-mono)" fontWeight="500">
        {value}
      </text>
    </svg>
  )
}

function TimelineItem({ event }: { event: AuditTrailEvent }) {
  const state = event.status === "complete" ? "done" : event.status === "running" ? "active" : "pending"
  return (
    <div className="tl-item" data-state={state}>
      <div className="tl-title">{event.label}</div>
      {event.metadata && <div className="tl-sub">{formatMetadata(event.metadata)}</div>}
      <div className="tl-time">{formatTime(event.timestamp)}</div>
    </div>
  )
}

function countSeverities(findings: ScanFinding[]) {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1
      return counts
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>,
  )
}

function countCategory(findings: ScanFinding[], category: FindingCategory) {
  return findings.filter((finding) => finding.category === category).length
}

function scoreTone(score: number): "ok" | "warn" | "danger" {
  if (score >= 50) return "danger"
  if (score >= 20) return "warn"
  return "ok"
}

function renderFindingIcon(finding: ScanFinding) {
  if (finding.category === "secret_exposure" || finding.category === "public_env_misuse") return <Icon.key />
  if (finding.category === "missing_auth" || finding.category === "client_data_exposure") return <Icon.lock />
  if (finding.category === "ai_endpoint_risk") return <Icon.bolt />
  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk" || finding.category === "dangerous_code") return <Icon.terminal />
  if (finding.category === "input_validation") return <Icon.brackets />
  return <Icon.doc />
}

function labelForCategory(category: FindingCategory) {
  return category.replaceAll("_", " ")
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value))
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value))
}

function formatMetadata(metadata: Record<string, unknown>) {
  return Object.entries(metadata)
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join(" · ")
}

function authHeaders(accessToken?: string | null) {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined
}
