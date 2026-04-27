"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import type { ReactNode, WheelEvent } from "react"
import { Icon } from "@/app/(app)/_components/icons"
import { generateIssueBody, getRiskLabel } from "@/lib/scanner/patches"
import type { AuditTrailEvent, FindingCategory, ScanFinding, ScanPullRequest, ScanReport, Severity } from "@/lib/scanner/types"

type SelectionMode = "issue" | "pull_request"

export function ScanResultsClient({
  initialReport,
  githubConnected,
}: {
  initialReport: ScanReport
  githubConnected?: boolean
}) {
  const [report, setReport] = useState(initialReport)
  const [loadingAi, setLoadingAi] = useState(false)
  const [creatingPr, setCreatingPr] = useState(false)
  const [pullRequest, setPullRequest] = useState<ScanPullRequest | undefined>(initialReport.pullRequest)
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectionMode, setSelectionMode] = useState<SelectionMode | null>(null)
  const [detailFindingId, setDetailFindingId] = useState<string | null>(null)
  const findingIds = useMemo(() => report.findings.map((finding) => finding.id), [report.findings])
  const findingIdSet = useMemo(() => new Set(findingIds), [findingIds])
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>(() => initialReport.findings.map((finding) => finding.id))
  const counts = useMemo(() => countSeverities(report.findings), [report.findings])
  const detailFinding = useMemo(
    () => report.findings.find((finding) => finding.id === detailFindingId),
    [detailFindingId, report.findings],
  )
  const activeSelectedFindingIds = useMemo(
    () => selectedFindingIds.filter((findingId) => findingIdSet.has(findingId)),
    [findingIdSet, selectedFindingIds],
  )
  const selectedCount = activeSelectedFindingIds.length
  const outsidePrimaryCoverage = isOutsidePrimaryCoverage(report)

  const generateFixes = async () => {
    setError(null)
    setLoadingAi(true)
    try {
      const response = await fetch(`/api/scan/${report.id}/explain`, {
        method: "POST",
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

  const openSelection = (mode: SelectionMode) => {
    setError(null)
    if (report.findings.length === 0) {
      setError("There are no findings to include.")
      return
    }

    if (activeSelectedFindingIds.length === 0 || activeSelectedFindingIds.length !== selectedFindingIds.length) {
      setSelectedFindingIds(findingIds)
    }

    setSelectionMode(mode)
  }

  const createPullRequest = async (findingIdsToInclude: string[]) => {
    setError(null)

    if (!githubConnected) {
      setError("Login with GitHub and scan a repository from your account before creating a PR.")
      return
    }

    if (findingIdsToInclude.length === 0) {
      setError("Select at least one finding before creating a PR.")
      return
    }

    setCreatingPr(true)
    try {
      const response = await fetch(`/api/scan/${report.id}/pull-request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ findingIds: findingIdsToInclude }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error ?? "Could not create GitHub PR.")
      setReport(data.report)
      setPullRequest(data.pullRequest)
      setSelectionMode(null)
    } catch (prError) {
      setError(prError instanceof Error ? prError.message : "Could not create GitHub PR.")
    } finally {
      setCreatingPr(false)
    }
  }

  const copyIssueBody = async (findingIdsToInclude: string[]) => {
    if (findingIdsToInclude.length === 0) {
      setError("Select at least one finding before copying an issue body.")
      return
    }

    await navigator.clipboard.writeText(generateIssueBody(report, findingIdsToInclude))
    setCopied("issue")
    setSelectionMode(null)
    window.setTimeout(() => setCopied(null), 2500)
  }

  const copyShareLink = async () => {
    await navigator.clipboard.writeText(window.location.href)
    setCopied("share")
    window.setTimeout(() => setCopied(null), 2500)
  }

  const openFindingDetail = (findingId: string) => {
    setDetailFindingId(findingId)
    if (typeof window !== "undefined") {
      window.history.replaceState(null, "", `#${findingId}`)
    }
  }

  const closeFindingDetail = () => {
    setDetailFindingId(null)
    if (typeof window !== "undefined" && window.location.hash) {
      window.history.replaceState(null, "", window.location.pathname)
    }
  }

  const copyDetailText = async (kind: string, value: string) => {
    setCopied(kind)
    window.setTimeout(() => setCopied(null), 3000)

    try {
      await navigator.clipboard.writeText(value)
    } catch {
      // Keep the action responsive even when browser clipboard permission is unavailable.
    }
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
          <button className="btn btn-outline" onClick={() => openSelection("issue")} type="button">
            <Icon.doc style={{ width: 14, height: 14 }} /> <span>{copied === "issue" ? "Copied" : "Copy GitHub issue body"}</span>
          </button>
          <button className="btn btn-outline" onClick={generateFixes} disabled={loadingAi} type="button">
            <Icon.wand style={{ width: 14, height: 14 }} /> <span>{loadingAi ? "Generating..." : "Generate patch previews"}</span>
          </button>
          {pullRequest ? (
            <a className="btn btn-accent" href={pullRequest.url} target="_blank" rel="noreferrer">
              <Icon.branch style={{ width: 14, height: 14 }} /> <span>Open PR #{pullRequest.number}</span>
            </a>
          ) : (
            <button className="btn btn-accent" onClick={() => openSelection("pull_request")} disabled={creatingPr} type="button">
              <Icon.branch style={{ width: 14, height: 14 }} /> <span>{creatingPr ? "Creating PR..." : "Create GitHub PR"}</span>
            </button>
          )}
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
              <span className="accent">{formatAnalysisMode(report.analysisMode)} mode</span>
              <span>·</span>
              <span className="accent">{report.filesInspected} files inspected</span>
            </div>

            {error && (
              <div className="scan-error scan-error-report" role="alert">
                <Icon.focus style={{ width: 14, height: 14 }} />
                <span>{error}</span>
              </div>
            )}

            {outsidePrimaryCoverage && (
              <div className="coverage-note">
                <Icon.focus style={{ width: 14, height: 14 }} />
                <span>
                  Limited coverage: this looks like a {report.framework ?? "non-Next.js/React"} repository. VibeShield still scanned supported text files, but absence of findings is not a full security clearance for this stack.
                </span>
              </div>
            )}

            {pullRequest && <PullRequestPanel pullRequest={pullRequest} />}

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
                report.findings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} onOpen={() => openFindingDetail(finding.id)} />
                ))
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
                <span>Depth</span>
                <b>{formatAnalysisMode(report.analysisMode)}</b>
              </div>
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

      {selectionMode && (
        <FindingSelectionDialog
          mode={selectionMode}
          findings={report.findings}
          selectedFindingIds={activeSelectedFindingIds}
          selectedCount={selectedCount}
          creatingPr={creatingPr}
          githubConnected={Boolean(githubConnected)}
          onClose={() => setSelectionMode(null)}
          onSelectAll={() => setSelectedFindingIds(findingIds)}
          onClear={() => setSelectedFindingIds([])}
          onToggle={(findingId) =>
            setSelectedFindingIds((current) =>
              current.includes(findingId) ? current.filter((id) => id !== findingId) : [...current, findingId],
            )
          }
          onConfirm={() => {
            if (selectionMode === "issue") {
              void copyIssueBody(activeSelectedFindingIds)
              return
            }

            void createPullRequest(activeSelectedFindingIds)
          }}
        />
      )}

      {detailFinding && (
        <FindingDetailWorkbench
          report={report}
          finding={detailFinding}
          copied={copied}
          onClose={closeFindingDetail}
          onSelectFinding={openFindingDetail}
          onCopy={copyDetailText}
          onPreparePr={(findingId) => {
            setSelectedFindingIds([findingId])
            setDetailFindingId(null)
            setSelectionMode("pull_request")
          }}
        />
      )}
    </>
  )
}

function FindingSelectionDialog({
  mode,
  findings,
  selectedFindingIds,
  selectedCount,
  creatingPr,
  githubConnected,
  onClose,
  onSelectAll,
  onClear,
  onToggle,
  onConfirm,
}: {
  mode: SelectionMode
  findings: ScanFinding[]
  selectedFindingIds: string[]
  selectedCount: number
  creatingPr: boolean
  githubConnected: boolean
  onClose: () => void
  onSelectAll: () => void
  onClear: () => void
  onToggle: (findingId: string) => void
  onConfirm: () => void
}) {
  const selectedSet = new Set(selectedFindingIds)
  const isPrMode = mode === "pull_request"
  const title = isPrMode ? "Choose PR scope" : "Choose issue scope"
  const confirmLabel = isPrMode ? (creatingPr ? "Creating PR..." : "Create PR with selected") : "Copy selected issue body"
  const disabled = selectedCount === 0 || (isPrMode && (!githubConnected || creatingPr))

  return (
    <div className="finding-select-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="finding-select-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-select-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="finding-select-head">
          <div className="finding-select-icon">
            {isPrMode ? <Icon.branch style={{ width: 18, height: 18 }} /> : <Icon.doc style={{ width: 18, height: 18 }} />}
          </div>
          <div>
            <h3 id="finding-select-title">{title}</h3>
            <p>
              Pick the findings VibeShield should include. Unselected items stay visible in this report but will not be copied or sent to the PR.
            </p>
          </div>
          <button className="finding-select-close" type="button" onClick={onClose} aria-label="Close selection">
            x
          </button>
        </div>

        {isPrMode && !githubConnected && (
          <div className="selection-warning">
            <Icon.lock style={{ width: 14, height: 14 }} />
            <span>GitHub login is required before VibeShield can open a remediation branch.</span>
          </div>
        )}

        <div className="finding-select-toolbar">
          <span>
            {selectedCount} of {findings.length} selected
          </span>
          <div>
            <button type="button" onClick={onSelectAll}>
              Select all
            </button>
            <button type="button" onClick={onClear}>
              Clear
            </button>
          </div>
        </div>

        <div className="finding-select-list">
          {findings.map((finding) => (
            <label className="finding-select-row" key={finding.id}>
              <input type="checkbox" checked={selectedSet.has(finding.id)} onChange={() => onToggle(finding.id)} />
              <span className={`selection-severity selection-${finding.severity === "info" ? "low" : finding.severity}`}>
                {finding.severity}
              </span>
              <span className="selection-copy">
                <b>{finding.title}</b>
                <em>
                  {finding.filePath}
                  {finding.lineStart ? `:${finding.lineStart}` : ""}
                </em>
              </span>
            </label>
          ))}
        </div>

        <div className="finding-select-foot">
          <span>{isPrMode ? "Only low-risk repo hygiene is applied automatically; code fixes stay review-required." : "The issue body will include only the selected findings."}</span>
          <div>
            <button className="btn btn-outline" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="btn btn-accent" type="button" onClick={onConfirm} disabled={disabled}>
              {confirmLabel}
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

function FindingCard({ finding, onOpen }: { finding: ScanFinding; onOpen: () => void }) {
  const findingIcon = renderFindingIcon(finding)

  return (
    <div
      className="finding real-finding"
      id={finding.id}
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(event) => {
        if (event.key !== "Enter" && event.key !== " ") return
        event.preventDefault()
        onOpen()
      }}
    >
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

function FindingDetailWorkbench({
  report,
  finding,
  copied,
  onClose,
  onSelectFinding,
  onCopy,
  onPreparePr,
}: {
  report: ScanReport
  finding: ScanFinding
  copied: string | null
  onClose: () => void
  onSelectFinding: (findingId: string) => void
  onCopy: (kind: string, value: string) => void
  onPreparePr: (findingId: string) => void
}) {
  const detailRef = useRef<HTMLElement | null>(null)
  const impact = finding.explanation?.impact ?? impactForFinding(finding)
  const summary = finding.explanation?.summary ?? summaryForFinding(finding)
  const hasPatchPreview = Boolean(finding.patchable || finding.patch)
  const patchText = hasPatchPreview ? patchTextForFinding(finding) : ""
  const shareHref = typeof window === "undefined" ? "" : `${window.location.origin}${window.location.pathname}#${finding.id}`

  useEffect(() => {
    const previousBodyOverflow = document.body.style.overflow
    const previousHtmlOverscroll = document.documentElement.style.overscrollBehavior

    document.body.style.overflow = "hidden"
    document.documentElement.style.overscrollBehavior = "contain"

    return () => {
      document.body.style.overflow = previousBodyOverflow
      document.documentElement.style.overscrollBehavior = previousHtmlOverscroll
    }
  }, [])

  const handleShellWheel = (event: WheelEvent<HTMLElement>) => {
    const shell = event.currentTarget
    const target = event.target instanceof Element ? event.target : null
    const detail = detailRef.current
    if (!target || !detail || !event.deltaY) return

    const scrollable = findVerticalScrollContainer(target, shell)
    if (scrollable && scrollable !== detail) return

    if (detail.scrollHeight <= detail.clientHeight) return
    if (scrollable === detail) return

    event.preventDefault()
    detail.scrollBy({ top: event.deltaY, behavior: "auto" })
  }

  return (
    <div className="finding-detail-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="finding-detail-shell"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-title"
        onMouseDown={(event) => event.stopPropagation()}
        onWheel={handleShellWheel}
      >
        <div className="finding-detail-top">
          <div>
            <span>Finding detail</span>
            <b>{report.projectName}</b>
          </div>
          <button className="finding-detail-close" type="button" onClick={onClose} aria-label="Close finding detail">
            x
          </button>
        </div>

        <div className="finding-grid">
          <aside className="finding-list">
            <div className="finding-list-head">
              <div className="title">
                <Icon.focus style={{ width: 15, height: 15 }} />
                Findings <span className="n">{report.findings.length}</span>
              </div>
              <span className="pill-sev">{finding.severity}</span>
            </div>
            <div className="finding-list-body">
              {report.findings.map((item) => (
                <button
                  className="fl-row"
                  data-active={item.id === finding.id}
                  key={item.id}
                  type="button"
                  onClick={() => onSelectFinding(item.id)}
                >
                  <span className="ico">{renderFindingIcon(item)}</span>
                  <span className="body">
                    <span className={`sev sev-${item.severity === "info" ? "low" : item.severity}`}>
                      <span className="dot" />
                      {item.severity}
                    </span>
                    <span className="title">{item.title}</span>
                    <span className="path">
                      {item.filePath}
                      {item.lineStart && <b>:{item.lineStart}</b>}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </aside>

          <article className="finding-detail" ref={detailRef}>
            <div className="fd-meta">
              <b>{finding.id}</b>
              <span>·</span>
              <span>{formatFindingLocation(finding)}</span>
            </div>

            <h2 className="fd-title" id="finding-detail-title">
              {finding.title} <em>{titleQualifier(finding)}</em>
            </h2>

            <div className="fd-tags">
              <span className={`tag tag-severity tag-${finding.severity === "info" ? "low" : finding.severity}`}>
                <span className="dot" /> {finding.severity}
              </span>
              <span className="tag">{labelForCategory(finding.category)}</span>
              <span className="tag">{Math.round(finding.confidence * 100)}% confidence</span>
              <span className="tag">{finding.source}</span>
              {finding.patchable && <span className="tag">review-required patch</span>}
            </div>

            <div className="fd-actions">
              {finding.patchable && (
                <button className="btn btn-outline" type="button" onClick={() => onPreparePr(finding.id)}>
                  <Icon.branch style={{ width: 14, height: 14 }} />
                  <span>Prepare PR scope</span>
                </button>
              )}
              <button className="btn btn-outline" type="button" onClick={() => onCopy("evidence", finding.evidence ?? finding.description)}>
                <Icon.doc style={{ width: 14, height: 14 }} />
                <span>{copied === "evidence" ? "Copied" : "Copy evidence"}</span>
              </button>
              {hasPatchPreview && (
                <button className="btn btn-outline" type="button" onClick={() => onCopy("patch", patchText)}>
                  <Icon.code style={{ width: 14, height: 14 }} />
                  <span>{copied === "patch" ? "Copied" : "Copy patch"}</span>
                </button>
              )}
              <button className="btn btn-outline" type="button" onClick={() => onCopy("finding-link", shareHref)}>
                <Icon.share style={{ width: 14, height: 14 }} />
                <span>{copied === "finding-link" ? "Copied" : "Share"}</span>
              </button>
            </div>

            <DetailSection title="What we found">
              <p className="prose">{summary}</p>
            </DetailSection>

            <DetailSection title="Where it is">
              <EvidenceBlock finding={finding} />
            </DetailSection>

            <DetailSection title="Why it matters">
              <p className="prose">{impact}</p>
            </DetailSection>

            {hasPatchPreview ? (
              <DetailSection title="Recommended patch">
                <PatchBlock finding={finding} />
              </DetailSection>
            ) : (
              <DetailSection title="Recommended review">
                <p className="prose">{finding.recommendation}</p>
              </DetailSection>
            )}

            <DetailSection title="Fix steps">
              <ol className="fd-steps">
                {(finding.explanation?.fixSteps?.length ? finding.explanation.fixSteps : fixStepsForFinding(finding)).map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </DetailSection>
          </article>
        </div>
      </section>
    </div>
  )
}

function findVerticalScrollContainer(start: Element, stopAt: Element) {
  let element: Element | null = start

  while (element && element !== stopAt) {
    if (element instanceof HTMLElement) {
      const style = window.getComputedStyle(element)
      const canScroll = /(auto|scroll)/.test(style.overflowY) && element.scrollHeight > element.clientHeight
      if (canScroll) return element
    }

    element = element.parentElement
  }

  return null
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="fd-section">
      <h3 className="eyebrow">{title}</h3>
      {children}
    </section>
  )
}

function EvidenceBlock({ finding }: { finding: ScanFinding }) {
  const evidence = finding.evidence || finding.description
  const startLine = Math.max(1, (finding.lineStart ?? 1) - 2)
  const highlightLine = finding.lineStart ?? startLine
  const lines = buildContextLines(evidence, startLine, highlightLine)

  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span className="filename">
          <Icon.doc style={{ width: 14, height: 14 }} />
          {finding.filePath}
        </span>
      </div>
      <div className="codeblock-body">
        {lines.map((line) => (
          <div className="cb-line" data-highlight={line.highlight} key={`${line.number}-${line.text}`}>
            <span className="cb-num">{line.number}</span>
            <code className="cb-content">{line.text}</code>
          </div>
        ))}
      </div>
    </div>
  )
}

function PatchBlock({ finding }: { finding: ScanFinding }) {
  const patch = finding.patch
  const diff = patch?.unifiedDiff ?? templatePatchForFinding(finding)

  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span className="filename">
          <Icon.branch style={{ width: 14, height: 14 }} />
          {finding.filePath}
          <span className="filename-sep">+</span>
          <span className="filename-secondary">review</span>
        </span>
        <span className="badge-auto">REVIEW REQUIRED</span>
      </div>
      <div className="patch-summary">
        <b>{patch?.title ?? "Review and patch this finding"}</b>
        <span>{patch?.summary ?? finding.recommendation}</span>
      </div>
      <div className="codeblock-body diff">
        {diff.split("\n").map((line, index) => {
          const remove = line.startsWith("-")
          const add = line.startsWith("+")
          return (
            <div
              className="cb-line"
              data-remove={remove}
              data-add={add}
              key={`${index}-${line}`}
            >
              <span className="cb-num">{index + 1}</span>
              <span className="cb-num">{index + 1}</span>
              <span className="cb-sign">{remove ? "-" : add ? "+" : " "}</span>
              <code className="cb-content">{remove || add ? line.slice(1) : line}</code>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function buildContextLines(evidence: string, startLine: number, highlightLine: number) {
  const trimmedEvidence = evidence.trim() || "No concrete evidence line was stored for this finding."
  const before = startLine < highlightLine ? [{ number: startLine, text: "...", highlight: false }] : []
  const afterLine = Math.max(highlightLine + 1, startLine + before.length + 1)

  return [
    ...before,
    { number: highlightLine, text: trimmedEvidence, highlight: true },
    { number: afterLine, text: "...", highlight: false },
  ]
}

function summaryForFinding(finding: ScanFinding) {
  const location = formatFindingLocation(finding)
  const evidence = finding.evidence ? ` Evidence: ${finding.evidence}` : ""
  return `${finding.description} VibeShield tied this finding to ${location} with ${Math.round(finding.confidence * 100)}% confidence.${evidence}`
}

function impactForFinding(finding: ScanFinding) {
  if (finding.category === "secret_exposure") {
    return "A committed secret can be copied by anyone with repository access and may continue working after deployment. Rotate the credential first, then remove it from source control and load it only from server-side environment variables."
  }
  if (finding.category === "public_env_misuse") {
    return "Next.js bundles NEXT_PUBLIC values into browser JavaScript. If the value is a secret, token, service-role key, or private database URL, visitors can extract it from client assets."
  }
  if (finding.category === "missing_auth") {
    return "Sensitive routes without server-side authorization can expose user, admin, billing, or internal data. Client-side checks do not protect API routes."
  }
  if (finding.category === "ai_endpoint_risk") {
    return "Model endpoints can be abused for spend, denial of wallet, prompt-injection chains, or tool execution. Rate limits, quotas, bot checks, and explicit execution bounds reduce that blast radius."
  }
  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk") {
    return "Dynamic tool dispatch lets user-controlled input influence which tool runs. In agentic systems that can escalate into data access, shell execution, or unintended external actions."
  }
  if (finding.category === "input_validation") {
    return "Unvalidated input can cross trust boundaries before the application knows its shape. Schema validation and signature checks prevent malformed, forged, or hostile payloads from reaching business logic."
  }
  if (finding.category === "client_data_exposure") {
    return "Anything shipped to a client component or exposed through permissive browser policies can be inspected by users. Keep sensitive data and session controls on the server."
  }
  if (finding.category === "dangerous_code") {
    return "Dynamic code execution, raw HTML, shell processes, and unsafe file writes turn small input-handling mistakes into high-impact compromise paths."
  }
  if (finding.category === "dependency_signal") {
    return "Supply-chain and dependency signals are not always vulnerabilities by themselves, but they mark code paths that should be reviewed before production release."
  }
  return "This finding affects production readiness. Review the evidence, confirm the app context, and apply the recommendation before shipping."
}

function fixStepsForFinding(finding: ScanFinding) {
  if (finding.category === "secret_exposure") {
    return [
      "Rotate the exposed credential in the provider dashboard.",
      "Remove the committed value from source control.",
      "Add only safe placeholder keys to .env.example.",
      "Read the real value from server-only environment variables.",
    ]
  }
  if (finding.category === "public_env_misuse") {
    return [
      "Rename the variable without the NEXT_PUBLIC_ prefix.",
      "Move all reads of the value into server components, route handlers, or server actions.",
      "Expose only derived, non-sensitive data to the browser.",
    ]
  }
  if (finding.category === "missing_auth") {
    return [
      "Add a server-side authentication guard at the top of the route.",
      "Verify role, ownership, or tenant access before returning data.",
      "Return 401 or 403 before running sensitive logic.",
    ]
  }
  if (finding.category === "ai_endpoint_risk") {
    return [
      "Check quota and rate limits before the first model call.",
      "Add bot or abuse protection for public routes.",
      "Set token, step, and budget limits for model/tool execution.",
    ]
  }
  if (finding.category === "input_validation") {
    return [
      "Define the expected request schema.",
      "Parse or safeParse the request before using fields.",
      "For webhooks, verify the provider signature against the raw body first.",
    ]
  }
  return [
    "Confirm the finding against the app's intended behavior.",
    "Apply the recommended patch in a small reviewable change.",
    "Add a regression test or manual verification step for the affected route.",
  ]
}

function patchTextForFinding(finding: ScanFinding) {
  return finding.patch?.unifiedDiff ?? templatePatchForFinding(finding)
}

function templatePatchForFinding(finding: ScanFinding) {
  if (finding.category === "input_validation") {
    return [
      "+ const BodySchema = z.object({",
      "+   // TODO: define expected fields",
      "+ })",
      "+ const body = BodySchema.parse(await request.json())",
    ].join("\n")
  }
  if (finding.category === "missing_auth") {
    return [
      "+ const user = await requireAuth()",
      "+ if (!user) {",
      "+   return NextResponse.json({ error: \"Unauthorized\" }, { status: 401 })",
      "+ }",
    ].join("\n")
  }
  if (finding.category === "ai_endpoint_risk") {
    return [
      "+ const allowed = await checkRateLimit(request)",
      "+ if (!allowed) {",
      "+   return new Response(\"Too many requests\", { status: 429 })",
      "+ }",
      "+ // Add token, step, and budget limits before invoking the model.",
    ].join("\n")
  }
  if (finding.category === "public_env_misuse") {
    return [
      "- NEXT_PUBLIC_SECRET_VALUE=...",
      "+ SECRET_VALUE=...",
      "+ // Read only from server-side code.",
    ].join("\n")
  }
  if (finding.category === "secret_exposure") {
    return [
      "- API_KEY=...redacted",
      "+ API_KEY=",
      "+ # Rotate the real credential and configure it in the deployment environment.",
    ].join("\n")
  }
  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk") {
    return [
      "+ const allowedTools = { search, summarize } as const",
      "+ const tool = allowedTools[requestedTool as keyof typeof allowedTools]",
      "+ if (!tool) throw new Error(\"Unsupported tool\")",
    ].join("\n")
  }
  return `+ ${finding.recommendation}`
}

function titleQualifier(finding: ScanFinding) {
  if (finding.category === "secret_exposure" || finding.category === "public_env_misuse") return "in source code"
  if (finding.category === "missing_auth" || finding.category === "input_validation") return "in a route boundary"
  if (finding.category === "ai_endpoint_risk") return "in an AI endpoint"
  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk") return "in agent tooling"
  if (finding.category === "client_data_exposure") return "in client-facing code"
  return "before production"
}

function formatFindingLocation(finding: ScanFinding) {
  if (!finding.lineStart) return finding.filePath
  return `${finding.filePath}:${finding.lineStart}`
}

function PullRequestPanel({ pullRequest }: { pullRequest: ScanPullRequest }) {
  return (
    <div className="github-pr-panel">
      <div className="github-pr-main">
        <Icon.branch style={{ width: 18, height: 18 }} />
        <div>
          <b>GitHub PR created</b>
          <span>
            Branch <code>{pullRequest.branch}</code> into <code>{pullRequest.base}</code>
          </span>
        </div>
      </div>
      <div className="github-pr-meta">
        <span>{pullRequest.filesChanged.length} files changed</span>
        <span>{pullRequest.appliedFixes.length} safe fixes applied</span>
        <span>{pullRequest.skippedFixes.length} review-required</span>
      </div>
      <a className="btn btn-outline" href={pullRequest.url} target="_blank" rel="noreferrer">
        Open PR #{pullRequest.number}
      </a>
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

function isOutsidePrimaryCoverage(report: ScanReport) {
  const framework = report.framework ?? ""
  if (/Next\.js|React\/Vite/i.test(framework)) return false
  return report.filesInspected > 0
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

function formatAnalysisMode(mode: ScanReport["analysisMode"] | undefined) {
  if (mode === "rules") return "Rules"
  return mode === "max" ? "Max depth" : "Pro normal"
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
