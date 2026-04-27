"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import { Icon } from "@/app/(app)/_components/icons"
import type { ScanReport } from "@/lib/scanner/types"
import { ScanResultsClient } from "./ScanResultsClient"

export function ScanReportLoader({ scanId }: { scanId: string }) {
  const [githubConnected, setGitHubConnected] = useState(false)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function loadGitHubSession() {
      try {
        const response = await fetch("/api/auth/github/session", { cache: "no-store" })
        const data = await response.json()
        setGitHubConnected(Boolean(data.session?.authenticated))
      } catch {
        setGitHubConnected(false)
      }
    }

    void loadGitHubSession()
  }, [])

  useEffect(() => {
    const controller = new AbortController()

    async function loadReport() {
      setLoading(true)
      setError(null)

      try {
        const response = await fetch(`/api/scan/${scanId}`, {
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error ?? "Scan report not found.")
        setReport(data.report)
      } catch (loadError) {
        if (controller.signal.aborted) return
        setError(loadError instanceof Error ? loadError.message : "Scan report not found.")
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadReport()

    return () => controller.abort()
  }, [scanId])

  if (report) {
    return (
      <ScanResultsClient
        initialReport={report}
        githubConnected={githubConnected}
      />
    )
  }

  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>
            <b>{loading ? "Loading report" : "Report not found"}</b>
          </span>
        </div>
      </div>
      <div className="page-pad">
        <div className="empty-state">
          <div className="empty-icon">
            <Icon.focus style={{ width: 28, height: 28 }} />
          </div>
          <h2 className="empty-title">{loading ? "Loading scan report" : "Scan report not found"}</h2>
          <p className="empty-sub">
            {loading
              ? "Fetching the stored report with your current browser session."
              : error ?? "Use the same browser/session that created this report, or start a new scan."}
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
    </>
  )
}
