"use client"

import Link from "next/link"
import { useEffect, useRef, useState } from "react"
import { Icon } from "@/app/(app)/_components/icons"
import type { ScanReport } from "@/lib/scanner/types"
import { subscribeGitHubSessionChange } from "@/lib/client/github-session-events"
import { ScanResultsClient } from "./ScanResultsClient"

export function ScanReportLoader({ scanId }: { scanId: string }) {
  const [githubConnected, setGitHubConnected] = useState(false)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const sessionVersion = useRef(0)

  useEffect(() => {
    async function loadGitHubSession() {
      const activeSessionVersion = sessionVersion.current
      try {
        const response = await fetch("/api/auth/github/session", { cache: "no-store" })
        const data = await response.json()
        if (sessionVersion.current !== activeSessionVersion) return
        setGitHubConnected(Boolean(data.session?.authenticated))
      } catch {
        if (sessionVersion.current !== activeSessionVersion) return
        setGitHubConnected(false)
      }
    }

    void loadGitHubSession()
  }, [])

  useEffect(() => {
    return subscribeGitHubSessionChange(() => {
      sessionVersion.current += 1
      setGitHubConnected(false)
      setReport(null)
      setError("Login with GitHub to view this report.")
      setLoading(false)
    })
  }, [])

  useEffect(() => {
    const controller = new AbortController()

    async function loadReport() {
      const activeSessionVersion = sessionVersion.current
      setLoading(true)
      setError(null)

      try {
        const response = await fetch(`/api/scan/${scanId}`, {
          cache: "no-store",
          signal: controller.signal,
        })
        const data = await response.json()
        if (sessionVersion.current !== activeSessionVersion) return
        if (!response.ok) throw new Error(data.error ?? "Scan report not found.")
        setReport(data.report)
      } catch (loadError) {
        if (controller.signal.aborted) return
        if (sessionVersion.current !== activeSessionVersion) return
        setError(loadError instanceof Error ? loadError.message : "Scan report not found.")
      } finally {
        if (!controller.signal.aborted && sessionVersion.current === activeSessionVersion) setLoading(false)
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
          <span>Badger</span>
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
              <Link href="/scan" className="btn btn-accent btn-lg btn-shine">
                <Icon.bolt style={{ width: 14, height: 14 }} /> Start security scan
              </Link>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
