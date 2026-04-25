"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import type { Session } from "@supabase/supabase-js"
import { Icon } from "@/app/(app)/_components/icons"
import { createBrowserSupabaseClient } from "@/lib/supabase/client"
import type { ScanReport } from "@/lib/scanner/types"
import { ScanResultsClient } from "./ScanResultsClient"

export function ScanReportLoader({ scanId }: { scanId: string }) {
  const supabase = useMemo(() => createBrowserSupabaseClient(), [])
  const [session, setSession] = useState<Session | null>(null)
  const [sessionChecked, setSessionChecked] = useState(!supabase)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

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

    async function loadReport() {
      setLoading(true)
      setError(null)

      try {
        const response = await fetch(`/api/scan/${scanId}`, {
          headers: authHeaders(session?.access_token),
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
  }, [scanId, session?.access_token, sessionChecked])

  if (report) return <ScanResultsClient initialReport={report} authToken={session?.access_token ?? null} />

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

function authHeaders(accessToken?: string | null) {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined
}
