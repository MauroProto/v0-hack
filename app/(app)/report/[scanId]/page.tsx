import Link from "next/link"
import { headers } from "next/headers"
import { ScanResultsClient } from "@/components/scan/ScanResultsClient"
import { getOrCreateDemoReport, isDemoScanEnabled } from "@/lib/scanner/demo"
import { getScanReport } from "@/lib/scanner/store"
import { canAccessReport, getRequestIdentityFromHeaders, publicReport } from "@/lib/security/request"
import { Icon } from "../../_components/icons"

export const dynamic = "force-dynamic"

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  if (scanId === "demo" && !isDemoScanEnabled()) {
    return notFoundReport()
  }

  const report = scanId === "demo" ? await getOrCreateDemoReport() : await getScanReport(scanId)
  const identity = await getRequestIdentityFromHeaders(await headers())

  if (!report || !canAccessReport(report, identity)) {
    return notFoundReport()
  }

  return <ScanResultsClient initialReport={publicReport(report)} />
}

function notFoundReport() {
  return (
    <>
      <div className="app-topbar">
        <div className="crumbs">
          <span>VibeShield</span>
          <span className="sep">/</span>
          <span>
            <b>Report not found</b>
          </span>
        </div>
      </div>
      <div className="page-pad">
        <div className="empty-state">
          <div className="empty-icon">
            <Icon.focus style={{ width: 28, height: 28 }} />
          </div>
          <h2 className="empty-title">Scan report not found</h2>
          <p className="empty-sub">Reports are scoped to the identity that created them. Start a new scan or use the same browser/session that created this report.</p>
          <div className="empty-actions">
            <Link href="/scan" className="btn btn-accent btn-lg">
              <Icon.bolt style={{ width: 14, height: 14 }} /> Start security scan
            </Link>
          </div>
        </div>
      </div>
    </>
  )
}
