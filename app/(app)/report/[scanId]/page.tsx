import { headers } from "next/headers"
import { notFound } from "next/navigation"
import { ScanResultsClient } from "@/components/scan/ScanResultsClient"
import { getScanReport } from "@/lib/scanner/store"
import { canAccessReport, getRequestIdentityFromHeaders, publicReport } from "@/lib/security/request"

export const dynamic = "force-dynamic"

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  const report = await getScanReport(scanId)
  const identity = await getRequestIdentityFromHeaders(await headers())

  if (!report || !canAccessReport(report, identity)) {
    notFound()
  }

  return <ScanResultsClient initialReport={publicReport(report)} />
}
