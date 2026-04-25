import { notFound } from "next/navigation"
import { ScanReportLoader } from "@/components/scan/ScanReportLoader"

export const dynamic = "force-dynamic"

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  if (!isReportId(scanId)) {
    notFound()
  }

  return <ScanReportLoader scanId={scanId} />
}

function isReportId(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
}
