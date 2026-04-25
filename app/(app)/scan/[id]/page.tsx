import { redirect } from "next/navigation"

export default async function LegacyScanReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  redirect(id === "r_8f2a" ? "/report/demo" : `/report/${id}`)
}
