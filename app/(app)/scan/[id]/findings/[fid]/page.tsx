import { redirect } from "next/navigation"

export default async function LegacyFindingPage({ params }: { params: Promise<{ id: string; fid: string }> }) {
  const { id, fid } = await params
  const reportId = id === "r_8f2a" ? "demo" : id
  redirect(`/report/${reportId}#${fid}`)
}
