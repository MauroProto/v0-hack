import { getSupabaseServiceClient, isSupabaseConfigured } from "@/lib/supabase/server"
import type { ScanReport } from "./types"

const TABLE = "vibeshield_scan_reports"

type StoreGlobal = typeof globalThis & {
  __vibeshieldScanStore?: Map<string, ScanReport>
}

type ScanReportRow = {
  id: string
  created_at: string
  updated_at: string
  owner_hash: string | null
  project_name: string
  source_type: ScanReport["sourceType"]
  source_label: string
  status: ScanReport["status"]
  risk_score: number
  report: ScanReport
}

const storeGlobal = globalThis as StoreGlobal

function getMemoryStore() {
  if (!storeGlobal.__vibeshieldScanStore) {
    storeGlobal.__vibeshieldScanStore = new Map<string, ScanReport>()
  }

  return storeGlobal.__vibeshieldScanStore
}

export function getStorageMode() {
  return isSupabaseConfigured() ? "supabase" : "memory"
}

export async function saveScanReport(report: ScanReport) {
  getMemoryStore().set(report.id, report)

  const supabase = getSupabaseServiceClient()
  if (!supabase) return report

  const row: Omit<ScanReportRow, "updated_at"> & { updated_at?: string } = {
    id: report.id,
    created_at: report.createdAt,
    updated_at: new Date().toISOString(),
    owner_hash: report.ownerHash ?? null,
    project_name: report.projectName,
    source_type: report.sourceType,
    source_label: report.sourceLabel,
    status: report.status,
    risk_score: report.riskScore,
    report,
  }

  const { error } = await supabase.from(TABLE).upsert(row, { onConflict: "id" })
  if (error) {
    console.error("VibeShield Supabase save failed", error.message)
  }

  return report
}

export async function getScanReport(scanId: string) {
  const memoryReport = getMemoryStore().get(scanId)
  if (memoryReport) return memoryReport

  const supabase = getSupabaseServiceClient()
  if (!supabase) return undefined

  const { data, error } = await supabase.from(TABLE).select("report").eq("id", scanId).maybeSingle()
  if (error) {
    console.error("VibeShield Supabase read failed", error.message)
    return undefined
  }

  const report = (data as Pick<ScanReportRow, "report"> | null)?.report
  if (report) getMemoryStore().set(scanId, report)

  return report
}

export async function updateScanReport(scanId: string, updater: (report: ScanReport) => ScanReport) {
  const current = await getScanReport(scanId)
  if (!current) return undefined

  const next = updater(current)
  await saveScanReport(next)
  return next
}

export async function listScanReports(ownerHash?: string) {
  const memoryReports = [...getMemoryStore().values()].filter((report) => canListReport(report, ownerHash))

  if (getStorageMode() === "supabase" && process.env.VIBESHIELD_ENABLE_PUBLIC_SCAN_LIST !== "true") {
    const ownerReports = await listSupabaseOwnerReports(ownerHash)
    if (ownerReports) return mergeReports(memoryReports, ownerReports)
    return sortReports(memoryReports)
  }

  const supabase = getSupabaseServiceClient()
  if (!supabase) return sortReports(memoryReports)

  const { data, error } = await supabase
    .from(TABLE)
    .select("report")
    .eq("owner_hash", ownerHash ?? "")
    .order("created_at", { ascending: false })
    .limit(25)

  if (error) {
    console.error("VibeShield Supabase list failed", error.message)
    return sortReports(memoryReports)
  }

  return mergeReports(
    memoryReports,
    (data as Pick<ScanReportRow, "report">[]).map((row) => row.report),
  )
}

async function listSupabaseOwnerReports(ownerHash?: string) {
  if (!ownerHash) return []

  const supabase = getSupabaseServiceClient()
  if (!supabase) return undefined

  const { data, error } = await supabase
    .from(TABLE)
    .select("report")
    .eq("owner_hash", ownerHash)
    .order("created_at", { ascending: false })
    .limit(25)

  if (error) {
    console.error("VibeShield Supabase owner list failed", error.message)
    return undefined
  }

  return (data as Pick<ScanReportRow, "report">[]).map((row) => row.report)
}

function canListReport(report: ScanReport, ownerHash?: string) {
  return Boolean(ownerHash && report.ownerHash === ownerHash)
}

function mergeReports(primary: ScanReport[], secondary: ScanReport[]) {
  const byId = new Map<string, ScanReport>()
  for (const report of [...secondary, ...primary]) {
    byId.set(report.id, report)
  }

  return sortReports([...byId.values()])
}

function sortReports(reports: ScanReport[]) {
  return reports.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}
