import { mkdir, readFile, rename, writeFile } from "node:fs/promises"
import path from "node:path"
import { isSupabaseConfigured } from "@/lib/supabase/config"
import { VIBESHIELD_SUPABASE_TABLES } from "@/lib/supabase/schema"
import type { ScanBaseline, ScanReport } from "./types"
import { baselineIdFor } from "./reportPolicy"

const TABLE = VIBESHIELD_SUPABASE_TABLES.reports
const BASELINES_TABLE = VIBESHIELD_SUPABASE_TABLES.baselines

type StoreGlobal = typeof globalThis & {
  __vibeshieldScanStore?: Map<string, ScanReport>
  __vibeshieldBaselineStore?: Map<string, ScanBaseline>
  __vibeshieldScanStoreLoaded?: boolean
  __vibeshieldScanStoreLoadPromise?: Promise<void>
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

type ScanBaselineRow = {
  id: string
  created_at: string
  updated_at: string
  owner_hash: string | null
  source_label: string
  baseline: ScanBaseline
}

const storeGlobal = globalThis as StoreGlobal

function getMemoryStore() {
  if (!storeGlobal.__vibeshieldScanStore) {
    storeGlobal.__vibeshieldScanStore = new Map<string, ScanReport>()
  }

  return storeGlobal.__vibeshieldScanStore
}

function getBaselineStore() {
  if (!storeGlobal.__vibeshieldBaselineStore) {
    storeGlobal.__vibeshieldBaselineStore = new Map<string, ScanBaseline>()
  }

  return storeGlobal.__vibeshieldBaselineStore
}

export function getStorageMode() {
  if (isSupabaseConfigured()) return "supabase"
  if (localFileStoreEnabled()) return "local_file"
  return "memory"
}

export async function saveScanReport(report: ScanReport) {
  await ensureLocalStoreLoaded()
  getMemoryStore().set(report.id, report)

  const supabase = await getSupabaseClient()
  if (!supabase) {
    if (persistentStorageRequired()) {
      throw new Error("Persistent scan storage is not configured. Connect Supabase before accepting production scans.")
    }
    await persistLocalStore()
    return report
  }

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
    if (persistentStorageRequired()) {
      throw new Error("Persistent scan storage failed. The report was not saved.")
    }
  }

  return report
}

export async function getScanReport(scanId: string) {
  await ensureLocalStoreLoaded()
  const memoryReport = getMemoryStore().get(scanId)
  if (memoryReport) return memoryReport

  const supabase = await getSupabaseClient()
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

export async function saveScanBaseline(baseline: ScanBaseline) {
  await ensureLocalStoreLoaded()
  const now = new Date().toISOString()
  const next: ScanBaseline = {
    ...baseline,
    updatedAt: now,
  }
  getBaselineStore().set(next.id, next)

  const supabase = await getSupabaseClient()
  if (!supabase) {
    if (persistentStorageRequired()) {
      throw new Error("Persistent baseline storage is not configured. Connect Supabase before accepting production scans.")
    }
    await persistLocalStore()
    return next
  }

  const row: ScanBaselineRow = {
    id: next.id,
    created_at: next.createdAt,
    updated_at: next.updatedAt,
    owner_hash: next.ownerHash ?? null,
    source_label: next.sourceLabel,
    baseline: next,
  }

  const { error } = await supabase.from(BASELINES_TABLE).upsert(row, { onConflict: "id" })
  if (error) {
    console.error("VibeShield Supabase baseline save failed", error.message)
    if (persistentStorageRequired()) {
      throw new Error("Persistent baseline storage failed. The baseline was not saved.")
    }
  }

  return next
}

export async function getScanBaseline(sourceLabel: string, ownerHash?: string) {
  await ensureLocalStoreLoaded()
  const id = baselineIdFor(sourceLabel, ownerHash)
  const memoryBaseline = getBaselineStore().get(id)
  if (memoryBaseline) return memoryBaseline

  const supabase = await getSupabaseClient()
  if (!supabase) return undefined

  const { data, error } = await supabase.from(BASELINES_TABLE).select("baseline").eq("id", id).maybeSingle()
  if (error) {
    console.error("VibeShield Supabase baseline read failed", error.message)
    return undefined
  }

  const baseline = (data as Pick<ScanBaselineRow, "baseline"> | null)?.baseline
  if (baseline) getBaselineStore().set(id, baseline)
  return baseline
}

export async function listScanReports(ownerHash?: string) {
  await ensureLocalStoreLoaded()
  const memoryReports = [...getMemoryStore().values()].filter((report) => canListReport(report, ownerHash))

  if (getStorageMode() === "supabase" && process.env.VIBESHIELD_ENABLE_PUBLIC_SCAN_LIST !== "true") {
    const ownerReports = await listSupabaseOwnerReports(ownerHash)
    if (ownerReports) return mergeReports(memoryReports, ownerReports)
    return sortReports(memoryReports)
  }

  const supabase = await getSupabaseClient()
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

  const supabase = await getSupabaseClient()
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

async function ensureLocalStoreLoaded() {
  if (!localFileStoreEnabled()) return
  if (storeGlobal.__vibeshieldScanStoreLoaded) return
  if (storeGlobal.__vibeshieldScanStoreLoadPromise) {
    await storeGlobal.__vibeshieldScanStoreLoadPromise
    return
  }

  storeGlobal.__vibeshieldScanStoreLoadPromise = loadLocalStore()
  await storeGlobal.__vibeshieldScanStoreLoadPromise
}

async function loadLocalStore() {
  try {
    const raw = await readFile(localStorePath(), "utf8")
    const parsed = JSON.parse(raw) as { reports?: unknown; baselines?: unknown }
    const reports = Array.isArray(parsed.reports) ? parsed.reports : []
    const baselines = Array.isArray(parsed.baselines) ? parsed.baselines : []
    const store = getMemoryStore()
    const baselineStore = getBaselineStore()

    for (const report of reports) {
      if (isPersistedScanReport(report)) store.set(report.id, report)
    }

    for (const baseline of baselines) {
      if (isPersistedScanBaseline(baseline)) baselineStore.set(baseline.id, baseline)
    }
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      storeGlobal.__vibeshieldScanStoreLoaded = true
      return
    }

    console.error("VibeShield local scan store read failed", error instanceof Error ? error.message : "unknown error")
  } finally {
    storeGlobal.__vibeshieldScanStoreLoaded = true
    storeGlobal.__vibeshieldScanStoreLoadPromise = undefined
  }
}

async function persistLocalStore() {
  if (!localFileStoreEnabled()) return

  const filePath = localStorePath()
  const tmpPath = `${filePath}.tmp`
  const reports = sortReports([...getMemoryStore().values()])
  const baselines = [...getBaselineStore().values()].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))

  try {
    await mkdir(path.dirname(filePath), { recursive: true })
    await writeFile(
      tmpPath,
      JSON.stringify(
        {
          version: 1,
          updatedAt: new Date().toISOString(),
          reports,
          baselines,
        },
        null,
        2,
      ),
      "utf8",
    )
    await rename(tmpPath, filePath)
  } catch (error) {
    console.error("VibeShield local scan store write failed", error instanceof Error ? error.message : "unknown error")
  }
}

function localFileStoreEnabled() {
  if (isSupabaseConfigured()) return false
  if (process.env.VIBESHIELD_DISABLE_LOCAL_FILE_STORE === "true") return false
  return process.env.NODE_ENV !== "production" || process.env.VIBESHIELD_ENABLE_LOCAL_FILE_STORE === "true"
}

async function getSupabaseClient() {
  if (!isSupabaseConfigured()) return null
  const { getSupabaseServiceClient } = await import("@/lib/supabase/server")
  return getSupabaseServiceClient()
}

function persistentStorageRequired() {
  const value = process.env.VIBESHIELD_REQUIRE_PERSISTENT_STORAGE?.trim().toLowerCase()
  if (value === "true") return true
  if (value === "false") return false

  const quotaValue = process.env.VIBESHIELD_REQUIRE_PERSISTENT_QUOTA?.trim().toLowerCase()
  if (quotaValue === "true") return true
  if (quotaValue === "false") return false

  return process.env.NODE_ENV === "production"
}

function localStorePath() {
  const fileName = (process.env.VIBESHIELD_LOCAL_STORE_FILE || "scan-reports.json").replace(/[^\w.-]/g, "_")
  return path.join(process.cwd(), ".vibeshield", fileName)
}

function isPersistedScanReport(value: unknown): value is ScanReport {
  if (!value || typeof value !== "object") return false
  const report = value as Partial<ScanReport>
  return Boolean(
    typeof report.id === "string" &&
      typeof report.createdAt === "string" &&
      typeof report.projectName === "string" &&
      report.sourceType === "github" &&
      Array.isArray(report.findings) &&
      Array.isArray(report.auditTrail),
  )
}

function isPersistedScanBaseline(value: unknown): value is ScanBaseline {
  if (!value || typeof value !== "object") return false
  const baseline = value as Partial<ScanBaseline>
  return Boolean(
    typeof baseline.id === "string" &&
      typeof baseline.sourceLabel === "string" &&
      typeof baseline.createdAt === "string" &&
      typeof baseline.updatedAt === "string" &&
      Array.isArray(baseline.fingerprints),
  )
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return Boolean(error && typeof error === "object" && "code" in error)
}
