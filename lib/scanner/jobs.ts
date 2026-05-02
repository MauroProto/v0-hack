import { isSupabaseConfigured } from "@/lib/supabase/config"
import { VIBESHIELD_SUPABASE_TABLES } from "@/lib/supabase/schema"
import type { ScanEvent, ScanJob, ScanMode, ScanRepositoryRef } from "./types"

const JOBS_TABLE = VIBESHIELD_SUPABASE_TABLES.jobs
const EVENTS_TABLE = VIBESHIELD_SUPABASE_TABLES.events

type JobGlobal = typeof globalThis & {
  __vibeshieldScanJobs?: Map<string, ScanJob>
  __vibeshieldScanEvents?: ScanEvent[]
}

type CreateScanJobInput = {
  ownerHash?: string
  reportId: string
  projectName: string
  sourceLabel: string
  analysisMode: ScanMode
  repository: ScanRepositoryRef
}

type AppendScanEventInput = {
  reportId: string
  jobId?: string
  label: string
  status: ScanEvent["status"]
  metadata?: Record<string, unknown>
}

const jobGlobal = globalThis as JobGlobal

export async function createScanJob(input: CreateScanJobInput): Promise<ScanJob> {
  const now = new Date().toISOString()
  const job: ScanJob = {
    id: crypto.randomUUID(),
    reportId: input.reportId,
    ownerHash: input.ownerHash,
    projectName: input.projectName,
    sourceLabel: input.sourceLabel,
    analysisMode: input.analysisMode,
    status: "queued",
    createdAt: now,
    updatedAt: now,
    attempts: 0,
    repository: input.repository,
  }

  getJobStore().set(job.id, job)
  await persistJob(job)
  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "Scan job queued", status: "complete" })
  return job
}

export async function claimNextScanJob(): Promise<ScanJob | undefined> {
  const supabase = await getSupabaseClient()
  if (supabase) {
    const { data, error } = await supabase
      .from(JOBS_TABLE)
      .select("job")
      .eq("status", "queued")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle()

    if (error) {
      console.error("VibeShield Supabase job claim read failed", error.message)
      return undefined
    }

    const job = (data as { job?: ScanJob } | null)?.job
    if (!job) return undefined
    return markJobRunning(job)
  }

  const job = [...getJobStore().values()]
    .filter((candidate) => candidate.status === "queued")
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0]
  if (!job) return undefined
  return markJobRunning(job)
}

export async function completeScanJob(jobId: string, reportId: string) {
  const job = await getScanJob(jobId)
  if (!job) return undefined

  const now = new Date().toISOString()
  const next: ScanJob = {
    ...job,
    reportId,
    status: "completed",
    updatedAt: now,
    completedAt: now,
  }
  getJobStore().set(next.id, next)
  await persistJob(next)
  await appendScanEvent({ reportId, jobId, label: "Scan job completed", status: "complete" })
  return next
}

export async function failScanJob(jobId: string, errorMessage: string) {
  const job = await getScanJob(jobId)
  if (!job) return undefined

  const now = new Date().toISOString()
  const next: ScanJob = {
    ...job,
    status: "failed",
    updatedAt: now,
    completedAt: now,
    error: errorMessage.slice(0, 500),
  }
  getJobStore().set(next.id, next)
  await persistJob(next)
  await appendScanEvent({ reportId: job.reportId, jobId, label: "Scan job failed", status: "failed", metadata: { error: next.error } })
  return next
}

export async function appendScanEvent(input: AppendScanEventInput): Promise<ScanEvent> {
  const event: ScanEvent = {
    id: crypto.randomUUID(),
    reportId: input.reportId,
    jobId: input.jobId,
    timestamp: new Date().toISOString(),
    label: input.label,
    status: input.status,
    metadata: input.metadata,
  }

  getEventStore().push(event)
  const supabase = await getSupabaseClient()
  if (supabase) {
    const { error } = await supabase.from(EVENTS_TABLE).insert({
      id: event.id,
      report_id: event.reportId,
      job_id: event.jobId ?? null,
      created_at: event.timestamp,
      label: event.label,
      status: event.status,
      metadata: event.metadata ?? {},
      event,
    })
    if (error) console.error("VibeShield Supabase event insert failed", error.message)
  }

  return event
}

export async function listScanEvents(reportId: string): Promise<ScanEvent[]> {
  const memoryEvents = getEventStore().filter((event) => event.reportId === reportId)
  const supabase = await getSupabaseClient()
  if (!supabase) return memoryEvents.sort(sortEvents)

  const { data, error } = await supabase
    .from(EVENTS_TABLE)
    .select("event")
    .eq("report_id", reportId)
    .order("created_at", { ascending: true })

  if (error) {
    console.error("VibeShield Supabase event list failed", error.message)
    return memoryEvents.sort(sortEvents)
  }

  const merged = [
    ...memoryEvents,
    ...(data as Array<{ event: ScanEvent }>).map((row) => row.event),
  ]
  return [...new Map(merged.map((event) => [event.id, event])).values()].sort(sortEvents)
}

export function backgroundJobsEnabled() {
  return process.env.VIBESHIELD_ENABLE_BACKGROUND_JOBS?.trim().toLowerCase() === "true"
}

async function markJobRunning(job: ScanJob) {
  const now = new Date().toISOString()
  const next: ScanJob = {
    ...job,
    status: "running",
    attempts: job.attempts + 1,
    startedAt: job.startedAt ?? now,
    updatedAt: now,
  }
  getJobStore().set(next.id, next)
  await persistJob(next)
  await appendScanEvent({ reportId: next.reportId, jobId: next.id, label: "Scan job started", status: "running", metadata: { attempts: next.attempts } })
  return next
}

async function getScanJob(jobId: string) {
  const memoryJob = getJobStore().get(jobId)
  if (memoryJob) return memoryJob

  const supabase = await getSupabaseClient()
  if (!supabase) return undefined

  const { data, error } = await supabase.from(JOBS_TABLE).select("job").eq("id", jobId).maybeSingle()
  if (error) {
    console.error("VibeShield Supabase job read failed", error.message)
    return undefined
  }
  return (data as { job?: ScanJob } | null)?.job
}

async function persistJob(job: ScanJob) {
  const supabase = await getSupabaseClient()
  if (!supabase) return

  const { error } = await supabase.from(JOBS_TABLE).upsert({
    id: job.id,
    report_id: job.reportId,
    owner_hash: job.ownerHash ?? null,
    created_at: job.createdAt,
    updated_at: job.updatedAt,
    started_at: job.startedAt ?? null,
    completed_at: job.completedAt ?? null,
    status: job.status,
    source_label: job.sourceLabel,
    analysis_mode: job.analysisMode,
    attempts: job.attempts,
    error: job.error ?? null,
    job,
  }, { onConflict: "id" })
  if (error) console.error("VibeShield Supabase job save failed", error.message)
}

function getJobStore() {
  jobGlobal.__vibeshieldScanJobs ??= new Map<string, ScanJob>()
  return jobGlobal.__vibeshieldScanJobs
}

function getEventStore() {
  jobGlobal.__vibeshieldScanEvents ??= []
  return jobGlobal.__vibeshieldScanEvents
}

function sortEvents(a: ScanEvent, b: ScanEvent) {
  return a.timestamp.localeCompare(b.timestamp)
}

async function getSupabaseClient() {
  if (!isSupabaseConfigured()) return null
  const { getSupabaseServiceClient } = await import("@/lib/supabase/server")
  return getSupabaseServiceClient()
}
