export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type FindingCategory =
  | "secret_exposure"
  | "public_env_misuse"
  | "missing_auth"
  | "ai_endpoint_risk"
  | "unsafe_tool_calling"
  | "mcp_risk"
  | "input_validation"
  | "client_data_exposure"
  | "dangerous_code"
  | "vercel_hardening"
  | "dependency_signal"

export interface PatchSuggestion {
  title: string
  summary: string
  before?: string
  after?: string
  unifiedDiff?: string
  reviewRequired: boolean
}

export interface FindingExplanation {
  summary: string
  impact: string
  fixSteps: string[]
  patch?: PatchSuggestion
}

export interface ScanRepositoryRef {
  owner: string
  repo: string
  ref: string
  defaultBranch: string
  private: boolean
  htmlUrl: string
}

export interface ScanPullRequest {
  url: string
  number: number
  branch: string
  base: string
  filesChanged: string[]
  appliedFixes: string[]
  skippedFixes: string[]
  createdAt: string
}

export interface ScanFinding {
  id: string
  severity: Severity
  category: FindingCategory
  title: string
  description: string
  filePath: string
  lineStart?: number
  lineEnd?: number
  evidence?: string
  confidence: number
  recommendation: string
  patchable: boolean
  patch?: PatchSuggestion
  explanation?: FindingExplanation
  source: "rule" | "ai" | "hybrid"
}

export interface AuditTrailEvent {
  id: string
  timestamp: string
  label: string
  status: "complete" | "running" | "failed"
  metadata?: Record<string, unknown>
}

export interface ScanReport {
  id: string
  createdAt: string
  projectName: string
  framework?: string
  repository?: ScanRepositoryRef
  pullRequest?: ScanPullRequest
  ownerHash?: string
  ownerKind?: "supabase_user" | "anonymous"
  sourceType: "github"
  sourceLabel: string
  status: "queued" | "running" | "completed" | "failed"
  riskScore: number
  filesInspected: number
  apiRoutesInspected: number
  clientComponentsInspected: number
  aiEndpointsInspected: number
  findings: ScanFinding[]
  auditTrail: AuditTrailEvent[]
  error?: string
}

export interface ProjectFile {
  path: string
  size: number
  text: string
}

export interface ExtractedProject {
  projectName: string
  files: ProjectFile[]
  auditTrail: AuditTrailEvent[]
}

export type SourceType = ScanReport["sourceType"]

export interface ScanInput {
  projectName: string
  sourceType: SourceType
  sourceLabel: string
  files: ProjectFile[]
  auditTrail?: AuditTrailEvent[]
}
