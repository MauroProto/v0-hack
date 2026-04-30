export type Severity = "critical" | "high" | "medium" | "low" | "info"
export type ScanMode = "rules" | "normal" | "max"
export type FindingKind = "vulnerability" | "hardening" | "repo_posture" | "platform_recommendation" | "info"
export type Reachability = "reachable" | "unknown" | "unreachable"
export type Exploitability = "high" | "medium" | "low" | "unknown"
export type BaselineState = "new" | "existing" | "resolved"
export type FindingTriageVerdict = "confirmed" | "needs_review" | "posture_only" | "likely_false_positive"
export type TriagePriority = "urgent" | "high" | "normal" | "low"
export type RiskBand = "None" | "Low" | "Moderate" | "High" | "Critical"

export type FindingCategory =
  | "secret_exposure"
  | "public_env_misuse"
  | "dependency_vulnerability"
  | "broken_access_control"
  | "missing_auth"
  | "missing_authentication"
  | "missing_authorization"
  | "ai_endpoint_risk"
  | "ai_prompt_injection_risk"
  | "ai_excessive_agency"
  | "ai_unbounded_consumption"
  | "unsafe_tool_calling"
  | "mcp_risk"
  | "input_validation"
  | "sql_injection"
  | "command_injection"
  | "ssrf"
  | "xss"
  | "unsafe_redirect"
  | "csrf"
  | "insecure_cookie"
  | "client_data_exposure"
  | "dangerous_code"
  | "server_action_risk"
  | "supabase_rls_risk"
  | "repo_security_posture"
  | "supply_chain_posture"
  | "platform_hardening"
  | "vercel_hardening"
  | "dependency_signal"

export interface TraceStep {
  filePath: string
  lineStart: number
  lineEnd?: number
  kind: "source" | "propagator" | "sanitizer" | "guard" | "sink"
  label: string
  code?: string
}

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

export interface FindingTriage {
  verdict: FindingTriageVerdict
  reason: string
  confidence: number
  reviewedBy: "ai" | "fallback"
  adjustedFrom?: {
    severity: Severity
    kind?: FindingKind
    category: FindingCategory
  }
  detectedControls?: string[]
  missingControls?: string[]
  attackScenario?: string
  priority?: TriagePriority
}

export interface RiskBreakdownBucket {
  score: number
  label: RiskBand
}

export interface RiskBreakdown {
  runtimeAgentRisk: RiskBreakdownBucket
  repoPostureRisk: RiskBreakdownBucket
  dependencyRisk: RiskBreakdownBucket
  secretsRisk: RiskBreakdownBucket
}

export interface ReportAiTriage {
  riskNarrative: string
  recommendedNextSteps: string[]
  model?: string
  provider?: string
  reviewedFindings: number
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
  kind?: FindingKind
  severity: Severity
  category: FindingCategory
  ruleId?: string
  title: string
  description: string
  filePath: string
  lineStart?: number
  lineEnd?: number
  evidence?: string
  confidence: number
  confidenceReason?: string
  reachability?: Reachability
  exploitability?: Exploitability
  evidenceTrace?: TraceStep[]
  cwe?: string
  owasp?: string
  asvs?: string
  fingerprint?: string
  suppressed?: boolean
  suppressionReason?: string
  baselineState?: BaselineState
  recommendation: string
  patchable: boolean
  patch?: PatchSuggestion
  explanation?: FindingExplanation
  triage?: FindingTriage
  source: "rule" | "ai" | "hybrid"
}

export interface AuditTrailEvent {
  id: string
  timestamp: string
  label: string
  status: "complete" | "running" | "failed"
  metadata?: Record<string, unknown>
}

export interface FindingGroups {
  vulnerabilities: number
  hardening: number
  repo_posture: number
  platform_recommendations: number
  informational: number
}

export interface DependencySummary {
  manifests: number
  lockfiles: number
  packages: number
  vulnerablePackages: number
  ecosystems: string[]
  osvEnabled: boolean
  error?: string
}

export interface RepoInventory {
  framework?: string
  languages: string[]
  routeHandlers: number
  serverActions: number
  clientComponents: number
  imports: number
  envReads: number
  authCalls: number
  validationCalls: number
  dangerousSinks: number
  aiCalls: number
  dbCalls: number
  githubWorkflows: number
  supabaseMigrations: number
  prismaSchemas: number
}

export interface BaselineSummary {
  new: number
  existing: number
  resolved: number
  suppressed: number
}

export interface ScanBaseline {
  id: string
  sourceLabel: string
  ownerHash?: string
  createdAt: string
  updatedAt: string
  fingerprints: string[]
  findingCount: number
  scannerVersion?: string
}

export interface ScanJob {
  id: string
  reportId: string
  ownerHash?: string
  projectName: string
  sourceLabel: string
  analysisMode: ScanMode
  status: "queued" | "running" | "completed" | "failed"
  createdAt: string
  updatedAt: string
  startedAt?: string
  completedAt?: string
  error?: string
  attempts: number
  repository: ScanRepositoryRef
}

export interface ScanEvent {
  id: string
  reportId: string
  jobId?: string
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
  ownerKind?: "supabase_user" | "github_user" | "anonymous"
  sourceType: "github"
  sourceLabel: string
  analysisMode: ScanMode
  status: "queued" | "running" | "completed" | "failed"
  jobId?: string
  riskScore: number
  baselineSummary?: BaselineSummary
  eventsAvailable?: boolean
  findingGroups?: FindingGroups
  dependencySummary?: DependencySummary
  repoInventory?: RepoInventory
  aiTriage?: ReportAiTriage
  riskBreakdown?: RiskBreakdown
  sarifAvailable?: boolean
  scannerVersion?: string
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
  analysisMode?: ScanMode
  files: ProjectFile[]
  auditTrail?: AuditTrailEvent[]
}
