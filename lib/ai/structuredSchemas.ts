import { z } from "zod"

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"])
const KindSchema = z.enum(["vulnerability", "hardening", "repo_posture", "platform_recommendation", "info"])
const TriageVerdictSchema = z.enum(["confirmed", "needs_review", "posture_only", "likely_false_positive"])
const TriagePrioritySchema = z.enum(["urgent", "high", "normal", "low"])
const RiskBandSchema = z.enum(["none", "low", "medium", "moderate", "high", "critical"])
const MaxLaunchVerdictSchema = z.enum(["ready", "needs_attention", "blocked"])
const MaxLaunchSectionStatusSchema = z.enum(["pass", "watch", "action_required"])
const CategorySchema = z.enum([
  "secret_exposure",
  "public_env_misuse",
  "dependency_vulnerability",
  "broken_access_control",
  "missing_auth",
  "missing_authentication",
  "missing_authorization",
  "ai_endpoint_risk",
  "ai_prompt_injection_risk",
  "ai_excessive_agency",
  "ai_unbounded_consumption",
  "unsafe_tool_calling",
  "mcp_risk",
  "input_validation",
  "sql_injection",
  "command_injection",
  "ssrf",
  "xss",
  "unsafe_redirect",
  "csrf",
  "insecure_cookie",
  "client_data_exposure",
  "dangerous_code",
  "server_action_risk",
  "supabase_rls_risk",
  "repo_security_posture",
  "supply_chain_posture",
  "platform_hardening",
  "vercel_hardening",
  "dependency_signal",
])

export const AiReviewSchema = z.object({
  triage: z
    .array(
      z.object({
        findingId: z.string(),
        verdict: TriageVerdictSchema,
        reason: z.string(),
        adjustedSeverity: SeveritySchema.optional(),
        adjustedKind: KindSchema.optional(),
        adjustedCategory: CategorySchema.optional(),
        confidence: z.number(),
        detectedControls: z.array(z.string()).optional(),
        missingControls: z.array(z.string()).optional(),
        attackScenario: z.string().optional(),
        priority: TriagePrioritySchema.optional(),
      }),
    )
    .optional(),
  reportSummary: z
    .object({
      riskNarrative: z.string(),
      recommendedNextSteps: z.array(z.string()).optional(),
      runtimeAgentRisk: RiskBandSchema.optional(),
      repoPostureRisk: RiskBandSchema.optional(),
      dependencyRisk: RiskBandSchema.optional(),
      secretsRisk: RiskBandSchema.optional(),
    })
    .optional(),
  maxLaunchReview: z
    .object({
      verdict: MaxLaunchVerdictSchema,
      summary: z.string(),
      sections: z.array(
        z.object({
          area: z.string(),
          status: MaxLaunchSectionStatusSchema,
          summary: z.string(),
          evidence: z.array(z.string()),
          recommendations: z.array(z.string()),
        }),
      ),
    })
    .optional(),
  findings: z
    .array(
      z.object({
        severity: SeveritySchema,
        category: CategorySchema,
        title: z.string(),
        description: z.string(),
        filePath: z.string(),
        lineStart: z.number().optional(),
        evidence: z.string(),
        confidence: z.number(),
        recommendation: z.string(),
      }),
    )
    .optional(),
})

export const ExplanationSchema = z.object({
  summary: z.string(),
  impact: z.string(),
  fixSteps: z.array(z.string()).optional(),
  patch: z
    .object({
      title: z.string(),
      summary: z.string(),
      unifiedDiff: z.string().optional(),
      reviewRequired: z.literal(true),
    })
    .optional(),
})

export const PatchSchema = z.object({
  title: z.string(),
  summary: z.string(),
  unifiedDiff: z.string().optional(),
  reviewRequired: z.literal(true),
})

export const PullRequestCopySchema = z.object({
  title: z.string(),
  body: z.string(),
  reportExecutiveSummary: z.string(),
})

export const PullRequestSafetyReviewSchema = z.object({
  decision: z.enum(["approve", "revise", "block"]),
  approved: z.boolean(),
  summary: z.string(),
  blockingReasons: z.array(z.string()).optional(),
  requiredChanges: z.array(z.string()).optional(),
  revisedTitle: z.string().optional(),
  revisedBody: z.string().optional(),
})

export type AiReviewOutput = z.infer<typeof AiReviewSchema>
export type AiFindingCandidate = NonNullable<AiReviewOutput["findings"]>[number]
export type PullRequestSafetyReviewOutput = z.infer<typeof PullRequestSafetyReviewSchema>
