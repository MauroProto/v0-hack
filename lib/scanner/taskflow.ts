import type { ProjectFile, ScanFinding, ScanReport } from "./types"

export interface SecurityTaskflow {
  profile: "standard" | "max"
  phases: string[]
  focusAreas: string[]
  reviewQuestions: string[]
  evidenceBudget: {
    filesInspected: number
    activeFindings: number
    maxTraceDepth: number
  }
}

export function buildSecurityTaskflow(report: ScanReport, files: ProjectFile[]): SecurityTaskflow {
  const activeFindings = report.findings.filter((finding) => !finding.suppressed)
  const focusAreas = buildFocusAreas(report, activeFindings)

  return {
    profile: report.analysisMode === "max" ? "max" : "standard",
    phases: [
      "inventory",
      "hypothesis generation",
      "evidence collection",
      "control and mitigation review",
      "false-positive triage",
      "risk prioritization",
      "remediation planning",
    ],
    focusAreas,
    reviewQuestions: buildReviewQuestions(focusAreas),
    evidenceBudget: {
      filesInspected: files.length,
      activeFindings: activeFindings.length,
      maxTraceDepth: report.analysisMode === "max" ? 5 : 3,
    },
  }
}

function buildFocusAreas(report: ScanReport, findings: ScanFinding[]) {
  const areas = new Set<string>()
  const inventory = report.repoInventory

  if (inventory?.serverActions || report.framework?.includes("Next")) areas.add("Next.js Server Actions and route authorization")
  if (inventory?.aiCalls || findings.some((finding) => /ai_|unsafe_tool_calling|mcp_risk/.test(finding.category))) {
    areas.add("AI endpoint, tool calling, MCP and agent runtime boundaries")
  }
  if (inventory?.supabaseMigrations || findings.some((finding) => finding.category === "supabase_rls_risk")) {
    areas.add("Supabase RLS, storage buckets and service-role exposure")
  }
  if (inventory?.githubWorkflows || findings.some((finding) => finding.category === "repo_security_posture")) {
    areas.add("GitHub Actions release, secret and supply-chain posture")
  }
  if (findings.some((finding) => finding.category === "secret_exposure" || finding.category === "public_env_misuse")) {
    areas.add("Committed secret candidates and browser-exposed env contracts")
  }
  if (findings.some((finding) => finding.category === "dependency_vulnerability" || finding.category === "dependency_signal")) {
    areas.add("Dependency advisories, maintenance risk and reachability")
  }
  if (findings.some((finding) => finding.category === "command_injection" || finding.category === "dangerous_code")) {
    areas.add("Dangerous sinks, command execution and source-to-sink traces")
  }
  if (findings.some((finding) => finding.category === "vercel_hardening" || finding.category === "platform_hardening")) {
    areas.add("Vercel and deployment hardening")
  }

  if (areas.size === 0) areas.add("Baseline static security posture")
  return [...areas]
}

function buildReviewQuestions(focusAreas: string[]) {
  const questions = new Set<string>()

  for (const area of focusAreas) {
    if (/AI|MCP|agent|tool/i.test(area)) {
      questions.add("Which tool or model-call surfaces are reachable, and what approval, sandbox, env-isolation, rate-limit or budget controls are visible?")
    }
    if (/Supabase|RLS/i.test(area)) {
      questions.add("Which public tables or buckets need RLS/policy evidence, and are service-role paths isolated to server-only code?")
    }
    if (/GitHub Actions|supply-chain/i.test(area)) {
      questions.add("Which workflows combine third-party actions with secrets or write permissions, and are refs pinned to immutable SHAs?")
    }
    if (/secret|env/i.test(area)) {
      questions.add("Is each secret signal a real committed value, an env var reference, a placeholder, a fixture, or detector/redaction code?")
    }
    if (/Vercel|deployment/i.test(area)) {
      questions.add("Do deployment configs expose source maps, unauthenticated cron endpoints, weak headers, or public env contracts?")
    }
    if (/Dangerous|command|sink/i.test(area)) {
      questions.add("Can user, request, model, repo config, or workflow input reach a dangerous sink without a sanitizer or guard?")
    }
  }

  questions.add("Which findings should be grouped as one root cause instead of counted repeatedly?")
  questions.add("What should be fixed first to reduce real exploitability without overpromising automatic patches?")
  return [...questions]
}
