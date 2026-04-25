import type { PatchSuggestion, ScanFinding, ScanReport } from "./types"

export function getRiskLabel(score: number) {
  if (score <= 19) return "Low"
  if (score <= 49) return "Moderate"
  if (score <= 79) return "Action required"
  return "Critical"
}

export function calculateRiskScore(findings: Pick<ScanFinding, "severity">[]) {
  const score = findings.reduce((total, finding) => {
    if (finding.severity === "critical") return total + 25
    if (finding.severity === "high") return total + 15
    if (finding.severity === "medium") return total + 7
    if (finding.severity === "low") return total + 3
    return total + 1
  }, 0)

  return Math.min(100, score)
}

export function createDeterministicPatch(finding: ScanFinding): PatchSuggestion | undefined {
  if (!finding.patchable) return undefined

  if (finding.category === "input_validation") {
    return {
      title: "Validate request body with Zod",
      summary: "Introduce a request schema and parse the JSON body before using it.",
      before: "const body = await req.json();",
      after: [
        "const BodySchema = z.object({",
        "  // TODO: define fields",
        "});",
        "",
        "const body = BodySchema.parse(await req.json());",
      ].join("\n"),
      unifiedDiff: [
        `--- a/${finding.filePath}`,
        `+++ b/${finding.filePath}`,
        "@@",
        "+import { z } from \"zod\";",
        "+",
        "+const BodySchema = z.object({",
        "+  // TODO: define fields",
        "+});",
        "+",
        "-const body = await req.json();",
        "+const body = BodySchema.parse(await req.json());",
      ].join("\n"),
      reviewRequired: true,
    }
  }

  if (finding.category === "missing_auth") {
    return {
      title: "Add a server-side auth guard",
      summary: "Require a validated user before returning sensitive route data.",
      before: "export async function GET() {",
      after: [
        "export async function GET() {",
        "  const user = await requireAuth();",
        "  if (!user) {",
        "    return NextResponse.json({ error: \"Unauthorized\" }, { status: 401 });",
        "  }",
      ].join("\n"),
      unifiedDiff: [
        `--- a/${finding.filePath}`,
        `+++ b/${finding.filePath}`,
        "@@",
        "+  const user = await requireAuth();",
        "+  if (!user) {",
        "+    return NextResponse.json({ error: \"Unauthorized\" }, { status: 401 });",
        "+  }",
      ].join("\n"),
      reviewRequired: true,
    }
  }

  if (finding.category === "ai_endpoint_risk") {
    return {
      title: "Add rate limiting before model calls",
      summary: "Check quota/abuse controls before invoking the AI model.",
      before: "const result = await streamText({",
      after: [
        "const allowed = await checkRateLimit(request);",
        "if (!allowed) {",
        "  return new Response(\"Too many requests\", { status: 429 });",
        "}",
        "",
        "const result = await streamText({",
      ].join("\n"),
      unifiedDiff: [
        `--- a/${finding.filePath}`,
        `+++ b/${finding.filePath}`,
        "@@",
        "+const allowed = await checkRateLimit(request);",
        "+if (!allowed) {",
        "+  return new Response(\"Too many requests\", { status: 429 });",
        "+}",
        "+",
      ].join("\n"),
      reviewRequired: true,
    }
  }

  if (finding.category === "public_env_misuse") {
    return {
      title: "Move public secret to server-only environment variable",
      summary: "Rename the variable without NEXT_PUBLIC_ and read it only from server code.",
      before: "NEXT_PUBLIC_OPENAI_API_KEY=...",
      after: "OPENAI_API_KEY=...",
      unifiedDiff: [
        `--- a/${finding.filePath}`,
        `+++ b/${finding.filePath}`,
        "@@",
        "-NEXT_PUBLIC_*SECRET*=...",
        "+SERVER_ONLY_SECRET=...",
      ].join("\n"),
      reviewRequired: true,
    }
  }

  if (finding.category === "secret_exposure") {
    return {
      title: "Remove committed secret and rotate it",
      summary: "Delete the committed value, rotate the credential, and load it from server-only environment variables.",
      before: finding.evidence,
      after: "SECRET_NAME=...redacted-placeholder",
      reviewRequired: true,
    }
  }

  if (finding.category === "unsafe_tool_calling" || finding.category === "mcp_risk") {
    return {
      title: "Replace dynamic tool dispatch with an allowlist",
      summary: "Validate the requested tool name against a fixed map before dispatching.",
      before: "const tool = tools[input.tool];",
      after: [
        "const ToolNameSchema = z.enum([\"search\", \"summarize\"]);",
        "const toolName = ToolNameSchema.parse(input.tool);",
        "const tool = tools[toolName];",
      ].join("\n"),
      unifiedDiff: [
        `--- a/${finding.filePath}`,
        `+++ b/${finding.filePath}`,
        "@@",
        "+const ToolNameSchema = z.enum([\"search\", \"summarize\"]);",
        "+const toolName = ToolNameSchema.parse(input.tool);",
        "-const tool = tools[input.tool];",
        "+const tool = tools[toolName];",
      ].join("\n"),
      reviewRequired: true,
    }
  }

  return undefined
}

export function generateIssueBody(report: ScanReport) {
  const topFindings = [...report.findings]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 10)

  const lines = [
    "# VibeShield security scan",
    "",
    `**Project:** ${report.projectName}`,
    `**Source:** ${report.sourceLabel}`,
    `**Risk score:** ${report.riskScore}/100 (${getRiskLabel(report.riskScore)})`,
    `**Files inspected:** ${report.filesInspected}`,
    `**Findings:** ${report.findings.length}`,
    "",
    "## Top findings",
    "",
    ...topFindings.flatMap((finding) => [
      `- **${finding.severity.toUpperCase()}** ${finding.title}`,
      `  - File: \`${formatFindingLocation(finding)}\``,
      `  - Category: \`${finding.category}\``,
      `  - Recommendation: ${finding.recommendation}`,
    ]),
    "",
    "## Recommended next steps",
    "",
    "1. Rotate any exposed credentials and remove committed `.env` files.",
    "2. Add server-side auth guards to sensitive API routes.",
    "3. Add rate limits and abuse controls before AI model calls.",
    "4. Validate request bodies with schemas before using user input.",
    "5. Review generated patch suggestions before applying them.",
    "",
    "_Generated by VibeShield._",
  ]

  return lines.join("\n")
}

function formatFindingLocation(finding: ScanFinding) {
  if (!finding.lineStart) return finding.filePath
  return `${finding.filePath}:${finding.lineStart}`
}

function severityRank(severity: ScanFinding["severity"]) {
  if (severity === "critical") return 5
  if (severity === "high") return 4
  if (severity === "medium") return 3
  if (severity === "low") return 2
  return 1
}
