import { readFile, readdir } from "node:fs/promises"
import path from "node:path"
import { getSystemHealth } from "../lib/system/health"
import {
  appendScanEvent,
  claimNextScanJob,
  completeScanJob,
  createScanJob,
  failScanJob,
  listScanEvents,
} from "../lib/scanner/jobs"
import {
  applyReportPolicy,
  createBaselineFromReport,
} from "../lib/scanner/reportPolicy"
import { compareProjectPathPriority, shouldConsiderProjectPath } from "../lib/scanner/extract"
import { scanDependencies } from "../lib/scanner/dependencies"
import { generateFullReportBody, generateIssueBody } from "../lib/scanner/patches"
import { scanProject } from "../lib/scanner/scan"
import type { ProjectFile, ScanFinding, ScanReport } from "../lib/scanner/types"
import { applyAiTriage } from "../lib/ai/triage"

const fixtureRoot = path.join(process.cwd(), "examples", "vulnerable-next-app")

async function main() {
  const files = await readProjectFiles(fixtureRoot)
  const previousOsv = process.env.VIBESHIELD_ENABLE_OSV
  process.env.VIBESHIELD_ENABLE_OSV = "false"

  try {
    const report = await scanProject({
      projectName: "vulnerable-next-app",
      sourceType: "github",
      sourceLabel: "fixture://vulnerable-next-app",
      analysisMode: "rules",
      files,
    })

    assert(report.repoInventory?.serverActions, "expected server action inventory")
    assert(report.repoInventory?.supabaseMigrations, "expected Supabase migration inventory")
    assert(report.findings.some((finding) => finding.category === "server_action_risk"), "expected server action finding")
    assert(report.findings.some((finding) => finding.category === "supabase_rls_risk"), "expected Supabase RLS finding")
    assert(report.findings.some((finding) => finding.category === "repo_security_posture"), "expected GitHub Actions posture finding")
    assert(report.findings.some((finding) => finding.evidenceTrace?.length), "expected at least one evidence trace")
    assert(report.findingGroups && report.findingGroups.vulnerabilities > 0, "expected vulnerability grouping")

    await assertReadmePlaceholdersDoNotBecomeSecrets()
    await assertEnvVarReferencesDoNotBecomeSecrets()
    await assertSecretFixturesAndRedactionPatternsDoNotBecomeCritical()
    await assertFixedRustCommandIsPostureOnly()
    await assertUserControlledRustCommandIsVulnerability()
    await assertInternalRustCommandBuilderIsNotCommandInjection()
    await assertAgentShellAndMcpRisksAreClassified()
    await assertHighAgentRisksWithoutCriticalDoNotReachCriticalScore()
    await assertTrivialUnsafeRustIsInventoryOnly()
    await assertRemoteInstallPipeToShellIsPosture()
    await assertGithubActionsGroupsUnpinnedActionsByWorkflow()
    await assertGithubOwnedCheckoutOnlyWorkflowIsLowerPostureRisk()
    assertLargeRepoFilePriorityKeepsSecurityFiles()
    await assertOsvUnmaintainedAdvisoryIsPosture()
    await assertAuthCallWithoutGuardStillFindsSensitiveRoute()
    await assertGuardedSensitiveRouteIsNotReported()
    await assertDecorativeZodDoesNotHideRawBodyUse()
    await assertInlineZodParseIsAccepted()
    await assertInterfileTaintFindsRouteServiceDbTrace()
    await assertInterfileTaintIgnoresValidatedFlow()
    await assertVibeshieldIgnoreSuppressesFindingsAndRisk()
    await assertBaselineMarksNewExistingResolved()
    assertAiTriageCanDowngradeAmbiguousProcessFinding()
    assertAiTriageCannotHideCriticalSecretEvidence()
    assertIssueBodyUsesContextAwareAgentNextSteps()
    assertFullReportCopyIncludesEveryFinding()
    await assertScanJobsAndEventsLifecycle()
    assertHealthStatusIsSecretFree()

    console.log(JSON.stringify({
      files: report.filesInspected,
      findings: report.findings.length,
      riskScore: report.riskScore,
      groups: report.findingGroups,
      inventory: report.repoInventory,
    }, null, 2))
  } finally {
    if (previousOsv === undefined) delete process.env.VIBESHIELD_ENABLE_OSV
    else process.env.VIBESHIELD_ENABLE_OSV = previousOsv
  }
}

function assertLargeRepoFilePriorityKeepsSecurityFiles() {
  const paths = [
    "docs/page-001.md",
    "tests/fixture.test.ts",
    "src/components/Button.tsx",
    "LICENSE",
    ".github/workflows/release.yml",
    "package.json",
    "app/api/admin/users/route.ts",
    "supabase/migrations/001_rls.sql",
    "README.md",
  ].sort(compareProjectPathPriority)

  assert(paths.indexOf(".github/workflows/release.yml") < paths.indexOf("docs/page-001.md"), "workflow files should outrank low-value docs in large repos")
  assert(paths.indexOf("app/api/admin/users/route.ts") < paths.indexOf("tests/fixture.test.ts"), "sensitive API routes should outrank tests in large repos")
  assert(paths.indexOf("package.json") < paths.indexOf("LICENSE"), "manifests should outrank license files in large repos")
}

async function assertReadmePlaceholdersDoNotBecomeSecrets() {
  const report = await scanProject({
    projectName: "readme-placeholders",
    sourceType: "github",
    sourceLabel: "fixture://readme-placeholders",
    analysisMode: "rules",
    files: [
      {
        path: "README.md",
        size: 181,
        text: [
          "# Setup",
          "DATABASE_URL=postgres://user:password@localhost:5432/app",
          "OPENAI_API_KEY=sk-demo-redacted",
          "NEXT_PUBLIC_OPENAI_API_KEY=sk-demo-redacted",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "secret_exposure"), "README placeholders must not be reported as secrets")
  assert(!report.findings.some((finding) => finding.category === "public_env_misuse"), "README NEXT_PUBLIC placeholders must not be reported as public env misuse")
}

async function assertEnvVarReferencesDoNotBecomeSecrets() {
  const report = await scanProject({
    projectName: "rust-env-reference",
    sourceType: "github",
    sourceLabel: "fixture://rust-env-reference",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 36, text: "[package]\nname = \"envref\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/auth/codex.rs",
        size: 172,
        text: [
          "pub fn load_env_api_key() -> Option<String> {",
          "  std::env::var(\"OPENAI_API_KEY\").ok().map(|value| value.trim().to_string())",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "secret_exposure"), "env var references must not be reported as leaked secrets")
}

async function assertSecretFixturesAndRedactionPatternsDoNotBecomeCritical() {
  const report = await scanProject({
    projectName: "secret-fixtures",
    sourceType: "github",
    sourceLabel: "fixture://secret-fixtures",
    analysisMode: "rules",
    files: [
      {
        path: "src/auth/external_tests.rs",
        size: 181,
        text: [
          "#[test]",
          "fn env_ref_fixture() {",
          "  let value = \"sk-from-env-ref\";",
          "  assert_eq!(value, \"sk-from-env-ref\");",
          "}",
        ].join("\n"),
      },
      {
        path: "src/session_tests/cases.rs",
        size: 231,
        text: [
          "#[test]",
          "fn redaction_case() {",
          "  let command = \"OPENROUTER_API_KEY=sk-or-v1-fake-redacted ghp_1234567890abcdef1234567890abcdef\";",
          "  assert!(command.contains(\"ghp_1234567890abcdef1234567890abcdef\"));",
          "}",
        ].join("\n"),
      },
      {
        path: "src/message/tests.rs",
        size: 151,
        text: [
          "#[test]",
          "fn redacts_provider_tokens() {",
          "  let input = \"access=sk-ant-api03-fakefixture\\nopenrouter=sk-or-v1-fakefixture\\ngithub=ghp_1234567890abcdef1234567890abcdef\\n\";",
          "}",
        ].join("\n"),
      },
      {
        path: "src/message.rs",
        size: 250,
        text: [
          "fn compile_static_regexes() {",
          "  let patterns = vec![r\"sk-[A-Za-z0-9_-]{10,}\", r\"ghp_[A-Za-z0-9_]{20,}\"];",
          "  let redacted = redact_secrets(\"token\");",
          "  assert!(!redacted.contains(\"sk-\"));",
          "}",
        ].join("\n"),
      },
      {
        path: "src/provider/copilot.rs",
        size: 112,
        text: "pub fn load(auth: Auth) {\n  let github_token = auth.github_token.clone();\n  let token_name = \"GITHUB_TOKEN\";\n}\n",
      },
      {
        path: "assets/demos/timeline.json",
        size: 91,
        text: "{\"event\":\"spawn command shown in a recorded demo, not executable source code\"}\n",
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "secret_exposure" && finding.severity === "critical"), "test fixtures and redaction patterns must not become critical secrets")
  assert(!report.findings.some((finding) => finding.category === "dangerous_code" && finding.filePath.endsWith(".json")), "JSON assets must not be scanned as executable dangerous code")
}

async function assertFixedRustCommandIsPostureOnly() {
  const report = await scanProject({
    projectName: "rust-fixed-command",
    sourceType: "github",
    sourceLabel: "fixture://rust-fixed-command",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 33, text: "[package]\nname = \"fixed\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/main.rs",
        size: 112,
        text: 'use std::process::Command;\nfn main() {\n  let output = Command::new("git").arg("status").output();\n}\n',
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.kind === "vulnerability" && finding.title === "Rust process execution detected"), "fixed Rust command should not be a vulnerability")
}

async function assertUserControlledRustCommandIsVulnerability() {
  const report = await scanProject({
    projectName: "rust-tainted-command",
    sourceType: "github",
    sourceLabel: "fixture://rust-tainted-command",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 35, text: "[package]\nname = \"tainted\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/main.rs",
        size: 148,
        text: 'use std::process::Command;\nfn run(user_command: String) {\n  let output = Command::new(user_command).arg("--version").output();\n}\n',
      },
    ],
  })

  assert(report.findings.some((finding) => finding.category === "command_injection" && finding.kind === "vulnerability"), "user-controlled Rust command should be a command injection finding")
}

async function assertInternalRustCommandBuilderIsNotCommandInjection() {
  const report = await scanProject({
    projectName: "rust-internal-command-builder",
    sourceType: "github",
    sourceLabel: "fixture://rust-internal-command-builder",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 38, text: "[package]\nname = \"selfdev\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/tool/selfdev/build_queue.rs",
        size: 320,
        text: [
          "use tokio::process::Command;",
          "use crate::tool::selfdev::build;",
          "pub async fn run(repo_dir: &std::path::Path) {",
          "  let command = build::selfdev_build_command(repo_dir);",
          "  let _ = Command::new(&command.program).args(&command.args).output().await;",
          "}",
        ].join("\n"),
      },
      {
        path: "src/tool/selfdev/build.rs",
        size: 260,
        text: [
          "pub fn selfdev_build_command(repo_dir: &std::path::Path) -> BuildCommand {",
          "  if repo_dir.join(\"scripts/dev_cargo.sh\").exists() {",
          "    return BuildCommand { program: \"bash\".into(), args: vec![\"scripts/dev_cargo.sh\".into()] }",
          "  }",
          "  BuildCommand { program: \"cargo\".into(), args: vec![\"build\".into()] }",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "command_injection"), "internal selfdev command builder should not be called command injection")
  assert(report.findings.some((finding) => finding.ruleId === "rust.process.internal-builder-review" && finding.kind === "repo_posture"), "internal process builder should be posture review")
}

async function assertAgentShellAndMcpRisksAreClassified() {
  const report = await scanProject({
    projectName: "agent-tooling-risks",
    sourceType: "github",
    sourceLabel: "fixture://agent-tooling-risks",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 36, text: "[package]\nname = \"agent\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/tool/bash.rs",
        size: 361,
        text: [
          "use std::process::Command;",
          "pub struct BashToolInput { pub command: String }",
          "pub fn run(input: BashToolInput) {",
          "  let cmd_str = input.command;",
          "  let _ = Command::new(\"bash\").arg(\"-c\").arg(cmd_str).output();",
          "}",
        ].join("\n"),
      },
      {
        path: "src/mcp/client.rs",
        size: 420,
        text: [
          "use std::collections::HashMap;",
          "use std::process::Command;",
          "pub struct McpConfig { pub command: String, pub args: Vec<String>, pub env: HashMap<String, String> }",
          "pub fn connect(config: McpConfig) {",
          "  let mut env: HashMap<String, String> = std::env::vars().collect();",
          "  env.extend(config.env);",
          "  let _child = Command::new(&config.command).args(&config.args).envs(&env).spawn();",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(report.findings.some((finding) => finding.ruleId === "agent.shell.tool-command-execution" && finding.category === "unsafe_tool_calling"), "agent bash shell execution should be classified as agent/tool risk")
  assert(report.findings.some((finding) => finding.ruleId === "agent.shell.tool-command-execution" && /Detected controls|Missing or unclear controls/i.test(finding.description)), "agent shell finding should summarize detected and missing mitigations")
  assert(report.findings.some((finding) => finding.ruleId === "mcp.process.config-command" && (finding.evidenceTrace?.length ?? 0) >= 2), "MCP config-driven process spawn should include trace evidence")
  assert(report.findings.some((finding) => finding.ruleId === "mcp.process.inherits-full-env" && (finding.evidenceTrace?.length ?? 0) >= 2), "MCP full environment inheritance should include trace evidence")
}

async function assertHighAgentRisksWithoutCriticalDoNotReachCriticalScore() {
  const report = await scanProject({
    projectName: "agent-risk-score",
    sourceType: "github",
    sourceLabel: "fixture://agent-risk-score",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 36, text: "[package]\nname = \"agent\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/tool/bash.rs",
        size: 220,
        text: "use std::process::Command;\npub struct BashToolInput { pub command: String }\npub fn run(input: BashToolInput) {\n  let approval_policy = true;\n  let cmd_str = input.command;\n  let _ = Command::new(\"bash\").arg(\"-c\").arg(cmd_str).output();\n}\n",
      },
      {
        path: "src/mcp/client.rs",
        size: 300,
        text: "use std::process::Command;\npub struct McpConfig { pub command: String, pub args: Vec<String> }\npub fn connect(config: McpConfig) {\n  let env = std::env::vars().collect::<std::collections::HashMap<_, _>>();\n  let _ = Command::new(&config.command).args(&config.args).envs(&env).spawn();\n}\n",
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.severity === "critical"), "fixture should contain no critical findings")
  assert(report.riskScore <= 79, "high agent review findings without critical evidence should not produce a Critical score band")
}

async function assertTrivialUnsafeRustIsInventoryOnly() {
  const report = await scanProject({
    projectName: "rust-trivial-unsafe",
    sourceType: "github",
    sourceLabel: "fixture://rust-trivial-unsafe",
    analysisMode: "rules",
    files: [
      { path: "Cargo.toml", size: 39, text: "[package]\nname = \"unsafe\"\nversion = \"0.1.0\"\n" },
      {
        path: "src/platform.rs",
        size: 95,
        text: "pub fn uid() -> u32 {\n  unsafe { libc::geteuid() as u32 }\n}\n",
      },
    ],
  })

  const finding = report.findings.find((item) => item.ruleId === "rust.unsafe.inventory")
  assert(finding, "expected unsafe Rust inventory finding")
  assert((finding.kind ?? "info") !== "vulnerability", "trivial unsafe blocks should not be treated as vulnerabilities")
}

async function assertRemoteInstallPipeToShellIsPosture() {
  const report = await scanProject({
    projectName: "remote-install-doc",
    sourceType: "github",
    sourceLabel: "fixture://remote-install-doc",
    analysisMode: "rules",
    files: [
      {
        path: "README.md",
        size: 97,
        text: "# Install\n\ncurl -fsSL https://example.com/scripts/install.sh | bash\n",
      },
    ],
  })

  const finding = report.findings.find((item) => item.ruleId === "supply-chain.remote-install-piped-shell")
  assert(finding, "expected remote install pipe-to-shell posture finding")
  assert(finding.kind === "repo_posture", "remote install documentation should be repo posture, not app vulnerability")
  assert(finding.category === "supply_chain_posture", "remote install documentation should be supply-chain posture, not dependency signal")
}

async function assertGithubActionsGroupsUnpinnedActionsByWorkflow() {
  const report = await scanProject({
    projectName: "workflow-unpinned",
    sourceType: "github",
    sourceLabel: "fixture://workflow-unpinned",
    analysisMode: "rules",
    files: [
      {
        path: ".github/workflows/release.yml",
        size: 430,
        text: [
          "name: release",
          "on: push",
          "permissions:",
          "  contents: write",
          "jobs:",
          "  release:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "      - uses: dtolnay/rust-toolchain@stable",
          "      - uses: softprops/action-gh-release@v2",
          "        env:",
          "          HOMEBREW_DEPLOY_KEY: ${{ secrets.HOMEBREW_DEPLOY_KEY }}",
        ].join("\n"),
      },
    ],
  })

  const grouped = report.findings.find((item) => item.ruleId === "github-actions.unpinned-actions.grouped")
  assert(grouped, "expected grouped unpinned workflow action finding")
  assert(grouped.severity === "high", "release workflow with third-party actions and secrets/write permissions should be high posture risk")
  assert(/3 unpinned action refs/i.test(grouped.evidence ?? ""), "grouped finding should summarize action count")
  assert((grouped.evidenceTrace?.length ?? 0) >= 3, "grouped workflow finding should retain per-action trace locations")
  assert(!report.findings.some((item) => item.ruleId === "github-actions.unpinned-action"), "individual unpinned action findings should be grouped")
}

async function assertGithubOwnedCheckoutOnlyWorkflowIsLowerPostureRisk() {
  const report = await scanProject({
    projectName: "workflow-checkout-only",
    sourceType: "github",
    sourceLabel: "fixture://workflow-checkout-only",
    analysisMode: "rules",
    files: [
      {
        path: ".github/workflows/ci.yml",
        size: 210,
        text: [
          "name: ci",
          "on: pull_request",
          "jobs:",
          "  test:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "      - run: cargo test",
        ].join("\n"),
      },
    ],
  })

  const grouped = report.findings.find((item) => item.ruleId === "github-actions.unpinned-actions.grouped")
  assert(grouped, "expected grouped GitHub-owned action posture finding")
  assert(grouped.severity === "low", "GitHub-owned checkout-only workflow should be lower posture risk")
  assert(grouped.exploitability === "low", "GitHub-owned checkout-only workflow should be low exploitability")
}

async function assertOsvUnmaintainedAdvisoryIsPosture() {
  const originalFetch = globalThis.fetch
  const previousOsv = process.env.VIBESHIELD_ENABLE_OSV
  process.env.VIBESHIELD_ENABLE_OSV = "true"
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({
      results: [
        {
          vulns: [
            {
              id: "RUSTSEC-2025-0141",
              summary: "bincode is unmaintained",
              details: "The crate is unmaintained and has no patched versions.",
              database_specific: { severity: "INFO" },
            },
          ],
        },
      ],
    }), { status: 200, headers: { "Content-Type": "application/json" } })) as typeof fetch

  try {
    const result = await scanDependencies([
      {
        path: "Cargo.lock",
        size: 61,
        text: "[[package]]\nname = \"bincode\"\nversion = \"1.3.3\"\n",
      },
    ])
    const finding = result.findings[0]
    assert(finding, "expected OSV finding from mocked advisory")
    assert(finding.category === "dependency_signal", "unmaintained advisory should be dependency posture signal")
    assert(finding.kind === "repo_posture", "unmaintained advisory should not be an app vulnerability")
    assert(finding.severity === "info" || finding.severity === "low", "unmaintained advisory should be info/low severity")
  } finally {
    globalThis.fetch = originalFetch
    if (previousOsv === undefined) delete process.env.VIBESHIELD_ENABLE_OSV
    else process.env.VIBESHIELD_ENABLE_OSV = previousOsv
  }
}

async function assertAuthCallWithoutGuardStillFindsSensitiveRoute() {
  const report = await scanProject({
    projectName: "auth-call-without-guard",
    sourceType: "github",
    sourceLabel: "fixture://auth-call-without-guard",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/admin/users/route.ts",
        size: 213,
        text: [
          "import { auth } from '@/auth'",
          "import { prisma } from '@/lib/db'",
          "export async function GET() {",
          "  const session = await getServerSession()",
          "  return Response.json(await prisma.user.findMany())",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(report.findings.some((finding) => finding.category === "missing_auth" || finding.category === "missing_authorization"), "auth() without a guard must still be reported on sensitive routes")
}

async function assertGuardedSensitiveRouteIsNotReported() {
  const report = await scanProject({
    projectName: "guarded-admin-route",
    sourceType: "github",
    sourceLabel: "fixture://guarded-admin-route",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/admin/users/route.ts",
        size: 295,
        text: [
          "import { getServerSession } from 'next-auth'",
          "import { prisma } from '@/lib/db'",
          "export async function GET() {",
          "  const session = await getServerSession()",
          "  if (!session?.user) return Response.json({ error: 'Unauthorized' }, { status: 401 })",
          "  return Response.json(await prisma.user.findMany())",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "missing_auth" || finding.category === "missing_authorization"), "guarded sensitive route should not be reported as missing auth")
}

async function assertDecorativeZodDoesNotHideRawBodyUse() {
  const report = await scanProject({
    projectName: "decorative-zod",
    sourceType: "github",
    sourceLabel: "fixture://decorative-zod",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/contact/route.ts",
        size: 340,
        text: [
          "import { z } from 'zod'",
          "import { prisma } from '@/lib/db'",
          "const BodySchema = z.object({ email: z.string().email() })",
          "export async function POST(request: Request) {",
          "  const body = await request.json()",
          "  BodySchema.safeParse({ email: 'nobody@example.com' })",
          "  await prisma.lead.create({ data: body })",
          "  return Response.json({ ok: true })",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(report.findings.some((finding) => finding.category === "input_validation"), "decorative Zod usage must not hide raw body use")
}

async function assertInlineZodParseIsAccepted() {
  const report = await scanProject({
    projectName: "inline-zod-parse",
    sourceType: "github",
    sourceLabel: "fixture://inline-zod-parse",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/contact/route.ts",
        size: 308,
        text: [
          "import { z } from 'zod'",
          "import { prisma } from '@/lib/db'",
          "const BodySchema = z.object({ email: z.string().email() })",
          "export async function POST(request: Request) {",
          "  const body = BodySchema.parse(await request.json())",
          "  await prisma.lead.create({ data: body })",
          "  return Response.json({ ok: true })",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "input_validation" && /JSON|body|Zod|schema/i.test(finding.title)), "inline Zod parse should not be reported as missing validation")
}

async function assertInterfileTaintFindsRouteServiceDbTrace() {
  const report = await scanProject({
    projectName: "interfile-taint",
    sourceType: "github",
    sourceLabel: "fixture://interfile-taint",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/search/route.ts",
        size: 172,
        text: [
          "import { searchUsers } from '@/lib/users'",
          "export async function POST(request: Request) {",
          "  const body = await request.json()",
          "  return Response.json(await searchUsers(body))",
          "}",
        ].join("\n"),
      },
      {
        path: "lib/users.ts",
        size: 129,
        text: [
          "import { findUsersByEmail } from '@/lib/db'",
          "export async function searchUsers(input: { email: string }) {",
          "  return findUsersByEmail(input.email)",
          "}",
        ].join("\n"),
      },
      {
        path: "lib/db.ts",
        size: 146,
        text: [
          "import { prisma } from '@/lib/prisma'",
          "export async function findUsersByEmail(email: string) {",
          "  return prisma.$queryRawUnsafe(`select * from users where email = '${email}'`)",
          "}",
        ].join("\n"),
      },
    ],
  })

  const finding = report.findings.find((item) => item.ruleId === "taint.interfile.request-to-dangerous-sink")
  assert(finding, "expected inter-file source-to-sink finding")
  assert((finding.evidenceTrace?.length ?? 0) >= 3, "expected inter-file trace with source, propagator, and sink")
}

async function assertInterfileTaintIgnoresValidatedFlow() {
  const report = await scanProject({
    projectName: "interfile-validated",
    sourceType: "github",
    sourceLabel: "fixture://interfile-validated",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/search/route.ts",
        size: 246,
        text: [
          "import { z } from 'zod'",
          "import { searchUsers } from '@/lib/users'",
          "const BodySchema = z.object({ email: z.string().email() })",
          "export async function POST(request: Request) {",
          "  const body = BodySchema.parse(await request.json())",
          "  return Response.json(await searchUsers(body))",
          "}",
        ].join("\n"),
      },
      {
        path: "lib/users.ts",
        size: 129,
        text: [
          "import { findUsersByEmail } from '@/lib/db'",
          "export async function searchUsers(input: { email: string }) {",
          "  return findUsersByEmail(input.email)",
          "}",
        ].join("\n"),
      },
      {
        path: "lib/db.ts",
        size: 146,
        text: [
          "import { prisma } from '@/lib/prisma'",
          "export async function findUsersByEmail(email: string) {",
          "  return prisma.$queryRawUnsafe(`select * from users where email = '${email}'`)",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((item) => item.ruleId === "taint.interfile.request-to-dangerous-sink"), "validated inter-file flow should not be reported")
}

async function assertVibeshieldIgnoreSuppressesFindingsAndRisk() {
  const files: ProjectFile[] = [
    { path: ".env.local", size: 35, text: "OPENAI_API_KEY=sk-demo-redacted\n" },
    {
      path: "app/api/admin/users/route.ts",
      size: 111,
      text: "export async function GET() {\n  return Response.json([{ email: 'admin@example.com' }])\n}\n",
    },
    {
      path: ".vibeshieldignore",
      size: 93,
      text: [
        "# Suppress the committed env fixture and any admin path finding",
        "category:secret_exposure",
        "category:vercel_hardening",
        "category:platform_hardening",
        "path:app/api/admin/**",
      ].join("\n"),
    },
  ]
  const raw = await scanProject({
    projectName: "suppression-fixture",
    sourceType: "github",
    sourceLabel: "fixture://suppression-fixture",
    analysisMode: "rules",
    files,
  })
  const report = applyReportPolicy(raw, files)

  assert(report.findings.some((finding) => finding.suppressed), "expected suppressed findings")
  assert((report.baselineSummary?.suppressed ?? 0) >= 1, "expected suppressed summary count")
  assert(report.riskScore === 0, "suppressed findings should not contribute to risk score")
}

async function assertBaselineMarksNewExistingResolved() {
  const baseReport = await scanProject({
    projectName: "baseline-v1",
    sourceType: "github",
    sourceLabel: "github.com/acme/app#main",
    analysisMode: "rules",
    files: [
      { path: ".env.local", size: 34, text: "STRIPE_SECRET_KEY=sk_test_fake\n" },
      {
        path: "app/api/admin/users/route.ts",
        size: 77,
        text: "export async function GET() {\n  return Response.json([])\n}\n",
      },
    ],
  })
  const baseline = createBaselineFromReport(baseReport)
  const nextReport = await scanProject({
    projectName: "baseline-v2",
    sourceType: "github",
    sourceLabel: "github.com/acme/app#main",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/admin/users/route.ts",
        size: 77,
        text: "export async function GET() {\n  return Response.json([])\n}\n",
      },
      {
        path: "app/api/chat/route.ts",
        size: 141,
        text: "import { streamText } from 'ai'\nexport async function POST() {\n  return streamText({ model: 'openai/gpt-4o', prompt: 'hello' }).toDataStreamResponse()\n}\n",
      },
    ],
  })
  const marked = applyReportPolicy(nextReport, nextReport.findings.length ? [] : [], baseline)

  assert(marked.findings.some((finding) => finding.baselineState === "existing"), "expected existing baseline finding")
  assert(marked.findings.some((finding) => finding.baselineState === "new"), "expected new baseline finding")
  assert((marked.baselineSummary?.resolved ?? 0) >= 1, "expected resolved baseline count")
}

function assertAiTriageCanDowngradeAmbiguousProcessFinding() {
  const report = makeTriageReport([
    makeFinding({
      id: "F-001",
      kind: "vulnerability",
      severity: "high",
      category: "command_injection",
      ruleId: "rust.process.user-controlled-command",
      title: "Rust process execution uses a user-controlled command",
      filePath: "src/tool/selfdev/build_queue.rs",
      evidence: "Command::new(&command.program)",
    }),
  ])

  const reviewed = applyAiTriage(report, {
    triage: [
      {
        findingId: "F-001",
        verdict: "posture_only",
        reason: "The command comes from an internal selfdev build command builder that returns fixed cargo/bash choices, not request/model input.",
        adjustedSeverity: "medium",
        adjustedKind: "repo_posture",
        adjustedCategory: "repo_security_posture",
        confidence: 0.9,
        detectedControls: ["internal fixed command builder"],
        missingControls: ["env isolation"],
        attackScenario: "A repo-local build wrapper could still execute project code during self-development flows.",
        priority: "normal",
      },
    ],
    reportSummary: {
      riskNarrative: "Runtime command execution exists, but this specific finding is posture review rather than command injection.",
      recommendedNextSteps: ["Review self-dev build execution policy."],
      runtimeAgentRisk: "medium",
      repoPostureRisk: "low",
      dependencyRisk: "low",
      secretsRisk: "none",
    },
  })

  const finding = reviewed.findings[0]
  assert(finding.kind === "repo_posture", "AI triage should be able to downgrade ambiguous process findings to repo posture")
  assert(finding.severity === "medium", "AI triage should apply conservative adjusted severity")
  assert(finding.category === "repo_security_posture", "AI triage should apply adjusted category")
  assert(finding.triage?.verdict === "posture_only", "AI triage verdict should be stored on the finding")
  assert(reviewed.aiTriage?.recommendedNextSteps.includes("Review self-dev build execution policy."), "AI report summary should be stored")
  assert(reviewed.riskBreakdown?.runtimeAgentRisk.label === "Moderate", "AI triage should populate runtime risk breakdown")
}

function assertAiTriageCannotHideCriticalSecretEvidence() {
  const report = makeTriageReport([
    makeFinding({
      id: "F-001",
      kind: "vulnerability",
      severity: "critical",
      category: "secret_exposure",
      ruleId: "secret.provider-token.committed",
      title: "Exposed provider API key committed",
      filePath: ".env.local",
      evidence: "OPENAI_API_KEY=sk-...redacted",
    }),
  ])

  const reviewed = applyAiTriage(report, {
    triage: [
      {
        findingId: "F-001",
        verdict: "likely_false_positive",
        reason: "The model thinks this might be an example.",
        adjustedSeverity: "info",
        adjustedKind: "info",
        adjustedCategory: "repo_security_posture",
        confidence: 0.95,
      },
    ],
  })

  const finding = reviewed.findings[0]
  assert(finding.severity === "critical", "AI triage must not downgrade critical secret evidence")
  assert(finding.category === "secret_exposure", "AI triage must not recategorize critical secret evidence")
  assert(finding.kind === "vulnerability", "AI triage must not hide critical secret evidence as info")
  assert(finding.triage?.verdict === "needs_review", "blocked critical downgrades should be retained as needs-review triage")
}

function assertIssueBodyUsesContextAwareAgentNextSteps() {
  const report = makeTriageReport([
    makeFinding({
      id: "F-001",
      kind: "vulnerability",
      severity: "high",
      category: "mcp_risk",
      ruleId: "mcp.process.inherits-full-env",
      title: "MCP child process inherits the full environment",
      filePath: "src/mcp/client.rs",
      evidence: ".envs(&env)",
    }),
    makeFinding({
      id: "F-002",
      kind: "vulnerability",
      severity: "high",
      category: "unsafe_tool_calling",
      ruleId: "agent.shell.tool-command-execution",
      title: "Agent-controlled shell execution surface",
      filePath: "src/tool/bash.rs",
      evidence: "Command::new(\"bash\").arg(\"-c\")",
    }),
    makeFinding({
      id: "F-003",
      kind: "repo_posture",
      severity: "high",
      category: "repo_security_posture",
      ruleId: "github-actions.unpinned-actions.grouped",
      title: "Unpinned GitHub Actions detected",
      filePath: ".github/workflows/release.yml",
      evidence: "3 unpinned action refs",
    }),
    makeFinding({
      id: "F-004",
      kind: "repo_posture",
      severity: "medium",
      category: "supply_chain_posture",
      ruleId: "supply-chain.remote-install-piped-shell",
      title: "Remote install script is piped directly to a shell",
      filePath: "README.md",
      evidence: "curl -fsSL ... | bash",
    }),
  ], {
    framework: "Rust",
    repoInventory: {
      framework: "Rust",
      languages: ["Rust", "YAML"],
      routeHandlers: 0,
      serverActions: 0,
      clientComponents: 0,
      imports: 0,
      envReads: 0,
      authCalls: 0,
      validationCalls: 0,
      dangerousSinks: 3,
      aiCalls: 0,
      dbCalls: 0,
      githubWorkflows: 2,
      supabaseMigrations: 0,
      prismaSchemas: 0,
    },
  })

  const body = generateIssueBody(report)
  assert(body.includes("Review MCP execution policy"), "agent reports should prioritize MCP execution policy")
  assert(body.includes("Pin third-party GitHub Actions"), "agent reports should include supply-chain workflow guidance")
  assert(!body.includes("Rotate any exposed credentials"), "agent report without secret findings should not recommend rotating credentials")
  assert(!body.includes("Add server-side auth guards"), "Rust agent report should not include generic Next.js route guidance")
  assert(!body.includes("/api/scan/"), "external issue body should not include local-only API links")
  assert(!body.includes("VibeShield"), "external issue body should not include product branding")
}

function assertFullReportCopyIncludesEveryFinding() {
  const findings: ScanFinding[] = Array.from({ length: 12 }, (_, index) => ({
    id: `F-${String(index + 1).padStart(3, "0")}`,
    kind: index % 2 === 0 ? "vulnerability" : "repo_posture",
    severity: index === 0 ? "critical" : index < 4 ? "high" : "medium",
    category: index % 2 === 0 ? "mcp_risk" : "repo_security_posture",
    ruleId: `fixture.rule.${index + 1}`,
    title: `Finding ${index + 1}`,
    description: `Description ${index + 1}`,
    filePath: `src/file-${index + 1}.ts`,
    lineStart: index + 10,
    evidence: `evidence-${index + 1}`,
    confidence: 0.8,
    confidenceReason: `confidence-${index + 1}`,
    reachability: "reachable",
    exploitability: "medium",
    evidenceTrace: [
      {
        filePath: `src/file-${index + 1}.ts`,
        lineStart: index + 10,
        kind: "sink",
        label: `trace-${index + 1}`,
        code: `code-${index + 1}`,
      },
    ],
    recommendation: `Recommendation ${index + 1}`,
    patchable: index % 3 === 0,
    patch: index % 3 === 0
      ? {
          title: `Patch ${index + 1}`,
          summary: `Patch summary ${index + 1}`,
          unifiedDiff: `diff-${index + 1}`,
          reviewRequired: true,
        }
      : undefined,
    source: "rule",
  }))

  const report: ScanReport = {
    id: "copy-full-fixture",
    createdAt: new Date("2026-04-28T12:00:00.000Z").toISOString(),
    projectName: "copy-full",
    sourceType: "github",
    sourceLabel: "github.com/acme/copy-full#main",
    analysisMode: "normal",
    status: "completed",
    riskScore: 79,
    filesInspected: 42,
    apiRoutesInspected: 3,
    clientComponentsInspected: 2,
    aiEndpointsInspected: 1,
    findings,
    auditTrail: [
      { id: "evt-1", timestamp: new Date("2026-04-28T12:00:01.000Z").toISOString(), label: "scanner completed", status: "complete" },
    ],
  }

  const body = generateFullReportBody(report)
  assert(body.includes("## All findings"), "full report copy should include all findings section")
  assert(body.includes("Finding 12"), "full report copy should include findings beyond the old top-10 issue body")
  assert(body.includes("Evidence trace"), "full report copy should include evidence traces")
  assert(body.includes("Patch summary 10"), "full report copy should include patch previews")
  assert(body.includes("scanner completed"), "full report copy should include audit trail")
}

function makeFinding(overrides: Partial<ScanFinding>): ScanFinding {
  return {
    id: "F-000",
    kind: "vulnerability",
    severity: "medium",
    category: "dangerous_code",
    ruleId: "test.finding",
    title: "Test finding",
    description: "Test description",
    filePath: "src/main.ts",
    lineStart: 1,
    evidence: "evidence",
    confidence: 0.8,
    recommendation: "Review this finding.",
    patchable: false,
    source: "rule",
    ...overrides,
  }
}

function makeTriageReport(findings: ScanFinding[], overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    id: "scan-triage-fixture",
    createdAt: "2026-01-01T00:00:00.000Z",
    projectName: "triage-fixture",
    framework: "Rust",
    sourceType: "github",
    sourceLabel: "fixture://triage",
    analysisMode: "max",
    status: "completed",
    riskScore: 0,
    filesInspected: 4,
    apiRoutesInspected: 0,
    clientComponentsInspected: 0,
    aiEndpointsInspected: 0,
    findings,
    auditTrail: [],
    ...overrides,
  }
}

async function assertScanJobsAndEventsLifecycle() {
  const job = await createScanJob({
    ownerHash: "a".repeat(64),
    reportId: crypto.randomUUID(),
    projectName: "job-fixture",
    sourceLabel: "github.com/acme/app#main",
    analysisMode: "max",
    repository: {
      owner: "acme",
      repo: "app",
      ref: "main",
      defaultBranch: "main",
      private: false,
      htmlUrl: "https://github.com/acme/app",
    },
  })

  await appendScanEvent({ reportId: job.reportId, jobId: job.id, label: "job created", status: "complete" })
  const claimed = await claimNextScanJob()
  assert(claimed?.id === job.id, "expected queued job to be claimed")
  assert(claimed.status === "running", "expected claimed job to become running")
  await completeScanJob(job.id, job.reportId)
  const completedEvents = await listScanEvents(job.reportId)
  assert(completedEvents.some((event) => event.label === "job created"), "expected stored scan event")

  const failed = await createScanJob({
    ownerHash: "b".repeat(64),
    reportId: crypto.randomUUID(),
    projectName: "job-failure",
    sourceLabel: "github.com/acme/fail#main",
    analysisMode: "rules",
    repository: {
      owner: "acme",
      repo: "fail",
      ref: "main",
      defaultBranch: "main",
      private: false,
      htmlUrl: "https://github.com/acme/fail",
    },
  })
  await failScanJob(failed.id, "fixture failure")
  const failedClaim = await claimNextScanJob()
  assert(failedClaim?.id !== failed.id, "failed jobs should not be claimable")
}

function assertHealthStatusIsSecretFree() {
  const health = getSystemHealth()
  const serialized = JSON.stringify(health)
  assert(!serialized.includes("sk-"), "health response must not contain API keys")
  assert(!serialized.includes("SUPABASE_SERVICE_ROLE_KEY"), "health response must not contain service key names")
  assert(typeof health.supabaseConfigured === "boolean", "health should expose boolean Supabase status")
  assert(typeof health.githubAppConfigured === "boolean", "health should expose boolean GitHub App status")
}

async function readProjectFiles(root: string): Promise<ProjectFile[]> {
  const out: ProjectFile[] = []

  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        await walk(fullPath)
        continue
      }

      const relativePath = path.relative(root, fullPath).replaceAll(path.sep, "/")
      if (!shouldConsiderProjectPath(relativePath)) continue
      const text = await readFile(fullPath, "utf8")
      out.push({ path: relativePath, size: Buffer.byteLength(text), text })
    }
  }

  await walk(root)
  return out
}

function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message)
}

void main().catch((error) => {
  console.error(error)
  process.exit(1)
})
