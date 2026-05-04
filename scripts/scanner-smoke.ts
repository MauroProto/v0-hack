import { zodSchema } from "ai"
import type { ZodTypeAny } from "zod"
import {
  AiReviewSchema,
  ExplanationSchema,
  PatchSchema,
  PullRequestCopySchema,
  PullRequestSafetyReviewSchema,
} from "../lib/ai/structuredSchemas"
import { getSystemHealth } from "../lib/system/health"
import {
  appendScanEvent,
  backgroundJobsEnabled,
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
import { compareProjectPathPriority } from "../lib/scanner/extract"
import { scanDependencies } from "../lib/scanner/dependencies"
import { generateFixesBody, generateFullReportBody, generateIssueBody } from "../lib/scanner/patches"
import { scanProject } from "../lib/scanner/scan"
import type { ProjectFile, ScanFinding, ScanReport } from "../lib/scanner/types"
import { applyAiTriage, buildRiskBreakdown } from "../lib/ai/triage"
import { sanitizePublicPullRequestCopy } from "../lib/ai/publicPullRequestCopy"
import { pinThirdPartyActionRefsInText } from "../lib/utils/githubActions"
import { formatGitHubNotFoundMessage } from "../lib/utils/githubErrors"
import { deriveQuotaDisplay } from "../lib/security/quota-view"
import { assertSameOriginRequest } from "../lib/security/origin"
import { assertScanModeAllowed } from "../lib/security/scanAccess"
import { SecurityError } from "../lib/security/errors"
import { ensureAnonymousGuestIdentity } from "../lib/security/anonymousGuest"
import { reportHistoryOwnerHash } from "../lib/security/reportHistory"
import { scanCreditCostForMode } from "../lib/security/scanCredits"
import {
  monthlyScanQuotaLimit,
  planLinkedMonthlyQuotaConsumption,
} from "../lib/security/quotaPolicy"
import { getCodeloadLimits } from "../lib/utils/githubCodeload"
import {
  buildProfessionalPullRequestBody,
  buildProfessionalPullRequestTitle,
  formatPinnedActionFix,
  shouldAttachReviewNotesFileToPullRequest,
} from "../lib/utils/pullRequestDraft"
import { isSafePullRequestFinding } from "../lib/utils/prSafety"
import { applyPullRequestSafetyDecision } from "../lib/utils/prSafetyReview"

async function main() {
  const files = securityRegressionFixtureFiles()
  const previousOsv = process.env.BADGER_ENABLE_OSV
  process.env.BADGER_ENABLE_OSV = "false"

  try {
    const report = await scanProject({
      projectName: "security-regression-fixture",
      sourceType: "github",
      sourceLabel: "fixture://security-regression",
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
    await assertHighEntropySecretAssignmentsUseGitleaksStyleContext()
    await assertGithubActionsSecretReferencesAndCodeWordsAreNotVulnerabilities()
    await assertFixedRustCommandIsPostureOnly()
    await assertUserControlledRustCommandIsVulnerability()
    await assertInternalRustCommandBuilderIsNotCommandInjection()
    await assertAgentShellAndMcpRisksAreClassified()
    await assertHighAgentRisksWithoutCriticalDoNotReachCriticalScore()
    await assertTrivialUnsafeRustIsInventoryOnly()
    await assertRemoteInstallPipeToShellIsPosture()
    await assertGithubActionsGroupsUnpinnedActionsByWorkflow()
    await assertGithubOwnedCheckoutOnlyWorkflowIsLowerPostureRisk()
    await assertRulePackFindsDataAccessLayerMissingServerOnly()
    await assertSupabaseRulePackFindsRlsCoverageAndPublicBuckets()
    await assertVercelPosturePackFindsSourceMapsAndCronSecret()
    await assertMaxModeBuildsSecurityTaskflow()
    assertLargeRepoFilePriorityKeepsSecurityFiles()
    await assertOsvUnmaintainedAdvisoryIsPosture()
    await assertAuthCallWithoutGuardStillFindsSensitiveRoute()
    await assertGuardedSensitiveRouteIsNotReported()
    await assertDecorativeZodDoesNotHideRawBodyUse()
    await assertInlineZodParseIsAccepted()
    await assertInterfileTaintFindsRouteServiceDbTrace()
    await assertInterfileTaintIgnoresValidatedFlow()
    await assertBadgerIgnoreSuppressesFindingsAndRisk()
    await assertDefaultExamplePathsAreSuppressedFromRisk()
    await assertBaselineMarksNewExistingResolved()
    assertAiTriageCanDowngradeAmbiguousProcessFinding()
    assertAiTriageCanSuppressCriticalDetectorFalsePositive()
    assertAiTriageCannotHideCriticalSecretEvidence()
    await assertScannerSelfScanFixturesDoNotBecomeCritical()
    await assertReportPresentationTextDoesNotBecomeSecretExposure()
    await assertScannerDetectorPatternsDoNotBecomeDangerousCode()
    await assertSafeCookieHelpersDoNotBecomeMissingCookieHardening()
    await assertAnthropicOutputSchemasAvoidUnsupportedArrayBounds()
    await assertThirdPartyActionPinningKeepsGitHubOwnedActionsUnchanged()
    assertZeroDependencyRiskCannotBeRaisedByAiLabel()
    assertIssueBodyUsesContextAwareAgentNextSteps()
    assertPublicPullRequestCopyLooksHumanAuthored()
    assertPinnedActionPullRequestDraftIsProfessional()
    assertPublicForkPullRequestsDoNotAttachReportNotes()
    assertOnlyDeterministicFindingsArePrEligible()
    assertPullRequestSafetyGateBlocksAndRepairsUnsafeCopy()
    assertGitHubNotFoundErrorsAreContextual()
    assertFullReportCopyIncludesEveryFinding()
    assertMaxLaunchReviewAppearsOnlyForMaxReports()
    assertGeneratedFixesCopyIncludesSpecificFixes()
    assertQuotaDisplayCountsRemainingScans()
    assertScanCreditCostsMatchMode()
    assertSharedMonthlyQuotaPolicy()
    assertScanModeAccessRules()
    assertAnonymousReportHistoryIsListable()
    assertAnonymousGuestIdentityUsesHttpOnlyCookie()
    assertSameOriginRequestGuard()
    assertCodeloadDefaultsAreConservative()
    assertBackgroundJobsStayDisabledUntilAtomicClaim()
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
    if (previousOsv === undefined) delete process.env.BADGER_ENABLE_OSV
    else process.env.BADGER_ENABLE_OSV = previousOsv
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

async function assertHighEntropySecretAssignmentsUseGitleaksStyleContext() {
  const report = await scanProject({
    projectName: "entropy-secrets",
    sourceType: "github",
    sourceLabel: "fixture://entropy-secrets",
    analysisMode: "rules",
    files: [
      {
        path: "src/config.ts",
        size: 190,
        text: [
          "export const paymentApiSecret = 'n98Y2fL4aQw7mPz0KjR6sVt3XbC9dN2p'",
          "export const ordinaryId = 'public-feature-flag'",
        ].join("\n"),
      },
      {
        path: "tests/config.fixture.ts",
        size: 110,
        text: "export const paymentApiSecret = 'n98Y2fL4aQw7mPz0KjR6sVt3XbC9dN2p'\n",
      },
    ],
  })

  const finding = report.findings.find((item) => item.ruleId === "secret.generic-high-entropy-assignment")
  assert(finding, "expected high-entropy secret assignment finding")
  assert(finding.filePath === "src/config.ts", "high-entropy secret should only be reported in production source context")
  assert(finding.confidenceReason?.includes("entropy"), "secret finding should explain entropy/context reasoning")
  assert(!report.findings.some((item) => item.ruleId === "secret.generic-high-entropy-assignment" && item.filePath.includes("fixture")), "test fixtures should not become high-entropy secret findings")
}

async function assertGithubActionsSecretReferencesAndCodeWordsAreNotVulnerabilities() {
  const report = await scanProject({
    projectName: "github-actions-secret-references",
    sourceType: "github",
    sourceLabel: "fixture://github-actions-secret-references",
    analysisMode: "rules",
    files: [
      {
        path: ".github/workflows/ci.yml",
        size: 280,
        text: [
          "name: ci",
          "jobs:",
          "  test:",
          "    steps:",
          "      - run: echo ok",
          "        env:",
          "          token: ${{ secrets.GEMINI_CLI_ROBOT_GITHUB_PAT }}",
          "          GITHUB_TOKEN: ${GITHUB_TOKEN}",
        ].join("\n"),
      },
      {
        path: "packages/core/src/agents/browser/browserAgentFactory.test.ts",
        size: 250,
        text: [
          "// Add static methods - use mockImplementation for lazy eval (hoisting-safe)",
          "while ((match = urlRegex.exec(text)) !== null) {",
          "  urls.push(match[0])",
          "}",
          "fs.writeFileSync(join(userGeminiDir, 'projects.json'), '{\"projects\":{}}');",
        ].join("\n"),
      },
      {
        path: ".github/scripts/backfill.cjs",
        size: 150,
        text: [
          "const { execFileSync } = require('child_process');",
          "execFileSync('gh', ['issue', 'list'], { stdio: 'inherit' });",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((item) => item.category === "secret_exposure"), "GitHub Actions secrets.* references and env interpolation must not become leaked secrets")
  assert(!report.findings.some((item) => item.title === "Dynamic eval call detected"), "comment text mentioning eval must not become an eval finding")
  assert(!report.findings.some((item) => item.evidence?.includes("urlRegex.exec")), "RegExp.exec must not be treated as shell process execution")
  assert(!report.findings.some((item) => item.title === "File write appears to use request input"), "static test file writes using user-named fixture dirs must not become request-input file write findings")
  assert(!report.findings.some((item) => item.category === "dangerous_code" && item.severity === "high"), "trusted scripts/tests must not become high dangerous-code vulnerabilities without source-to-sink evidence")
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

async function assertRulePackFindsDataAccessLayerMissingServerOnly() {
  const report = await scanProject({
    projectName: "dal-server-only",
    sourceType: "github",
    sourceLabel: "fixture://dal-server-only",
    analysisMode: "rules",
    files: [
      {
        path: "next.config.mjs",
        size: 26,
        text: "export default {}\n",
      },
      {
        path: "lib/data/users.ts",
        size: 160,
        text: [
          "import { prisma } from '@/lib/prisma'",
          "export async function getUser(id: string) {",
          "  return prisma.user.findUnique({ where: { id } })",
          "}",
        ].join("\n"),
      },
    ],
  })

  const finding = report.findings.find((item) => item.ruleId === "next.data-access.server-only-missing")
  assert(finding, "expected Semgrep-style rule pack finding for missing server-only import")
  assert(finding.kind === "hardening", "data access layer server-only finding should be hardening")
  assert(finding.confidenceReason?.includes("rule pack"), "rule pack findings should identify their rule-pack source")
}

async function assertSupabaseRulePackFindsRlsCoverageAndPublicBuckets() {
  const report = await scanProject({
    projectName: "supabase-pack",
    sourceType: "github",
    sourceLabel: "fixture://supabase-pack",
    analysisMode: "rules",
    files: [
      {
        path: "supabase/migrations/001_profiles.sql",
        size: 390,
        text: [
          "create table public.profiles (",
          "  id uuid primary key,",
          "  email text not null",
          ");",
          "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);",
        ].join("\n"),
      },
    ],
  })

  assert(report.findings.some((item) => item.ruleId === "supabase.rls.table-without-policy-coverage"), "expected Supabase RLS coverage finding")
  assert(report.findings.some((item) => item.ruleId === "supabase.storage.public-bucket-review"), "expected Supabase public storage bucket finding")
}

async function assertVercelPosturePackFindsSourceMapsAndCronSecret() {
  const report = await scanProject({
    projectName: "vercel-posture",
    sourceType: "github",
    sourceLabel: "fixture://vercel-posture",
    analysisMode: "rules",
    files: [
      {
        path: "next.config.mjs",
        size: 72,
        text: "export default { productionBrowserSourceMaps: true }\n",
      },
      {
        path: "app/api/cron/reindex/route.ts",
        size: 96,
        text: "export async function GET() {\n  return Response.json({ ok: true })\n}\n",
      },
    ],
  })

  assert(report.findings.some((item) => item.ruleId === "vercel.source-maps.enabled-in-production"), "expected production sourcemap posture finding")
  assert(report.findings.some((item) => item.ruleId === "vercel.cron.missing-secret-guard"), "expected missing cron secret guard finding")
}

async function assertMaxModeBuildsSecurityTaskflow() {
  const report = await scanProject({
    projectName: "max-taskflow",
    sourceType: "github",
    sourceLabel: "fixture://max-taskflow",
    analysisMode: "max",
    files: [
      {
        path: "app/api/chat/route.ts",
        size: 150,
        text: "import { streamText } from 'ai'\nexport async function POST() {\n  return streamText({ model: 'openai/gpt-4o', prompt: 'hi' }).toDataStreamResponse()\n}\n",
      },
      {
        path: "supabase/migrations/001.sql",
        size: 80,
        text: "create table public.messages (id uuid primary key, body text);\n",
      },
    ],
  })

  const event = report.auditTrail.find((item) => item.label === "Build Max security taskflow")
  assert(event, "Max mode should build a security taskflow audit event")
  assert(String(event.metadata?.phases ?? "").includes("hypothesis"), "Max mode taskflow should include hypothesis-driven review phases")
}

async function assertOsvUnmaintainedAdvisoryIsPosture() {
  const originalFetch = globalThis.fetch
  const previousOsv = process.env.BADGER_ENABLE_OSV
  process.env.BADGER_ENABLE_OSV = "true"
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
    if (previousOsv === undefined) delete process.env.BADGER_ENABLE_OSV
    else process.env.BADGER_ENABLE_OSV = previousOsv
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

async function assertBadgerIgnoreSuppressesFindingsAndRisk() {
  const files: ProjectFile[] = [
    { path: ".env.local", size: 35, text: "OPENAI_API_KEY=sk-demo-redacted\n" },
    {
      path: "app/api/admin/users/route.ts",
      size: 111,
      text: "export async function GET() {\n  return Response.json([{ email: 'admin@example.com' }])\n}\n",
    },
    {
      path: ".badgerignore",
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

async function assertDefaultExamplePathsAreSuppressedFromRisk() {
  const report = await scanProject({
    projectName: "badger-self-scan-fixtures",
    sourceType: "github",
    sourceLabel: "github.com/mauroproto/badger#main",
    analysisMode: "normal",
    files: [
      {
        path: "examples/security-regression-fixture/app/api/search/route.ts",
        size: 210,
        text: [
          "import { prisma } from '@/lib/db'",
          "export async function POST(request: Request) {",
          "  const body = await request.json()",
          "  const rows = await prisma.$queryRawUnsafe(`select * from users where email = '${body.email}'`)",
          "  return Response.json({ rows })",
          "}",
        ].join("\n"),
      },
      {
        path: "examples/security-regression-fixture/app/actions.ts",
        size: 160,
        text: [
          '"use server"',
          "import { prisma } from '@/lib/db'",
          "export async function deleteUser(formData: FormData) {",
          "  await prisma.user.delete({ where: { id: String(formData.get('userId')) } })",
          "}",
        ].join("\n"),
      },
      {
        path: "examples/security-regression-fixture/supabase/migrations/001_init.sql",
        size: 220,
        text: [
          "create table public.accounts (id uuid primary key, email text not null);",
          "alter table public.accounts disable row level security;",
          "create function public.admin_delete_account(account_id uuid)",
          "returns void language plpgsql security definer as $$",
          "begin delete from public.accounts where id = account_id; end; $$;",
        ].join("\n"),
      },
      {
        path: "examples/security-regression-fixture/.env.example",
        size: 48,
        text: "NEXT_PUBLIC_OPENAI_API_KEY=...redacted\n",
      },
    ],
  })

  assert(report.findings.some((finding) => finding.suppressed), "default example path policy should suppress fixture findings")
  assert(!report.findings.some((finding) => !finding.suppressed && finding.filePath.startsWith("examples/")), "example fixtures must not remain active findings")
  assert(report.riskScore === 0, "example fixtures must not contribute to the production risk score")
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

function assertAiTriageCanSuppressCriticalDetectorFalsePositive() {
  const report = makeTriageReport([
    makeFinding({
      id: "F-001",
      kind: "vulnerability",
      severity: "critical",
      category: "public_env_misuse",
      ruleId: "rule.public_env_misuse.dangerous.next.public.environment.variable",
      title: "Dangerous NEXT_PUBLIC environment variable",
      filePath: "lib/scanner/rules.ts",
      evidence: '"NEXT_PUBLIC_OPENAI_API_KEY",',
      confidence: 0.97,
    }),
  ])

  const reviewed = applyAiTriage(report, {
    triage: [
      {
        findingId: "F-001",
        verdict: "likely_false_positive",
        reason: "The evidence is the scanner's own detector allowlist, not an application env contract.",
        adjustedSeverity: "info",
        adjustedKind: "info",
        adjustedCategory: "repo_security_posture",
        confidence: 0.98,
        priority: "low",
      },
    ],
    reportSummary: {
      riskNarrative: "The critical signal is detector code noise, not a real secret exposure.",
      recommendedNextSteps: ["Fix scanner self-exclusion for detector constants."],
      runtimeAgentRisk: "none",
      repoPostureRisk: "low",
      dependencyRisk: "none",
      secretsRisk: "none",
    },
  })

  const finding = reviewed.findings[0]
  assert(finding.suppressed, "high-confidence detector-code false positives should be suppressed")
  assert(finding.severity === "info", "suppressed detector-code false positives should be downgraded to info")
  assert(finding.kind === "info", "suppressed detector-code false positives should not remain vulnerabilities")
  assert(reviewed.riskScore === 0, "suppressed detector-code false positives should not contribute to risk score")
  assert(reviewed.riskBreakdown?.secretsRisk.label === "None", "suppressed detector-code false positives should not create secrets risk")
}

async function assertScannerSelfScanFixturesDoNotBecomeCritical() {
  const report = await scanProject({
    projectName: "scanner-self-fixtures",
    sourceType: "github",
    sourceLabel: "fixture://scanner-self-fixtures",
    analysisMode: "rules",
    files: [
      {
        path: "lib/scanner/rules.ts",
        size: 250,
        text: [
          "const DANGEROUS_NEXT_PUBLIC_NAMES = [",
          '  "NEXT_PUBLIC_OPENAI_API_KEY",',
          '  "NEXT_PUBLIC_ANTHROPIC_API_KEY",',
          "]",
        ].join("\n"),
      },
      {
        path: "scripts/scanner-smoke.ts",
        size: 340,
        text: [
          "async function assertSecretFixturesAndRedactionPatternsDoNotBecomeCritical() {",
          "  let input = \"access=sk-ant-api03-fakefixture\\nopenrouter=sk-or-v1-fakefixture\\ngithub=ghp_1234567890abcdef1234567890abcdef\\n\";",
          "}",
          "async function assertHighEntropySecretAssignmentsUseGitleaksStyleContext() {",
          "  const text = \"export const paymentApiSecret = 'n98Y2fL4aQw7mPz0KjR6sVt3XbC9dN2p'\\n\"",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.severity === "critical"), "scanner detector code and smoke fixtures must not produce critical findings")
  assert(report.riskScore < 50, "scanner detector code and smoke fixtures must not create a critical/action-required self-scan score")
}

async function assertReportPresentationTextDoesNotBecomeSecretExposure() {
  const report = await scanProject({
    projectName: "report-presentation-text",
    sourceType: "github",
    sourceLabel: "fixture://report-presentation-text",
    analysisMode: "rules",
    files: [
      {
        path: "components/scan/ScanResultsClient.tsx",
        size: 520,
        text: [
          '"use client"',
          "function impactForFinding(finding) {",
          "  if (finding.category === \"public_env_misuse\") {",
          "    return \"Next.js bundles NEXT_PUBLIC values into browser JavaScript. If the value is a secret, token, service-role key, or private database URL, visitors can extract it from client assets.\"",
          "  }",
          "}",
          "function templatePatchForFinding(finding) {",
          "  return [",
          "    \"- NEXT_PUBLIC_SECRET_VALUE=...\",",
          "    \"+ SECRET_VALUE=...\",",
          "  ].join(\"\\n\")",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "public_env_misuse"), "report UI copy must not become public env misuse")
  assert(!report.findings.some((finding) => finding.ruleId === "supabase.service-role.in-client-component"), "report UI copy must not become service-role exposure")
}

async function assertScannerDetectorPatternsDoNotBecomeDangerousCode() {
  const report = await scanProject({
    projectName: "scanner-detector-patterns",
    sourceType: "github",
    sourceLabel: "fixture://scanner-detector-patterns",
    analysisMode: "rules",
    files: [
      {
        path: "lib/scanner/inventory.ts",
        size: 200,
        text: "const DANGEROUS_SINK_RE = /\\b(eval|Function|dangerouslySetInnerHTML|exec|spawn)\\b/i",
      },
      {
        path: "lib/scanner/rules.ts",
        size: 260,
        text: [
          "const patterns = [",
          "  /\\bconst\\s+toolName\\s*=\\s*(?:await\\s+)?(?:req|request)\\.json\\(\\)/i,",
          "]",
          "if (!/(dangerouslySetInnerHTML|eval\\s*\\(|new\\s+Function\\s*\\()/i.test(line)) return",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.category === "dangerous_code"), "scanner detector regexes must not become dangerous-code findings")
  assert(!report.findings.some((finding) => finding.category === "unsafe_tool_calling"), "scanner detector regexes must not become unsafe-tool findings")
}

async function assertSafeCookieHelpersDoNotBecomeMissingCookieHardening() {
  const report = await scanProject({
    projectName: "cookie-helper",
    sourceType: "github",
    sourceLabel: "fixture://cookie-helper",
    analysisMode: "rules",
    files: [
      {
        path: "app/api/auth/github/callback/route.ts",
        size: 180,
        text: [
          "import { createGitHubSessionCookie } from '@/lib/security/github-session'",
          "export async function GET() {",
          "  const response = new Response(null)",
          "  response.headers.append(\"Set-Cookie\", createGitHubSessionCookie(session))",
          "  return response",
          "}",
        ].join("\n"),
      },
      {
        path: "app/api/auth/github/session/route.ts",
        size: 180,
        text: [
          "import { clearGitHubSessionCookie } from '@/lib/security/github-session'",
          "export async function DELETE() {",
          "  return Response.json({}, { headers: { \"Set-Cookie\": clearGitHubSessionCookie() } })",
          "}",
        ].join("\n"),
      },
      {
        path: "lib/security/github-session.ts",
        size: 220,
        text: [
          "export function createGitHubSessionCookie(session) {",
          "  return serializeCookie('gh', session, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/', maxAge: 100 })",
          "}",
          "export function clearGitHubSessionCookie() {",
          "  return serializeCookie('gh', '', { httpOnly: true, sameSite: 'Lax', secure: true, path: '/', maxAge: 0 })",
          "}",
        ].join("\n"),
      },
    ],
  })

  assert(!report.findings.some((finding) => finding.title === "Session-like cookie missing hardened attributes"), "safe cookie helper call sites must not be flagged as missing hardening")
}

async function assertAnthropicOutputSchemasAvoidUnsupportedArrayBounds() {
  const schemas = {
    AiReviewSchema,
    ExplanationSchema,
    PatchSchema,
    PullRequestCopySchema,
    PullRequestSafetyReviewSchema,
  }

  for (const [name, schema] of Object.entries(schemas)) {
    const jsonSchema = await zodSchema(schema as ZodTypeAny).jsonSchema
    assert(!containsUnsupportedAnthropicSchemaKeywords(jsonSchema), `${name} must not send unsupported JSON Schema bounds to Claude structured output`)
  }
}

async function assertThirdPartyActionPinningKeepsGitHubOwnedActionsUnchanged() {
  const input = [
    "name: ci",
    "jobs:",
    "  test:",
    "    steps:",
    "      - uses: actions/checkout@v6",
    "      - uses: goreleaser/goreleaser-action@v6.1.0",
    "      - uses: ./local-action",
    "      - uses: docker://alpine:3.20",
  ].join("\n")

  const result = await pinThirdPartyActionRefsInText(input, async (action) => {
    if (action.raw === "goreleaser/goreleaser-action@v6.1.0") return "0123456789abcdef0123456789abcdef01234567"
    return null
  })

  assert(result.text.includes("actions/checkout@v6"), "GitHub-owned actions should not be pinned by the public PR fixer")
  assert(result.text.includes("goreleaser/goreleaser-action@0123456789abcdef0123456789abcdef01234567 # v6.1.0"), "third-party action refs should be pinned to immutable SHAs with the original tag retained as a comment")
  assert(result.pinned.length === 1, "only one third-party action should be pinned")
}

function assertZeroDependencyRiskCannotBeRaisedByAiLabel() {
  const breakdown = buildRiskBreakdown([], {
    riskNarrative: "No dependencies were detected.",
    recommendedNextSteps: [],
    dependencyRisk: "low",
  })

  assert(breakdown.dependencyRisk.label === "None", "AI labels must not raise dependency risk when there are no dependency findings")
  assert(breakdown.dependencyRisk.score === 0, "zero dependency findings should keep dependency risk at 0")
}

function containsUnsupportedAnthropicSchemaKeywords(value: unknown): boolean {
  if (!value || typeof value !== "object") return false
  if (
    "minItems" in value ||
    "maxItems" in value ||
    "minimum" in value ||
    "maximum" in value ||
    "minLength" in value ||
    "maxLength" in value ||
    "multipleOf" in value
  ) return true
  if (Array.isArray(value)) return value.some(containsUnsupportedAnthropicSchemaKeywords)
  return Object.values(value).some(containsUnsupportedAnthropicSchemaKeywords)
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
  assert(!body.includes(["Vibe", "Shield"].join("")), "external issue body should not include product branding")
}

function assertPublicPullRequestCopyLooksHumanAuthored() {
  const legacyBrand = ["Vibe", "Shield"].join("")
  const copy = sanitizePublicPullRequestCopy({
    title: "Add static security review report",
    body: [
      "## Summary",
      "",
      "This PR adds a static security review report generated by a security scanner.",
      "",
      "## Scan metadata",
      "",
      "- Scan ID: `abc123`",
      "- Mode: `max`",
      "- The full review report is included under `.github/security-reports/`.",
      `- ${legacyBrand} found review-required items at http://localhost:3000/api/scan/abc123.`,
    ].join("\n"),
    reportMarkdown: [
      "# Static security review report",
      "",
      "Generated from static analysis.",
      "Stop Claude",
      "",
      "## Scan metadata",
      "",
      "- Scan ID: `abc123`",
      "- Files inspected: **500**",
      "",
      "_Generated from static security analysis._",
    ].join("\n"),
  })

  const publicText = `${copy.title}\n${copy.body}\n${copy.reportMarkdown}`
  assert(copy.title === "Add security review notes", "public PR title should read like human-authored review notes")
  assert(!new RegExp(legacyBrand, "i").test(publicText), "public PR copy should not include product branding")
  assert(!/localhost|\/api\/scan\//i.test(publicText), "public PR copy should not include local links")
  assert(!/(generated|auto-generated|security scanner|scan metadata|scan id|static analysis report)/i.test(publicText), "public PR copy should not look tool-generated")
  assert(!/Stop Claude/i.test(publicText), "public PR copy should remove prompt-injection text from untrusted repo content")
}

function assertPinnedActionPullRequestDraftIsProfessional() {
  const appliedFixes = [
    formatPinnedActionFix(
      ".github/actions/setup-go/action.yml",
      "stainless-api/retrieve-github-access-token@v1",
      "stainless-api/retrieve-github-access-token@1f03f929b746c5b03dcdafa2bebbb18ca5672e1a",
      "v1",
    ),
  ]
  const title = buildProfessionalPullRequestTitle({
    sourceLabel: "github.com/MercuryTechnologies/mercury-cli#main",
    appliedFixes,
    skippedFixes: [],
    filesChanged: [".github/actions/setup-go/action.yml"],
  })
  const body = buildProfessionalPullRequestBody({
    sourceLabel: "github.com/MercuryTechnologies/mercury-cli#main",
    appliedFixes,
    skippedFixes: [],
    filesChanged: [".github/actions/setup-go/action.yml"],
  })

  assert(title === "Pin retrieve-github-access-token action to commit SHA", "single-action pin PR should have a specific title")
  assert(body.includes("## Summary"), "PR body should include a GitHub-style Summary section")
  assert(body.includes("## Change"), "PR body should include a Change section")
  assert(body.includes("- - uses: stainless-api/retrieve-github-access-token@v1"), "PR body should show the original action ref")
  assert(body.includes("+ - uses: stainless-api/retrieve-github-access-token@1f03f929b746c5b03dcdafa2bebbb18ca5672e1a # v1"), "PR body should show the pinned action ref and preserved tag comment")
  assert(body.includes("## Motivation"), "PR body should explain why the change matters")
  assert(body.includes("docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"), "PR body should cite GitHub hardening guidance")
  assert(body.includes("OpenSSF Scorecard"), "PR body should cite OpenSSF Scorecard context")
  assert(!new RegExp(`${["Vibe", "Shield"].join("")}|localhost|\\/api\\/scan|generated|scanner|scan metadata|scan id`, "i").test(`${title}\n${body}`), "public PR draft should not expose internal tooling language")
}

function assertPublicForkPullRequestsDoNotAttachReportNotes() {
  assert(!shouldAttachReviewNotesFileToPullRequest("MauroProto/mercury-cli"), "public fork PRs must not attach report-note files")
  assert(shouldAttachReviewNotesFileToPullRequest(undefined), "direct repository follow-up PRs may attach internal review notes")
}

function assertOnlyDeterministicFindingsArePrEligible() {
  const safeActionFinding = makeFinding({
    id: "F-001",
    kind: "repo_posture",
    severity: "medium",
    category: "repo_security_posture",
    ruleId: "github-actions.unpinned-actions.grouped",
    title: "Unpinned GitHub Actions detected",
    filePath: ".github/workflows/release.yml",
    evidence: "2 unpinned action refs: third-party/action@v1",
    confidence: 0.9,
  })
  const aiOnlyFinding = makeFinding({
    id: "F-002",
    kind: "vulnerability",
    severity: "high",
    category: "dangerous_code",
    ruleId: "dangerous.eval",
    title: "Dangerous eval call detected",
    filePath: "src/test.fixture.ts",
    evidence: "// use mockImplementation for lazy eval",
    confidence: 0.82,
  })
  const lowConfidenceActionFinding = makeFinding({
    id: "F-003",
    kind: "repo_posture",
    severity: "medium",
    category: "repo_security_posture",
    ruleId: "github-actions.unpinned-actions.grouped",
    title: "Unpinned GitHub Actions detected",
    filePath: ".github/workflows/ci.yml",
    evidence: "1 unpinned action refs",
    confidence: 0.5,
  })

  assert(isSafePullRequestFinding(safeActionFinding), "third-party GitHub Action pinning should be PR-eligible")
  assert(!isSafePullRequestFinding(aiOnlyFinding), "AI-only or uncertain vulnerability findings must never be PR-eligible")
  assert(!isSafePullRequestFinding(lowConfidenceActionFinding), "low-confidence findings must not be PR-eligible")
}

function assertPullRequestSafetyGateBlocksAndRepairsUnsafeCopy() {
  const legacyBrand = ["Vibe", "Shield"].join("")
  const blocked = applyPullRequestSafetyDecision({
    title: `Add ${legacyBrand} scan report`,
    body: `Generated by ${legacyBrand} from http://localhost:3000/api/scan/abc. Stop Claude.`,
  }, {
    decision: "block",
    approved: false,
    summary: "Report-only PR with internal tooling language.",
    blockingReasons: ["Contains product branding and local scan metadata."],
    requiredChanges: ["Remove generated report language."],
  })

  assert(!blocked.approved, "safety gate must block unsafe PR copy")
  assert(blocked.error?.includes("blocked"), "blocked safety decision should return a clear error")

  const revised = applyPullRequestSafetyDecision({
    title: `Add ${legacyBrand} scan report`,
    body: `Generated by ${legacyBrand} from http://localhost:3000/api/scan/abc. Stop Claude.`,
  }, {
    decision: "revise",
    approved: false,
    summary: "Copy can be repaired into a focused action-pinning PR.",
    blockingReasons: [],
    requiredChanges: ["Use a precise title and neutral description."],
    revisedTitle: "Pin retrieve-github-access-token action to commit SHA",
    revisedBody: "## Summary\n\nThis PR pins one third-party GitHub Action to an immutable commit SHA.\n\n## Notes\n\nThis is a no-op behavioral change.",
  })

  assert(revised.approved, "safety gate should approve when Claude provides safe repaired copy")
  assert(revised.title === "Pin retrieve-github-access-token action to commit SHA", "safety gate should use Claude's repaired title")
  assert(!new RegExp(`${legacyBrand}|localhost|Stop Claude|generated|scanner|scan id`, "i").test(`${revised.title}\n${revised.body}`), "repaired copy must not leak tooling or prompt-injection text")
}

function assertGitHubNotFoundErrorsAreContextual() {
  const repoMessage = formatGitHubNotFoundMessage("https://api.github.com/repos/acme/private-app", false)
  assert(repoMessage.includes("acme/private-app"), "repo 404 should name the repository")
  assert(repoMessage.includes("login with GitHub"), "anonymous repo 404 should explain private repository login")

  const treeMessage = formatGitHubNotFoundMessage("https://api.github.com/repos/acme/app/git/trees/feature%2Fmissing?recursive=1", true)
  assert(treeMessage.includes("feature/missing"), "tree 404 should name the missing ref")
  assert(treeMessage.includes("default branch"), "tree 404 should explain branch fallback")

  const contentMessage = formatGitHubNotFoundMessage("https://api.github.com/repos/acme/app/contents/.github%2Fworkflows%2Fci.yml?ref=review", true)
  assert(contentMessage.includes(".github/workflows/ci.yml"), "content 404 should name the missing file")
  assert(contentMessage.includes("stale"), "content 404 should explain stale report or branch context")
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

function assertGeneratedFixesCopyIncludesSpecificFixes() {
  const report = makeTriageReport([
    makeFinding({
      id: "F-001",
      severity: "high",
      category: "input_validation",
      title: "Request body reaches raw query",
      filePath: "app/api/search/route.ts",
      lineStart: 12,
      recommendation: "Validate request input and use parameterized queries.",
      patchable: true,
      explanation: {
        summary: "The request body is used before schema validation.",
        impact: "An attacker can influence database query behavior.",
        fixSteps: [
          "Parse the request body with a route-specific schema.",
          "Pass validated values into parameterized database APIs.",
        ],
      },
      patch: {
        title: "Validate search input before querying",
        summary: "Add schema validation before the database call and remove string interpolation.",
        unifiedDiff: "+ const body = SearchSchema.parse(await request.json())",
        reviewRequired: true,
      },
    }),
  ])

  const body = generateFixesBody(report)
  assert(body.includes("# Security fixes"), "generated fixes copy should have a clear title")
  assert(body.includes("Request body reaches raw query"), "generated fixes copy should include finding titles")
  assert(body.includes("Validate search input before querying"), "generated fixes copy should include patch titles")
  assert(body.includes("SearchSchema.parse"), "generated fixes copy should include concrete patch preview text")
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

function assertQuotaDisplayCountsRemainingScans() {
  const resetAt = "2026-06-01T00:00:00.000Z"
  const unknown = deriveQuotaDisplay(null)
  assert(unknown.limit === 5, "unknown quota display should default to the anonymous five-credit limit")

  const full = deriveQuotaDisplay({ limit: 10, remaining: 10, resetAt, period: "monthly" })
  assert(full.remaining === 10, "quota display should preserve full remaining count")
  assert(full.used === 0, "quota display should count zero used credits at full quota")
  assert(full.percentRemaining === 100, "quota bar should be full when no credits were used")
  assert(full.label === "10 / 10 left", "quota label should show remaining credits over limit")

  const partial = deriveQuotaDisplay({ limit: 10, remaining: 7, resetAt, period: "monthly" })
  assert(partial.remaining === 7, "quota display should keep server remaining count")
  assert(partial.used === 3, "quota display should show credits consumed")
  assert(partial.percentRemaining === 70, "quota bar should shrink as credits are consumed")

  const empty = deriveQuotaDisplay({ limit: 10, remaining: -5, resetAt, period: "monthly" })
  assert(empty.remaining === 0, "quota display should clamp negative remaining quota")
  assert(empty.percentRemaining === 0, "quota bar should be empty at zero remaining credits")
  assert(empty.tone === "empty", "quota display should mark empty monthly quota")
}

function assertScanCreditCostsMatchMode() {
  assert(scanCreditCostForMode("normal") === 1, "normal scans should consume one monthly credit")
  assert(scanCreditCostForMode("max") === 2, "max scans should consume two monthly credits")
  assert(scanCreditCostForMode("rules") === 1, "rules-compatible scans should consume one monthly credit")
}

function assertSharedMonthlyQuotaPolicy() {
  const anonymous = {
    subjectHash: "anonymous",
    quotaSubjectHash: "anonymous",
    rateLimitSubjectHash: "anonymous-rate-limit",
    kind: "anonymous" as const,
    label: "anonymous browser",
  }
  const user = {
    subjectHash: "user",
    quotaSubjectHash: "user",
    linkedQuotaSubjectHash: "anonymous",
    rateLimitSubjectHash: "user-rate-limit",
    kind: "clerk_user" as const,
    label: "Badger user",
  }

  assert(monthlyScanQuotaLimit(anonymous) === 5, "anonymous visitors should get five monthly credits")
  assert(monthlyScanQuotaLimit(user) === 7, "signed-in users should get seven monthly credits")

  const upgrade = planLinkedMonthlyQuotaConsumption({
    primaryCount: 0,
    linkedCount: 5,
    limit: 7,
    requestCost: 1,
  })
  assert(upgrade.allowed, "signing in after guest usage should allow only the upgraded allowance")
  assert(upgrade.primaryCost === 6, "linked guest usage should be carried into the signed-in quota ledger")
  assert(upgrade.remaining === 1, "five guest credits plus one signed-in credit should leave one of seven")

  const exhausted = planLinkedMonthlyQuotaConsumption({
    primaryCount: 6,
    linkedCount: 5,
    limit: 7,
    requestCost: 2,
  })
  assert(!exhausted.allowed, "Max should be blocked when guest-linked usage leaves fewer than two credits")
}

function assertScanModeAccessRules() {
  const anonymous = {
    subjectHash: "anonymous",
    quotaSubjectHash: "anonymous",
    rateLimitSubjectHash: "anonymous-rate-limit",
    kind: "anonymous" as const,
    label: "anonymous browser",
  }
  const user = {
    subjectHash: "user",
    quotaSubjectHash: "user",
    linkedQuotaSubjectHash: "anonymous",
    rateLimitSubjectHash: "user-rate-limit",
    kind: "clerk_user" as const,
    label: "Badger user",
  }

  assertScanModeAllowed(anonymous, "normal")
  assertScanModeAllowed(user, "max")

  let blocked = false
  try {
    assertScanModeAllowed(anonymous, "max")
  } catch (error) {
    blocked = error instanceof SecurityError && error.status === 401 && error.code === "max_login_required"
  }

  assert(blocked, "anonymous users must be blocked from Max before quota or extraction work")
}

function assertAnonymousReportHistoryIsListable() {
  const anonymous = {
    subjectHash: "anonymous-report-owner",
    quotaSubjectHash: "anonymous-report-owner",
    rateLimitSubjectHash: "anonymous-rate-limit",
    kind: "anonymous" as const,
    label: "anonymous browser",
  }
  const user = {
    subjectHash: "user-report-owner",
    quotaSubjectHash: "user-report-owner",
    linkedQuotaSubjectHash: "anonymous-report-owner",
    rateLimitSubjectHash: "user-rate-limit",
    kind: "clerk_user" as const,
    label: "Badger user",
  }

  assert(reportHistoryOwnerHash(anonymous) === "anonymous-report-owner", "anonymous scan history should list reports owned by the anonymous identity")
  assert(reportHistoryOwnerHash(user) === "user-report-owner", "signed-in scan history should remain scoped to the signed-in account")
}

function assertAnonymousGuestIdentityUsesHttpOnlyCookie() {
  const first = ensureAnonymousGuestIdentity(new Headers(), "rate-limit-a")
  const second = ensureAnonymousGuestIdentity(new Headers(), "rate-limit-a")
  assert(first.subjectHash !== second.subjectHash, "new anonymous browsers must not share report ownership by IP")
  assert(first.rateLimitSubjectHash === "rate-limit-a", "anonymous rate limiting should still use the abuse subject")
  assert(first.setCookie?.includes("HttpOnly"), "anonymous guest cookie must be HttpOnly")
  assert(first.setCookie?.includes("SameSite=Lax"), "anonymous guest cookie must use SameSite=Lax")

  const cookieValue = /^badger_guest_id=([^;]+)/.exec(first.setCookie ?? "")?.[1]
  assert(Boolean(cookieValue), "anonymous guest cookie should include a guest id value")
  const repeated = ensureAnonymousGuestIdentity(new Headers({ cookie: `badger_guest_id=${cookieValue}` }), "rate-limit-b")
  assert(repeated.subjectHash === first.subjectHash, "same anonymous browser cookie should keep the same report owner")
  assert(!repeated.setCookie, "existing anonymous guest cookie should not be rewritten")
}

function assertSameOriginRequestGuard() {
  const previous = process.env.BADGER_ALLOWED_ORIGINS
  try {
    delete process.env.BADGER_ALLOWED_ORIGINS
    assertSameOriginRequest(new Request("https://badger-security.vercel.app/api/scan"))
    assertSameOriginRequest(new Request("https://badger-security.vercel.app/api/scan", {
      headers: { Origin: "https://badger-security.vercel.app" },
    }))

    let blocked = false
    try {
      assertSameOriginRequest(new Request("https://badger-security.vercel.app/api/scan", {
        headers: { Origin: "https://evil.example" },
      }))
    } catch (error) {
      blocked = error instanceof SecurityError && error.status === 403 && error.code === "cross_origin_request_blocked"
    }
    assert(blocked, "cross-origin state-changing requests must be blocked")

    process.env.BADGER_ALLOWED_ORIGINS = "https://preview.badger-security.vercel.app"
    assertSameOriginRequest(new Request("https://badger-security.vercel.app/api/scan", {
      headers: { Origin: "https://preview.badger-security.vercel.app" },
    }))
  } finally {
    if (previous === undefined) delete process.env.BADGER_ALLOWED_ORIGINS
    else process.env.BADGER_ALLOWED_ORIGINS = previous
  }
}

function assertCodeloadDefaultsAreConservative() {
  const previousArchive = process.env.BADGER_GITHUB_CODELOAD_MAX_ARCHIVE_BYTES
  const previousTar = process.env.BADGER_GITHUB_CODELOAD_MAX_TAR_BYTES
  try {
    delete process.env.BADGER_GITHUB_CODELOAD_MAX_ARCHIVE_BYTES
    delete process.env.BADGER_GITHUB_CODELOAD_MAX_TAR_BYTES
    const defaults = getCodeloadLimits()
    assert(defaults.maxArchiveBytes === 15_000_000, "default codeload archive limit should be 15 MB")
    assert(defaults.maxTarBytes === 50_000_000, "default codeload tar expansion limit should be 50 MB")

    process.env.BADGER_GITHUB_CODELOAD_MAX_ARCHIVE_BYTES = "12000000"
    process.env.BADGER_GITHUB_CODELOAD_MAX_TAR_BYTES = "42000000"
    const configured = getCodeloadLimits()
    assert(configured.maxArchiveBytes === 12_000_000, "codeload archive env override should still work")
    assert(configured.maxTarBytes === 42_000_000, "codeload tar env override should still work")
  } finally {
    if (previousArchive === undefined) delete process.env.BADGER_GITHUB_CODELOAD_MAX_ARCHIVE_BYTES
    else process.env.BADGER_GITHUB_CODELOAD_MAX_ARCHIVE_BYTES = previousArchive
    if (previousTar === undefined) delete process.env.BADGER_GITHUB_CODELOAD_MAX_TAR_BYTES
    else process.env.BADGER_GITHUB_CODELOAD_MAX_TAR_BYTES = previousTar
  }
}

function assertBackgroundJobsStayDisabledUntilAtomicClaim() {
  const previous = process.env.BADGER_ENABLE_BACKGROUND_JOBS
  try {
    process.env.BADGER_ENABLE_BACKGROUND_JOBS = "true"
    assert(backgroundJobsEnabled() === false, "background jobs must stay disabled until atomic Supabase job claim exists")
  } finally {
    if (previous === undefined) delete process.env.BADGER_ENABLE_BACKGROUND_JOBS
    else process.env.BADGER_ENABLE_BACKGROUND_JOBS = previous
  }
}

function assertMaxLaunchReviewAppearsOnlyForMaxReports() {
  const maxReport = makeTriageReport([], {
    analysisMode: "max",
    maxLaunchReview: {
      verdict: "needs_attention",
      summary: "The public endpoint has cost controls, but quota timing needs review.",
      sections: [
        {
          area: "Cost and abuse controls",
          status: "action_required",
          summary: "Monthly credits must be consumed before expensive GitHub extraction.",
          evidence: ["app/api/scan/route.ts"],
          recommendations: ["Reserve credits before extracting repository files."],
        },
      ],
    },
  } as Partial<ScanReport>)
  const normalReport = makeTriageReport([], {
    analysisMode: "normal",
    maxLaunchReview: maxReport.maxLaunchReview,
  } as Partial<ScanReport>)

  const maxBody = generateFullReportBody(maxReport)
  const normalBody = generateFullReportBody(normalReport)
  assert(maxBody.includes("## Max launch review"), "Max full report should include launch review notes")
  assert(maxBody.includes("Cost and abuse controls"), "Max launch review should include section evidence")
  assert(!normalBody.includes("## Max launch review"), "Normal full report should not include Max launch review")
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

function securityRegressionFixtureFiles(): ProjectFile[] {
  return [
    {
      path: ".github/workflows/ci.yml",
      size: 130,
      text: [
        "name: ci",
        "on:",
        "  pull_request_target:",
        "permissions: write-all",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - run: npm test",
      ].join("\n"),
    },
    {
      path: "app/actions.ts",
      size: 180,
      text: [
        '"use server"',
        "import { prisma } from '@/lib/db'",
        "export async function deleteUser(formData: FormData) {",
        "  const userId = String(formData.get('userId'))",
        "  await prisma.user.delete({ where: { id: userId } })",
        "}",
      ].join("\n"),
    },
    {
      path: "app/api/search/route.ts",
      size: 220,
      text: [
        "import { prisma } from '@/lib/db'",
        "export async function POST(request: Request) {",
        "  const body = await request.json()",
        "  const rows = await prisma.$queryRawUnsafe(`select * from users where email = '${body.email}'`)",
        "  return Response.json({ rows })",
        "}",
      ].join("\n"),
    },
    {
      path: "app/api/chat/route.ts",
      size: 230,
      text: [
        "import { streamText } from 'ai'",
        "import { tools } from '@/lib/agent/tools'",
        "export async function POST(request: Request) {",
        "  const body = await request.json()",
        "  return streamText({ model: 'openai/gpt-5.2-mini', prompt: body.message, tools }).toTextStreamResponse()",
        "}",
      ].join("\n"),
    },
    {
      path: "app/dashboard/page.tsx",
      size: 70,
      text: "'use client'\nexport default function Page() { return <pre>{JSON.stringify({ token: 'demo-token' })}</pre> }\n",
    },
    {
      path: "lib/agent/tools.ts",
      size: 160,
      text: [
        "export const tools = {",
        "  search: async () => 'ok',",
        "  deleteUser: async () => 'deleted',",
        "}",
        "export async function runTool(input: { tool: string }) {",
        "  return tools[input.tool as keyof typeof tools]()",
        "}",
      ].join("\n"),
    },
    {
      path: "supabase/migrations/001_init.sql",
      size: 280,
      text: [
        "create table public.accounts (",
        "  id uuid primary key,",
        "  email text not null",
        ");",
        "alter table public.accounts disable row level security;",
        "create function public.admin_delete_account(account_id uuid)",
        "returns void language plpgsql security definer as $$",
        "begin",
        "  delete from public.accounts where id = account_id;",
        "end;",
        "$$;",
      ].join("\n"),
    },
    {
      path: "prisma/schema.prisma",
      size: 120,
      text: "datasource db { provider = \"postgresql\" url = env(\"DATABASE_URL\") }\ngenerator client { provider = \"prisma-client-js\" }\n",
    },
  ]
}

function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message)
}

void main().catch((error) => {
  console.error(error)
  process.exit(1)
})
