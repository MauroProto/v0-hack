import type { ProjectFile, ScanFinding, Severity } from "./types"

export type RuleFinding = Omit<ScanFinding, "id">

const ENV_FILE_NAMES = new Set([".env", ".env.local", ".env.production", ".env.development"])

const SENSITIVE_API_SEGMENTS = /\/(admin|internal|billing|users|secrets)\//i
const AUTH_SIGNALS =
  /\b(?:auth\s*\(|getServerSession\s*\(|currentUser\s*\(|clerkClient|verifyToken\s*\(|getSession\s*\(|requireAuth\s*\(|withAuth\s*\(|middleware|validateSession\s*\(|session\s*[:=]|jwtVerify\s*\()/i
const STRONG_AUTH_GUARD_SIGNALS =
  /\b(requireAuth|withAuth|assertAuthenticated|assertAuthorized|requireUser|requireAdmin|ensureAuth|ensureUser|requireSession|requireRole|requirePermission)\s*\(/i
const AUTH_DENY_SIGNALS =
  /\b(status\s*:\s*(401|403)|Unauthorized|Forbidden|Access denied|redirect\s*\(\s*["'][^"']*(login|signin|auth)|notFound\s*\()/i
const AUTH_CONDITION_SIGNALS =
  /if\s*\(\s*(?:!\s*(session|user|currentUser|viewer|account|token|authResult)\b(?:\??\.[A-Za-z_$][\w$]*)*|(?:session|user|currentUser|viewer|account|token|authResult)(?:\??\.[A-Za-z_$][\w$]*)*\s*(?:={2,3}|!)\s*(?:null|undefined)|[^)]*\b(role|permission|ownerId|userId|organizationId|teamId|isAdmin|canAccess|canManage|hasPermission)\b[^)]*)\)/i
const COOKIES_SESSION_SIGNAL = /\bcookies\(\)/i
const HEADERS_TOKEN_SIGNAL = /\bheaders\(\)/i
const SESSION_OR_TOKEN_SIGNAL = /\b(session|token|authorization|bearer|jwt|auth)\b/i
const AI_ENDPOINT_SIGNALS =
  /\b(generateText|streamText|generateObject|streamObject|openai\.chat\.completions|anthropic\.messages\.create|model\s*:|tools\s*:)\b/i
const AI_IMPORT_SIGNALS = /\bfrom\s+["']ai["']|from\s+["']@ai-sdk\/|from\s+["']openai["']|from\s+["']@anthropic-ai\//i
const RATE_LIMIT_SIGNALS = /\b(rateLimit|ratelimit|upstash|limit\(|quota|budget|BotID|botid|verifyBot|turnstile|recaptcha)\b/i
const AI_STEP_LIMIT_SIGNALS = /\b(maxSteps|maxToolRoundtrips|stopWhen|stepCountIs|toolChoice|maxTokens|budget|quota)\b/i
const VALIDATION_SIGNALS = /\b(zod|\.parse\(|\.safeParse\(|yup|valibot|superstruct)\b/i
const JSON_PARSE_SIGNALS = /\bawait\s+(req|request)\.json\(\)/i
const TOOL_CONTEXT_SIGNALS = /\b(tools?|agents?|mcp|function calling|toolName|availableTools)\b/i
const WEBHOOK_PATH_SIGNAL = /\/webhooks?\//i
const WEBHOOK_PROVIDER_SIGNAL = /\b(stripe|github|clerk|svix|supabase|resend|polar|lemonsqueezy|webhook)\b/i
const WEBHOOK_SIGNATURE_SIGNALS =
  /\b(constructEvent|verifyWebhook|verifySignature|stripe-signature|svix-signature|x-hub-signature|x-signature|createHmac|timingSafeEqual|crypto\.subtle|Webhook\s*\()/i
const PERMISSIVE_CORS_SIGNALS =
  /\b(Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*(true|["']\*["'])|cors\s*\(\s*\{[^}]*origin\s*:\s*(true|["']\*["']))/i
const UNSAFE_DATABASE_QUERY_SIGNALS =
  /\b(\$queryRawUnsafe|\$executeRawUnsafe|(?:db|pool|client|connection)\.query\s*\(\s*`[^`]*\$\{[^}]*\b(req|request|body|input|params|searchParams)\b)/i
const INSTALL_SCRIPT_NAMES = new Set(["preinstall", "install", "postinstall", "prepare"])
const RISKY_INSTALL_SCRIPT_SIGNALS = /\b(curl|wget|bash|sh|node\s+-e|npx|pnpm\s+dlx|bunx)\b/i
const REMOTE_INSTALL_PIPE_TO_SHELL =
  /\b(?:curl|wget)\b[^\n|;&]*(?:https?:\/\/|raw\.githubusercontent\.com|github\.com)[^\n|;&]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i
const SHA_REF_RE = /^[a-f0-9]{40}$/i

const DANGEROUS_NEXT_PUBLIC_NAMES = [
  "NEXT_PUBLIC_OPENAI_API_KEY",
  "NEXT_PUBLIC_ANTHROPIC_API_KEY",
  "NEXT_PUBLIC_STRIPE_SECRET_KEY",
  "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
  "NEXT_PUBLIC_DATABASE_URL",
  "NEXT_PUBLIC_DEEPSEEK_API_KEY",
  "NEXT_PUBLIC_CLAUDE_API_KEY",
]

const GENERIC_SECRET_NAMES =
  /\b(SECRET_KEY|API_SECRET|PRIVATE_KEY|DATABASE_URL|SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|DEEPSEEK_API_KEY|VERCEL_TOKEN|GITHUB_TOKEN)\b/i

const SECRET_PATTERNS: { name: string; regex: RegExp }[] = [
  { name: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{10,}\b/g },
  { name: "OpenAI API key", regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{10,}\b/g },
  { name: "Stripe secret key", regex: /\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: "GitHub token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g },
  { name: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { name: "Vercel token", regex: /\bvercel_[A-Za-z0-9]{20,}\b/gi },
  { name: "JWT-like token", regex: /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: "private key block", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
]

const CLIENT_SENSITIVE_NAMES = /\b(password|token|apiKey|api_key|secret|ssn|creditCard|credit_card|customerEmail)\b/i

export interface ProjectSignals {
  framework?: string
  isNextApp: boolean
  hasAppRouter: boolean
  hasPagesRouter: boolean
  hasVite: boolean
  hasAiSdk: boolean
  hasOpenAiSdk: boolean
  hasAnthropicSdk: boolean
  hasRust: boolean
  hasTauri: boolean
  hasVercelAnalytics: boolean
  hasSpeedInsights: boolean
  hasAiGateway: boolean
  hasBotProtection: boolean
  hasSignupContactCheckout: boolean
}

export interface RuleScanStats {
  apiRoutesInspected: number
  clientComponentsInspected: number
  aiEndpointsInspected: number
}

export interface RuleScanResult {
  findings: RuleFinding[]
  signals: ProjectSignals
  stats: RuleScanStats
}

export function collectRuleFindings(files: ProjectFile[]): RuleScanResult {
  const signals = detectProjectSignals(files)
  const stats: RuleScanStats = {
    apiRoutesInspected: files.filter((file) => isApiRoute(file.path)).length,
    clientComponentsInspected: files.filter((file) => isClientComponent(file.text)).length,
    aiEndpointsInspected: files.filter((file) => isApiRoute(file.path) && isAiEndpoint(file.text)).length,
  }
  const findings: RuleFinding[] = []
  const seen = new Set<string>()

  const add = (finding: RuleFinding) => {
    const key = [
      finding.category,
      finding.title,
      finding.filePath,
      finding.lineStart ?? "",
      finding.evidence ?? "",
    ].join("|")

    if (seen.has(key)) return
    seen.add(key)
    findings.push(finding)
  }

  for (const file of files) {
    scanCommittedEnvFile(file, add)
    scanSecretPatterns(file, add)
    scanHighEntropySecretAssignments(file, add)
    scanDangerousNextPublic(file, add)
    scanAdminRouteWithoutAuth(file, add)
    scanAiEndpointWithoutGuard(file, add)
    scanAiToolCallingWithoutBounds(file, add)
    scanUnsafeToolCalling(file, add)
    scanAgentToolingRisks(file, add)
    scanMissingInputValidation(file, add)
    scanWebhookWithoutSignature(file, add)
    scanPermissiveCors(file, add)
    scanCookieHardening(file, add)
    scanUnsafeDatabaseQuery(file, add)
    scanRequestTaintToDangerousSink(file, add)
    scanUnsafeRedirect(file, add)
    scanServerActionRisks(file, add)
    scanSupabaseRisks(file, add)
    scanPrismaSchemaRisks(file, add)
    scanGitHubActionsRisks(file, add)
    scanRemoteInstallPipeToShell(file, add)
    scanDangerousCode(file, add)
    scanRustDangerousCode(file, add)
    scanPackageScripts(file, add)
    scanSensitiveClientData(file, add)
  }

  scanVercelHardening(files, signals, add)

  return { findings, signals, stats }
}

export function detectProjectSignals(files: ProjectFile[]): ProjectSignals {
  const paths = files.map((file) => normalizePath(file.path))
  const allText = files.map((file) => file.text.slice(0, 80_000)).join("\n")
  const hasAppRouter = paths.some((path) => path.startsWith("app/"))
  const hasPagesRouter = paths.some((path) => path.startsWith("pages/"))
  const hasNextConfig = paths.some((path) => /^next\.config\.(mjs|js|ts|cjs)$/.test(path))
  const hasVite = paths.some((path) => /^vite\.config\.(mjs|js|ts|cjs)$/.test(path))
  const hasPythonManifest = paths.some((path) =>
    /(^|\/)(pyproject\.toml|requirements\.txt|setup\.py|setup\.cfg|Pipfile)$/.test(path),
  )
  const hasCargoToml = paths.some((path) => path === "Cargo.toml" || path.endsWith("/Cargo.toml"))
  const hasRust = hasCargoToml || paths.some((path) => path.endsWith(".rs"))
  const hasTauri =
    paths.some((path) => path.startsWith("src-tauri/") || path.endsWith("/tauri.conf.json") || path === "tauri.conf.json") ||
    /tauri-build|@tauri-apps\/api|tauri::/i.test(allText)
  const hasAiSdk = /\bfrom\s+["']ai["']|["']ai["']\s*:|from\s+["']@ai-sdk\//.test(allText)
  const hasOpenAiSdk = /\bfrom\s+["']openai["']|["']openai["']\s*:/.test(allText)
  const hasAnthropicSdk = /\bfrom\s+["']@anthropic-ai\/|["']@anthropic-ai\//.test(allText)

  let framework: string | undefined
  if (hasAppRouter && hasNextConfig) framework = "Next.js App Router"
  else if (hasPagesRouter && hasNextConfig) framework = "Next.js Pages Router"
  else if (hasNextConfig) framework = "Next.js"
  else if (hasVite) framework = "React/Vite"
  else if (hasTauri) framework = "Tauri/Rust"
  else if (hasRust) framework = "Rust"
  else if (hasPythonManifest) framework = "Python"

  return {
    framework,
    isNextApp: Boolean(hasNextConfig || hasAppRouter || hasPagesRouter),
    hasAppRouter,
    hasPagesRouter,
    hasVite,
    hasAiSdk,
    hasOpenAiSdk,
    hasAnthropicSdk,
    hasRust,
    hasTauri,
    hasVercelAnalytics: /@vercel\/analytics|<Analytics\b|injectAnalytics\(/.test(allText),
    hasSpeedInsights: /@vercel\/speed-insights|<SpeedInsights\b/.test(allText),
    hasAiGateway:
      /AI_GATEWAY|ai gateway|@ai-sdk\/gateway|model\s*:\s*["'][a-z0-9-]+\/[a-z0-9._-]+["']/i.test(allText),
    hasBotProtection: /\b(BotID|botid|verifyBot|turnstile|recaptcha)\b/i.test(allText),
    hasSignupContactCheckout: paths.some((path) => /\/(signup|contact|checkout)\//i.test(`/${path}/`)),
  }
}

function scanCommittedEnvFile(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const name = basename(file.path)
  if (!ENV_FILE_NAMES.has(name)) return

  const secretLike = hasSecretLikeContent(file)
  add({
    severity: secretLike ? "critical" : "medium",
    category: "secret_exposure",
    title: "Committed environment file detected",
    description: `${name} is present in the repository. Environment files often contain credentials and should not be committed.`,
    filePath: file.path,
    lineStart: 1,
    evidence: redactSecrets(firstNonEmptyLine(file.text) || name),
    confidence: secretLike ? 0.96 : 0.82,
    recommendation: "Remove committed environment files, rotate any exposed values, and keep only safe placeholders in .env.example.",
    patchable: false,
    source: "rule",
  })
}

function scanSecretPatterns(file: ProjectFile, add: (finding: RuleFinding) => void) {
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0
    for (const match of file.text.matchAll(pattern.regex)) {
      const index = match.index ?? 0
      const { line, lineNumber } = lineAtIndex(file.text, index)
      if (shouldIgnoreSecretPatternMatch(file.path, line)) continue

      add({
        kind: "vulnerability",
        severity: "critical",
        category: "secret_exposure",
        ruleId: "secret.provider-token.committed",
        title: `${pattern.name} appears to be exposed`,
        description: `A value matching ${pattern.name} was found in source-controlled project files.`,
        filePath: file.path,
        lineStart: lineNumber,
        evidence: redactSecrets(line.trim()),
        confidence: pattern.name === "JWT-like token" ? 0.78 : 0.94,
        confidenceReason: "Provider-format credential value was found outside documentation, tests, fixtures, placeholders, and redaction detector code.",
        reachability: "reachable",
        exploitability: "high",
        recommendation: "Revoke and rotate this credential, remove it from the repository, and read it only from server-side environment variables.",
        patchable: true,
        source: "rule",
      })
    }
  }

  file.text.split(/\r?\n/).forEach((line, index) => {
    if (!GENERIC_SECRET_NAMES.test(line)) return
    if (!extractSecretAssignment(line)) return
    if (!lineHasConcreteSecretValue(file.path, line)) return

    add({
      kind: "vulnerability",
      severity: "critical",
      category: "secret_exposure",
      ruleId: "secret.high-risk-name.assigned-value",
      title: "High-risk secret name with assigned value",
      description: "A high-risk secret variable name appears with a committed value.",
      filePath: file.path,
      lineStart: index + 1,
      evidence: redactSecrets(line.trim()),
      confidence: 0.82,
      confidenceReason: "A sensitive env/secret variable is assigned a concrete non-placeholder value.",
      reachability: "reachable",
      exploitability: "high",
      recommendation: "Move the value to a server-only environment variable, rotate it if it was real, and commit only placeholders.",
      patchable: true,
      source: "rule",
    })
  })
}

function scanHighEntropySecretAssignments(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (isDocumentationPath(file.path) || isTestOrFixturePath(file.path) || isExampleOrTemplatePath(file.path)) return

  file.text.split(/\r?\n/).forEach((line, index) => {
    if (isScannerSelfTestOrDetectorLine(file.path, line)) return
    if (isCommentOnlyLine(line)) return
    if (isEnvVarReferenceLine(line)) return
    if (isGitHubActionsSecretReference(line)) return
    if (isSecretDetectorPatternLine(line)) return
    if (isObviousPlaceholder(line)) return

    const assignment = extractGenericSecretAssignment(line)
    if (!assignment) return
    if (!isSecretishIdentifier(assignment.name)) return
    if (!looksLikeHighEntropyToken(assignment.value)) return
    if (shannonEntropy(assignment.value) < 3.65) return

    add({
      kind: "vulnerability",
      severity: "critical",
      category: "secret_exposure",
      ruleId: "secret.generic-high-entropy-assignment",
      title: "High-entropy secret-like value committed",
      description:
        "A secret-looking identifier is assigned a high-entropy literal in production source. This follows a Gitleaks-style context check instead of matching variable names alone.",
      filePath: file.path,
      lineStart: index + 1,
      evidence: redactSecrets(line.trim()),
      confidence: 0.86,
      confidenceReason:
        "Secret-like identifier plus high-entropy literal in production source; documentation, fixtures, placeholders and redaction-pattern code were excluded.",
      reachability: "reachable",
      exploitability: "high",
      recommendation:
        "Rotate the value if it was real, remove it from source control, and load it from a server-only secret store or environment variable.",
      patchable: true,
      source: "rule",
    })
  })
}

function scanDangerousNextPublic(file: ProjectFile, add: (finding: RuleFinding) => void) {
  file.text.split(/\r?\n/).forEach((line, index) => {
    if (isCommentOnlyLine(line)) return
    if (isScannerSelfTestOrDetectorLine(file.path, line)) return
    if (isScannerReportPresentationLine(file.path, line)) return

    const matches = line.match(/\bNEXT_PUBLIC_[A-Z0-9_]+\b/g)
    if (!matches) return

    for (const name of matches) {
      const exactDanger = DANGEROUS_NEXT_PUBLIC_NAMES.includes(name)
      const containsDanger = /SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL/.test(name)
      const tokenLike = /TOKEN/.test(name)
      if (!exactDanger && !containsDanger && !tokenLike) continue
      const examplePlaceholder = isExampleSecretPlaceholder(file.path, line)
      if (isDocumentationPublicEnvPlaceholder(file.path, line)) continue

      add({
        severity: examplePlaceholder || (tokenLike && !containsDanger && !exactDanger) ? "high" : "critical",
        category: "public_env_misuse",
        title: "Dangerous NEXT_PUBLIC environment variable",
        description: `${name} is exposed to browser bundles because it uses the NEXT_PUBLIC_ prefix. In an example file this is still an unsafe env contract, not a leaked secret.`,
        filePath: file.path,
        lineStart: index + 1,
        evidence: redactSecrets(line.trim()),
        confidence: examplePlaceholder ? 0.78 : 0.97,
        recommendation: "Move this value to server-only env vars and access it only from server routes/actions.",
        patchable: true,
        source: "rule",
      })
    }
  })
}

function isDocumentationPublicEnvPlaceholder(path: string, line: string) {
  if (!isDocumentationPath(path)) return false
  const assigned = extractAssignedValue(line)
  if (!assigned) return true
  return isObviousPlaceholder(line) || isLocalOrExampleAssignedValue(assigned)
}

function scanAdminRouteWithoutAuth(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!SENSITIVE_API_SEGMENTS.test(`/${normalizePath(file.path)}/`)) return
  const hasAuthCall = hasAuthSignal(file.text)
  if (hasEffectiveAuthGuard(file.text)) return

  add({
    severity: "high",
    category: hasAuthCall ? "missing_authorization" : "missing_auth",
    title: hasAuthCall ? "Sensitive API route calls auth without enforcing access" : "Sensitive API route lacks an obvious auth guard",
    description: hasAuthCall
      ? "This admin/internal-style API route calls an auth helper, but does not show a clear deny path, role check, or ownership check before handling data."
      : "This admin/internal-style API route does not show an authentication or authorization check before handling data.",
    filePath: file.path,
    lineStart: firstHandlerLine(file.text),
    evidence: redactSecrets(findLineMatching(file.text, /\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|NextResponse\.json|Response\.json/)?.line ?? ""),
    confidence: 0.82,
    recommendation: hasAuthCall
      ? "Check the session/user result and return 401/403 before returning sensitive data or performing mutations. Add role and ownership checks where needed."
      : "Add a server-side authentication/authorization guard before returning data or performing mutations.",
    patchable: true,
    source: "rule",
  })
}

function scanAiEndpointWithoutGuard(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!isAiEndpoint(file.text)) return
  if (RATE_LIMIT_SIGNALS.test(file.text)) return

  const hit = findLineMatching(file.text, AI_ENDPOINT_SIGNALS) ?? findLineMatching(file.text, AI_IMPORT_SIGNALS)
  add({
    severity: "high",
    category: "ai_endpoint_risk",
    title: "AI endpoint has no obvious rate limit or abuse guard",
    description: "This route appears to invoke a model or expose tools without rate limiting, bot checks, quota, or budget controls.",
    filePath: file.path,
    lineStart: hit?.lineNumber ?? firstHandlerLine(file.text),
    evidence: redactSecrets(hit?.line.trim() ?? ""),
    confidence: 0.86,
    recommendation: "Add rate limiting, abuse protection and budget controls before invoking the model.",
    patchable: true,
    source: "rule",
  })
}

function scanAiToolCallingWithoutBounds(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!/\btools\s*:/.test(file.text)) return
  if (!/\b(generateText|streamText|generateObject|streamObject)\b/i.test(file.text)) return
  if (AI_STEP_LIMIT_SIGNALS.test(file.text)) return

  const hit = findLineMatching(file.text, /\btools\s*:/)
  add({
    severity: "medium",
    category: "ai_endpoint_risk",
    title: "AI tool-calling endpoint lacks explicit execution bounds",
    description:
      "This endpoint exposes tools to a model but does not show an explicit step, tool-round, token, quota, or budget limit. That increases excessive-agency and cost-abuse risk.",
    filePath: file.path,
    lineStart: hit?.lineNumber ?? firstHandlerLine(file.text),
    evidence: redactSecrets(hit?.line.trim() ?? ""),
    confidence: 0.78,
    recommendation: "Set explicit tool-call step limits, token limits, and budget/quota checks before allowing model-controlled tool execution.",
    patchable: true,
    source: "rule",
  })
}

function scanUnsafeToolCalling(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!TOOL_CONTEXT_SIGNALS.test(file.text) && !/\/(agent|mcp|tool)s?\//i.test(`/${file.path}/`)) return

  const patterns = [
    /tools\s*\[\s*req\.body\.tool\s*\]/i,
    /tools\s*\[\s*input\.tool\s*\]/i,
    /availableTools\s*\[\s*userInput\s*\]/i,
    /\bconst\s+toolName\s*=\s*(?:await\s+)?(?:req|request)\.json\(\)/i,
    /\btoolName\b[\s\S]{0,120}\b(req|request|body|input|userInput)\b/i,
    /\b(tools|availableTools)\s*\[\s*(toolName|body\.tool|input\.tool|userInput)\s*\]/i,
  ]

  for (const pattern of patterns) {
    const hit = findLineMatching(file.text, pattern)
    if (!hit) continue
    if (isScannerSelfTestOrDetectorLine(file.path, hit.line)) continue

    add({
      severity: "high",
      category: /mcp/i.test(file.path) ? "mcp_risk" : "unsafe_tool_calling",
      title: "Dynamic tool selection from user input",
      description: "Tool dispatch appears to be selected directly from request or user-controlled input.",
      filePath: file.path,
      lineStart: hit.lineNumber,
      evidence: redactSecrets(hit.line.trim()),
      confidence: 0.82,
      recommendation: "Use an explicit allowlist of tools and validate tool names server-side before dispatch.",
      patchable: true,
      source: "rule",
    })
    return
  }
}

function scanAgentToolingRisks(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!file.path.endsWith(".rs")) return
  const normalized = normalizePath(file.path).toLowerCase()

  if (isAgentShellToolFile(normalized, file.text)) {
    const sink = findLineMatching(file.text, /\bCommand::new\s*\(\s*["'](?:bash|sh|cmd(?:\.exe)?)["']\s*\)[^\n]*(?:-c|\/C|cmd_str|command|input)/i) ??
      findLineMatching(file.text, /\b(?:bash|sh|cmd(?:\.exe)?)\b[\s\S]{0,120}\b(?:cmd_str|command|input)\b/i)
    const source = findLineMatching(file.text, /\bcommand\s*:\s*String\b|\bcommand["']?\s*:\s*\{|\bBashToolInput\b/i)
    if (sink) {
      const mitigations = detectAgentShellMitigations(file.text)
      const detectedControls = mitigations.detected.map((item) => item.label)
      const missingControls = mitigations.missing.map((item) => item.label)
      const hasStrongControl = mitigations.detected.some((item) => item.key === "approval" || item.key === "sandbox")
      const hasAnyControl = mitigations.detected.length > 0
      add({
        kind: "vulnerability",
        severity: hasAnyControl ? "high" : "critical",
        category: "unsafe_tool_calling",
        ruleId: "agent.shell.tool-command-execution",
        title: "Agent-controlled shell execution surface",
        description:
          [
            "This repository exposes a shell command tool that can execute a model/user-provided command through a system shell.",
            "That is a core agent risk surface.",
            `Detected controls: ${detectedControls.length ? detectedControls.join(", ") : "none visible"}.`,
            `Missing or unclear controls: ${missingControls.length ? missingControls.join(", ") : "none"}.`,
          ].join(" "),
        filePath: file.path,
        lineStart: sink.lineNumber,
        evidence: redactSecrets(sink.line.trim()),
        confidence: 0.9,
        confidenceReason: hasStrongControl
          ? "Shell execution from a command-shaped tool input was found; approval/sandbox language is present but still requires architectural review."
          : hasAnyControl
          ? "Shell execution from a command-shaped tool input was found; partial controls are visible but approval/sandbox/env isolation were not all proven."
          : "Shell execution from a command-shaped tool input was found without obvious approval/sandbox guard keywords.",
        reachability: "reachable",
        exploitability: "high",
        cwe: "CWE-78",
        owasp: "LLM06 Excessive Agency",
        evidenceTrace: [
          ...(source ? [{
            filePath: file.path,
            lineStart: source.lineNumber,
            kind: "source" as const,
            label: "Agent/tool command input",
            code: redactSecrets(source.line.trim()),
          }] : []),
          {
            filePath: file.path,
            lineStart: sink.lineNumber,
            kind: "sink",
            label: "Shell execution sink",
            code: redactSecrets(sink.line.trim()),
          },
          ...mitigations.detected.map((control) => ({
            filePath: file.path,
            lineStart: control.lineNumber,
            kind: "guard" as const,
            label: `${control.label} detected`,
            code: redactSecrets(control.line.trim()),
          })),
        ],
        recommendation:
          "Require explicit user approval for shell commands, run inside a constrained sandbox, strip secrets from the environment, add timeouts, and block remote bootstrap/exfiltration commands by policy.",
        patchable: false,
        source: "rule",
      })
    }
  }

  if (isMcpRustFile(normalized, file.text)) {
    const configCommand = findLineMatching(file.text, /\bCommand::new\s*\(\s*&?config\.command\b/i)
    if (configCommand) {
      add({
        kind: "vulnerability",
        severity: "high",
        category: "mcp_risk",
        ruleId: "mcp.process.config-command",
        title: "MCP server process is spawned from configuration",
        description:
          "An MCP server command is launched from config. That can be legitimate, but it makes MCP configuration a supply-chain execution boundary that needs trust controls and clear review.",
        filePath: file.path,
        lineStart: configCommand.lineNumber,
        evidence: redactSecrets(configCommand.line.trim()),
        confidence: 0.86,
        confidenceReason: "MCP-related Rust code starts a process from config.command.",
        reachability: "reachable",
        exploitability: "high",
        cwe: "CWE-78",
        owasp: "LLM06 Excessive Agency",
        evidenceTrace: compactTrace([
          traceFromHit(file.path, "source", "MCP configuration model", findLineMatching(file.text, /\bMcpConfig\b|mcp\.json|config\.command/i)),
          traceFromHit(file.path, "propagator", "Configured MCP command", findLineMatching(file.text, /\bconfig\.command\b/i)),
          traceFromHit(file.path, "sink", "Process spawn from MCP config", configCommand),
        ]),
        recommendation: "Treat MCP config as executable trust policy: require explicit user consent, validate command paths, and prefer allowlisted server definitions.",
        patchable: false,
        source: "rule",
      })
    }

    const fullEnv = /\bstd::env::vars\s*\(\s*\)/.test(file.text) && /\.envs\s*\(\s*&?env\b/.test(file.text)
    if (fullEnv) {
      const envHit = findLineMatching(file.text, /\.envs\s*\(\s*&?env\b/) ?? findLineMatching(file.text, /\bstd::env::vars\s*\(\s*\)/)
      const envSource = findLineMatching(file.text, /\bstd::env::vars\s*\(\s*\)/)
      const envExtend = findLineMatching(file.text, /\benv\.extend\s*\(\s*config\.env\b/i)
      add({
        kind: "vulnerability",
        severity: "high",
        category: "mcp_risk",
        ruleId: "mcp.process.inherits-full-env",
        title: "MCP child process inherits the full environment",
        description:
          "The MCP child process appears to inherit the parent process environment. A malicious or compromised MCP server could receive provider keys, GitHub tokens, database URLs, or other local secrets.",
        filePath: file.path,
        lineStart: envHit?.lineNumber,
        evidence: redactSecrets(envHit?.line.trim() ?? "std::env::vars() -> Command.envs(env)"),
        confidence: 0.88,
        confidenceReason: "MCP code collects std::env::vars() and passes that map to Command.envs().",
        reachability: "reachable",
        exploitability: "high",
        cwe: "CWE-200",
        owasp: "LLM02 Sensitive Information Disclosure",
        evidenceTrace: compactTrace([
          traceFromHit(file.path, "source", "Parent process environment", envSource),
          traceFromHit(file.path, "propagator", "MCP config env merged into child env", envExtend),
          traceFromHit(file.path, "sink", "Full env passed to MCP child process", envHit),
        ]),
        recommendation:
          "Pass only an explicit env allowlist to MCP servers, strip provider/API tokens by default, and require per-server consent for any secret-bearing variables.",
        patchable: false,
        source: "rule",
      })
    }
  }
}

function scanWebhookWithoutSignature(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!WEBHOOK_PATH_SIGNAL.test(`/${normalizePath(file.path)}/`) && !/\bwebhooks?\b/i.test(file.text)) return
  if (!/\bawait\s+(req|request)\.(text|json|arrayBuffer)\(\)|NextResponse\.json|Response\.json/i.test(file.text)) return
  if (WEBHOOK_SIGNATURE_SIGNALS.test(file.text)) return

  const hit =
    findLineMatching(file.text, /\bawait\s+(req|request)\.(text|json|arrayBuffer)\(\)/i) ??
    findLineMatching(file.text, WEBHOOK_PROVIDER_SIGNAL)

  add({
    severity: "high",
    category: "input_validation",
    title: "Webhook route lacks obvious signature verification",
    description: "This webhook-style API route processes inbound provider data without a visible HMAC/signature verification step.",
    filePath: file.path,
    lineStart: hit?.lineNumber ?? firstHandlerLine(file.text),
    evidence: redactSecrets(hit?.line.trim() ?? ""),
    confidence: 0.8,
    recommendation: "Verify the provider signature using the raw request body before parsing or trusting webhook payload fields.",
    patchable: false,
    source: "rule",
  })
}

function scanPermissiveCors(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const isRelevantConfig = /(?:next\.config\.|vercel\.json$|middleware\.|route\.)/i.test(file.path)
  if (!isRelevantConfig) return

  const hit = findLineMatching(file.text, PERMISSIVE_CORS_SIGNALS)
  if (!hit) return

  add({
    severity: "medium",
    category: "client_data_exposure",
    title: "Permissive CORS policy detected",
    description: "A wildcard or reflected CORS policy can expose authenticated browser-accessible responses to untrusted origins.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.78,
    recommendation: "Restrict CORS to explicit trusted origins and avoid combining wildcard origins with credentials or sensitive routes.",
    patchable: false,
    source: "rule",
  })
}

function scanCookieHardening(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) return

  const lines = file.text.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (!/\b(cookies\(\)\.set|response\.cookies\.set|Set-Cookie)\b/i.test(line)) continue
    if (isScannerSelfTestOrDetectorLine(file.path, line)) continue
    if (/\bSet-Cookie\b[\s\S]*\bcreate[A-Za-z0-9_$]*Cookie\s*\(/.test(line)) continue

    const window = lines.slice(index, index + 10).join("\n")
    if (!/\b(session|token|auth|jwt|refresh|access)\b/i.test(window)) continue
    if (/\bhttpOnly\s*:\s*true\b/i.test(window) && /\bsecure\s*:\s*true\b/i.test(window) && /\bsameSite\s*:/i.test(window)) continue

    add({
      severity: "medium",
      category: "client_data_exposure",
      title: "Session-like cookie missing hardened attributes",
      description: "A session/auth/token cookie is set without all obvious httpOnly, secure, and sameSite protections nearby.",
      filePath: file.path,
      lineStart: index + 1,
      evidence: redactSecrets(line.trim()),
      confidence: 0.72,
      recommendation: "Set session cookies with httpOnly, secure, sameSite, a narrow path, and the shortest practical expiration.",
      patchable: false,
      source: "rule",
    })
    return
  }
}

function scanUnsafeDatabaseQuery(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const hit = findLineMatching(file.text, UNSAFE_DATABASE_QUERY_SIGNALS)
  if (!hit) return

  add({
    kind: "vulnerability",
    severity: "high",
    category: "sql_injection",
    ruleId: "database.raw-query.request-input",
    title: "Unsafe database query construction detected",
    description: "This code uses an unsafe raw query helper or appears to interpolate request-controlled data into a SQL query.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.82,
    confidenceReason: "Raw query helper or request-controlled interpolation was found in a database query expression.",
    reachability: isApiRoute(file.path) ? "reachable" : "unknown",
    exploitability: "high",
    cwe: "CWE-89",
    recommendation: "Use parameterized queries or safe ORM methods, and validate request-controlled inputs before they reach the database layer.",
    patchable: false,
    source: "rule",
  })
}

function scanRequestTaintToDangerousSink(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) return
  const lines = file.text.split(/\r?\n/)
  const sources = new Map<string, { line: string; lineNumber: number }>()

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    const sourceMatch = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+(?:req|request)\.(?:json|formData)\(\)/)
    if (sourceMatch) sources.set(sourceMatch[1], { line, lineNumber: index + 1 })
    if (/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:req|request)\.nextUrl\.searchParams/.test(line)) {
      const name = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)/)?.[1]
      if (name) sources.set(name, { line, lineNumber: index + 1 })
    }
  }

  if (sources.size === 0) return

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (!/(\$queryRawUnsafe|\$executeRawUnsafe|exec\s*\(|spawn\s*\(|redirect\s*\(|fetch\s*\(|dangerouslySetInnerHTML|eval\s*\(|new\s+Function\s*\()/i.test(line)) {
      continue
    }

    for (const [name, source] of sources) {
      if (!new RegExp(`\\b${escapeRegExp(name)}\\b`).test(line)) continue
      const sanitizerWindow = lines.slice(source.lineNumber - 1, index + 1).join("\n")
      if (VALIDATION_SIGNALS.test(sanitizerWindow) || /allowlist|allowedOrigins|trustedHosts|parameterized/i.test(sanitizerWindow)) continue

      add({
        kind: "vulnerability",
        severity: /(\$queryRawUnsafe|\$executeRawUnsafe)/.test(line) ? "high" : "medium",
        category: /(\$queryRawUnsafe|\$executeRawUnsafe)/.test(line) ? "sql_injection" : "input_validation",
        ruleId: "taint.intrafile.request-to-dangerous-sink",
        title: "Request-controlled data reaches a dangerous sink",
        description: "A value parsed from the request appears to flow into a dangerous operation without a visible validator or allowlist.",
        filePath: file.path,
        lineStart: index + 1,
        evidence: redactSecrets(line.trim()),
        confidence: 0.82,
        confidenceReason: "Intra-file source-to-sink trace found request input reused in a dangerous operation with no sanitizer in between.",
        reachability: "reachable",
        exploitability: "high",
        evidenceTrace: [
          { filePath: file.path, lineStart: source.lineNumber, kind: "source", label: "Request input source", code: redactSecrets(source.line.trim()) },
          { filePath: file.path, lineStart: index + 1, kind: "sink", label: "Dangerous sink", code: redactSecrets(line.trim()) },
        ],
        recommendation: "Validate the request data, pass only sanitized fields to the sink, and use allowlists or parameterized APIs instead of raw/dynamic operations.",
        patchable: false,
        source: "rule",
      })
      return
    }
  }
}

function scanUnsafeRedirect(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) return
  const hit = findLineMatching(file.text, /\bredirect\s*\(\s*(?:req|request|url|nextUrl|searchParams|params|body|input)\b/i)
  if (!hit) return
  if (/allowlist|allowedRedirect|safeRedirect|new URL\(/i.test(file.text)) return

  add({
    kind: "vulnerability",
    severity: "medium",
    category: "unsafe_redirect",
    ruleId: "nextjs.redirect.user-controlled-target",
    title: "Redirect target appears user-controlled",
    description: "A redirect target appears to come from request-controlled data without an obvious origin allowlist.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.74,
    confidenceReason: "Redirect call references request/search/body-style values and no allowlist signal was found.",
    reachability: isApiRoute(file.path) ? "reachable" : "unknown",
    exploitability: "medium",
    cwe: "CWE-601",
    recommendation: "Validate redirect destinations against an explicit allowlist of relative paths or trusted origins.",
    patchable: false,
    source: "rule",
  })
}

function scanServerActionRisks(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!/\.(ts|tsx|js|jsx)$/.test(file.path)) return
  const firstChunk = file.text.slice(0, 1200)
  if (!/["']use server["']/.test(firstChunk)) return

  const hasMutation =
    /\b(db|supabase|fetch)\.(create|update|delete|insert|upsert|from|query)|\bprisma\.\w+\.(create|update|delete|deleteMany|updateMany|createMany|upsert)|redirect\s*\(|revalidate(Path|Tag)\s*\(/i.test(file.text)
  const hasSensitivePath = /\/(admin|billing|users|settings|account|dashboard|actions?)\//i.test(`/${normalizePath(file.path)}/`)
  if (!hasMutation && !hasSensitivePath) return

  const authCall = hasAuthSignal(file.text)
  const auth = hasEffectiveAuthGuard(file.text)
  const validation = VALIDATION_SIGNALS.test(file.text)
  const exported = findLineMatching(file.text, /\bexport\s+(async\s+)?function\b|\bexport\s+const\s+\w+\s*=\s*async\b/)

  if (!auth) {
    add({
      kind: "vulnerability",
      severity: "high",
      category: authCall ? "missing_authorization" : "server_action_risk",
      ruleId: authCall ? "nextjs.server-action.auth-call-without-guard" : "nextjs.server-action.missing-auth",
      title: authCall ? "Server Action calls auth without enforcing access" : "Server Action performs sensitive work without an obvious auth guard",
      description: authCall
        ? "Exported Server Actions are callable endpoints. This action calls auth, but no clear deny path, role check, or ownership check is visible before sensitive work."
        : "Exported Server Actions are callable endpoints and should verify authentication and authorization inside the action before mutation or sensitive reads.",
      filePath: file.path,
      lineStart: exported?.lineNumber ?? 1,
      evidence: redactSecrets(exported?.line.trim() ?? "\"use server\""),
      confidence: 0.84,
      confidenceReason: authCall
        ? "File declares use server and performs sensitive work after an auth call, but no enforce/deny guard signal was found."
        : "File declares use server and performs mutation/sensitive work, but no auth guard signal was found.",
      reachability: "reachable",
      exploitability: "high",
      cwe: "CWE-862",
      owasp: "A01 Broken Access Control",
      recommendation: "Verify the user session, role, and ownership inside the Server Action before doing sensitive work, and return/throw before mutation when access is denied.",
      patchable: true,
      source: "rule",
    })
  }

  if (!validation && /\b(formData|FormData|input|body|searchParams)\b/i.test(file.text)) {
    add({
      kind: "vulnerability",
      severity: "medium",
      category: "server_action_risk",
      ruleId: "nextjs.server-action.missing-input-validation",
      title: "Server Action uses client input without visible schema validation",
      description: "A Server Action receives client-controlled input but no schema validation is visible in the file.",
      filePath: file.path,
      lineStart: exported?.lineNumber ?? 1,
      evidence: redactSecrets(exported?.line.trim() ?? "\"use server\""),
      confidence: 0.76,
      confidenceReason: "Server Action input names were found, but no parse/safeParse-style validation signal was present.",
      reachability: "reachable",
      exploitability: "medium",
      recommendation: "Validate Server Action inputs with Zod or equivalent before using them in mutations, redirects, model calls, or database operations.",
      patchable: true,
      source: "rule",
    })
  }
}

function scanSupabaseRisks(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const normalized = normalizePath(file.path).toLowerCase()

  if (normalized.endsWith(".sql") && normalized.includes("supabase/migrations/")) {
    const rlsDisabled = findLineMatching(file.text, /\balter\s+table\b[\s\S]{0,120}\bdisable\s+row\s+level\s+security\b/i)
    if (rlsDisabled) {
      add({
        kind: "vulnerability",
        severity: "high",
        category: "supabase_rls_risk",
        ruleId: "supabase.rls.disabled",
        title: "Supabase migration disables row level security",
        description: "A Supabase migration disables RLS on a table. Public clients can be overexposed if policies are not restored immediately.",
        filePath: file.path,
        lineStart: rlsDisabled.lineNumber,
        evidence: redactSecrets(rlsDisabled.line.trim()),
        confidence: 0.9,
        confidenceReason: "SQL migration explicitly disables row level security.",
        reachability: "reachable",
        exploitability: "high",
        cwe: "CWE-284",
        recommendation: "Keep RLS enabled on exposed tables and use least-privilege policies for anon/authenticated roles.",
        patchable: false,
        source: "rule",
      })
    }

    const securityDefiner = findLineMatching(file.text, /\bsecurity\s+definer\b/i)
    if (securityDefiner && !/\bset\s+search_path\b/i.test(file.text)) {
      add({
        kind: "hardening",
        severity: "medium",
        category: "supabase_rls_risk",
        ruleId: "supabase.function.security-definer-without-search-path",
        title: "SECURITY DEFINER function needs focused review",
        description: "SECURITY DEFINER functions can bypass caller privileges and should pin search_path and enforce authorization explicitly.",
        filePath: file.path,
        lineStart: securityDefiner.lineNumber,
        evidence: redactSecrets(securityDefiner.line.trim()),
        confidence: 0.72,
        confidenceReason: "SQL contains SECURITY DEFINER without a nearby search_path guard signal.",
        reachability: "unknown",
        exploitability: "medium",
        recommendation: "Set a safe search_path inside the function and verify the function enforces authorization before privileged operations.",
        patchable: false,
        source: "rule",
      })
    }
  }

  const clientServiceRoleHit = isClientComponent(file.text)
    ? findCodeLineMatching(file.text, /\b(supabaseAdmin|SERVICE_ROLE|SUPABASE_SERVICE_ROLE_KEY|createClient\s*\([^)]*(?:service[_-]?role|process\.env))\b/i)
    : undefined
  if (clientServiceRoleHit && !isScannerReportPresentationLine(file.path, clientServiceRoleHit.line)) {
    add({
      kind: "vulnerability",
      severity: "critical",
      category: "client_data_exposure",
      ruleId: "supabase.service-role.in-client-component",
      title: "Supabase service-role access appears in client code",
      description: "Service-role keys and admin clients must never be reachable from browser/client components.",
      filePath: file.path,
      lineStart: clientServiceRoleHit.lineNumber,
      evidence: redactSecrets(clientServiceRoleHit.line.trim()),
      confidence: 0.88,
      confidenceReason: "Client component references service-role/admin Supabase access.",
      reachability: "reachable",
      exploitability: "high",
      recommendation: "Move service-role access to server-only code and expose only narrowly scoped operations through authenticated server routes/actions.",
      patchable: true,
      source: "rule",
    })
  }
}

function scanPrismaSchemaRisks(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!file.path.endsWith(".prisma")) return
  const sensitive = findLineMatching(file.text, /\b(password|token|secret|apiKey|ssn|creditCard|stripeCustomerId)\b/i)
  if (!sensitive) return

  add({
    kind: "hardening",
    severity: "low",
    category: "client_data_exposure",
    ruleId: "prisma.schema.sensitive-fields",
    title: "Prisma schema contains sensitive user fields",
    description: "Sensitive fields in database models should be protected by DTOs, authorization checks, and explicit selection.",
    filePath: file.path,
    lineStart: sensitive.lineNumber,
    evidence: redactSecrets(sensitive.line.trim()),
    confidence: 0.7,
    confidenceReason: "Prisma schema includes sensitive-looking field names.",
    reachability: "unknown",
    exploitability: "unknown",
    recommendation: "Avoid returning full model objects to clients; use server-only data access functions and explicit safe DTOs.",
    patchable: false,
    source: "rule",
  })
}

function scanGitHubActionsRisks(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const normalized = normalizePath(file.path).toLowerCase()
  if (!normalized.startsWith(".github/workflows/") || !/\.(ya?ml)$/.test(normalized)) return
  const workflowUsesSecrets = /\bsecrets\.[A-Z0-9_]+\b/i.test(file.text)
  const workflowHasWritePermission = /^\s*(?:contents|packages|id-token|pull-requests|actions)\s*:\s*write\s*$/im.test(file.text) ||
    /^\s*permissions\s*:\s*write-all\s*$/im.test(file.text)
  const releaseLikeWorkflow = /\b(release|publish|deploy|homebrew|artifact)\b/i.test(file.text)

  const pullRequestTarget = findLineMatching(file.text, /\bpull_request_target\s*:/i)
  if (pullRequestTarget) {
    add({
      kind: "repo_posture",
      severity: "high",
      category: "repo_security_posture",
      ruleId: "github-actions.pull-request-target",
      title: "Workflow uses pull_request_target",
      description: "pull_request_target runs with base-repo privileges and is dangerous when combined with untrusted checkout or scripts.",
      filePath: file.path,
      lineStart: pullRequestTarget.lineNumber,
      evidence: redactSecrets(pullRequestTarget.line.trim()),
      confidence: 0.86,
      confidenceReason: "GitHub Actions workflow declares pull_request_target.",
      reachability: "reachable",
      exploitability: "high",
      recommendation: "Use pull_request where possible, or strictly avoid checking out and executing untrusted fork code under privileged tokens.",
      patchable: false,
      source: "rule",
    })
  }

  const writeAll = findLineMatching(file.text, /^\s*permissions\s*:\s*write-all\s*$/i)
  if (writeAll) {
    add({
      kind: "repo_posture",
      severity: "medium",
      category: "repo_security_posture",
      ruleId: "github-actions.permissions-write-all",
      title: "Workflow grants write-all permissions",
      description: "Broad workflow token permissions increase blast radius if an action or script is compromised.",
      filePath: file.path,
      lineStart: writeAll.lineNumber,
      evidence: redactSecrets(writeAll.line.trim()),
      confidence: 0.88,
      confidenceReason: "GitHub Actions workflow explicitly sets permissions: write-all.",
      reachability: "reachable",
      exploitability: "medium",
      recommendation: "Set least-privilege permissions per job, such as contents: read by default and scoped write permissions only where required.",
      patchable: false,
      source: "rule",
    })
  }

  const unpinnedActions = findUnpinnedWorkflowActions(file.text)
  if (unpinnedActions.length > 0) {
    const thirdPartyActions = unpinnedActions.filter((action) => !action.githubOwned)
    const sensitiveWorkflow = workflowUsesSecrets || workflowHasWritePermission || releaseLikeWorkflow
    const severity =
      thirdPartyActions.length > 0 && sensitiveWorkflow ? "high" :
      thirdPartyActions.length > 0 ? "medium" :
      sensitiveWorkflow ? "medium" :
      "low"
    const first = unpinnedActions[0]
    const actionSummary = unpinnedActions.map((action) => `${action.action}@${action.ref}`).join("; ")

    add({
      kind: "repo_posture",
      severity,
      category: "repo_security_posture",
      ruleId: "github-actions.unpinned-actions.grouped",
      title: "Unpinned GitHub Actions detected",
      description: thirdPartyActions.length > 0
        ? `This workflow uses ${unpinnedActions.length} action refs that are not pinned to commit SHAs, including ${thirdPartyActions.length} third-party action(s). ${sensitiveWorkflow ? "Because this workflow has release/deploy/secrets/write-permission signals, a compromised action ref has higher blast radius." : "Pinning third-party actions is the strongest control against mutable supply-chain refs."}`
        : `This workflow uses ${unpinnedActions.length} GitHub-owned action ref(s) that are not pinned to commit SHAs. This is lower risk than third-party actions, but still repo posture debt for sensitive projects.`,
      filePath: file.path,
      lineStart: first?.lineNumber,
      evidence: redactSecrets(`${unpinnedActions.length} unpinned action refs: ${actionSummary}`),
      confidence: 0.82,
      confidenceReason: `Workflow uses non-SHA action refs; ${thirdPartyActions.length} third-party, ${unpinnedActions.length - thirdPartyActions.length} GitHub-owned. Sensitive workflow signals: ${sensitiveWorkflow ? "yes" : "no"}.`,
      reachability: "reachable",
      exploitability: severity === "high" ? "medium" : "low",
      evidenceTrace: unpinnedActions.slice(0, 8).map((action) => ({
        filePath: file.path,
        lineStart: action.lineNumber,
        kind: "source" as const,
        label: action.githubOwned ? "GitHub-owned action ref" : "Third-party action ref",
        code: redactSecrets(action.line.trim()),
      })),
      recommendation: thirdPartyActions.length > 0
        ? "Pin third-party actions to reviewed commit SHAs first, then decide whether GitHub-owned actions also need SHA pinning for your compliance posture."
        : "For high-assurance workflows, pin GitHub-owned actions to reviewed commit SHAs and update them intentionally.",
      patchable: false,
      source: "rule",
    })
  }
}

function scanRemoteInstallPipeToShell(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!/\.(md|mdx|txt|sh|bash|zsh)$/i.test(file.path) && basename(file.path).toLowerCase() !== "readme") return
  const hit = findLineMatching(file.text, REMOTE_INSTALL_PIPE_TO_SHELL)
  if (!hit) return

  add({
    kind: "repo_posture",
    severity: "medium",
    category: "supply_chain_posture",
    ruleId: "supply-chain.remote-install-piped-shell",
    title: "Remote install script is piped directly to a shell",
    description:
      "The project documents a remote bootstrap command piped into bash/sh. That is convenient, but it weakens supply-chain verification for CLI and agent tooling installs.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.84,
    confidenceReason: "Documentation or shell script contains curl/wget from a remote URL piped directly to bash/sh.",
    reachability: "reachable",
    exploitability: "medium",
    recommendation: "Provide a signed release, checksum verification, package-manager install path, or a download-then-inspect workflow instead of piping remote code directly to a shell.",
    patchable: false,
    source: "rule",
  })
}

function findUnpinnedWorkflowActions(text: string) {
  return text.split(/\r?\n/).flatMap((line, index) => {
    const match = line.match(/^\s*-?\s*uses\s*:\s*([^@\s]+\/[^@\s]+)@([^\s#]+)\s*$/i)
    if (!match) return []
    const action = match[1].replace(/^["']|["']$/g, "")
    const ref = match[2].replace(/^["']|["']$/g, "")
    if (SHA_REF_RE.test(ref)) return []
    return [{ action, ref, line, lineNumber: index + 1, githubOwned: isGitHubOwnedAction(action) }]
  })
}

function scanMissingInputValidation(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!JSON_PARSE_SIGNALS.test(file.text)) return

  const hit = findLineMatching(file.text, JSON_PARSE_SIGNALS)
  const inlineValidated = /\.(?:parse|safeParse)\s*\(\s*await\s+(?:req|request)\.json\(\)\s*\)/i.test(file.text)
  if (inlineValidated) return

  const bodyVariable = findRequestJsonVariable(file.text)
  const hasValidationSignal = VALIDATION_SIGNALS.test(file.text)
  const validatesParsedBody = bodyVariable ? validatesVariable(file.text, bodyVariable) : false
  const rawBodySink = bodyVariable ? findRawRequestBodyUse(file.text, bodyVariable) : null

  if (hasValidationSignal && validatesParsedBody && !rawBodySink) return

  add({
    severity: "medium",
    category: "input_validation",
    ruleId: rawBodySink ? "nextjs.route.raw-body-used-after-validation" : "nextjs.route.request-json-without-effective-validation",
    title: rawBodySink ? "API route uses raw request body after validation" : "API route parses JSON without effective schema validation",
    description: rawBodySink
      ? "The request body is parsed and validation appears in the file, but the raw body variable is still used in a sensitive operation."
      : "The request body is parsed but no Zod/Yup/Valibot/Superstruct validation of that parsed value is visible in the route.",
    filePath: file.path,
    lineStart: rawBodySink?.lineNumber ?? hit?.lineNumber,
    evidence: redactSecrets(rawBodySink?.line.trim() ?? hit?.line.trim() ?? ""),
    confidence: rawBodySink ? 0.8 : 0.84,
    confidenceReason: rawBodySink
      ? "A request JSON variable is later passed to a sensitive operation instead of a parsed/validated value."
      : "request.json() was found without parse/safeParse of the parsed request value.",
    recommendation: rawBodySink
      ? "Use the parsed schema output, usually `const body = BodySchema.parse(await request.json())`, and do not pass the raw request body to DB/model/response sinks."
      : "Validate the request body with Zod before using it.",
    patchable: true,
    source: "rule",
  })
}

function findRequestJsonVariable(text: string) {
  return text.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+(?:req|request)\.json\(\)/)?.[1]
}

function validatesVariable(text: string, variableName: string) {
  const variable = escapeRegExp(variableName)
  return new RegExp(`\\.(?:parse|safeParse)\\s*\\(\\s*${variable}\\b`, "i").test(text)
}

function findRawRequestBodyUse(text: string, variableName: string) {
  const variable = escapeRegExp(variableName)
  return findLineMatching(
    text,
    new RegExp(`\\b(prisma|db|pool|client|connection|fetch|redirect|generateText|streamText|generateObject|streamObject|Response\\.json|NextResponse\\.json)\\b[^\\n]*\\b${variable}\\b`, "i"),
  )
}

function scanPackageScripts(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (basename(file.path) !== "package.json") return

  let parsed: { scripts?: Record<string, unknown> }
  try {
    parsed = JSON.parse(file.text) as { scripts?: Record<string, unknown> }
  } catch {
    return
  }

  for (const [scriptName, scriptValue] of Object.entries(parsed.scripts ?? {})) {
    if (!INSTALL_SCRIPT_NAMES.has(scriptName)) continue
    if (typeof scriptValue !== "string") continue
    if (!RISKY_INSTALL_SCRIPT_SIGNALS.test(scriptValue)) continue

    const hit = findLineMatching(file.text, new RegExp(`"${escapeRegExp(scriptName)}"\\s*:`))
    add({
      severity: "high",
      category: "dependency_signal",
      title: "Risky package install script detected",
      description: "Install lifecycle scripts that download or execute shell commands are high-risk supply-chain behavior in AI-generated projects.",
      filePath: file.path,
      lineStart: hit?.lineNumber,
      evidence: redactSecrets(`${scriptName}: ${scriptValue}`),
      confidence: 0.86,
      recommendation: "Remove remote bootstrap commands from install scripts, pin trusted tooling, and document any required setup step explicitly.",
      patchable: false,
      source: "rule",
    })
  }
}

function scanDangerousCode(file: ProjectFile, add: (finding: RuleFinding) => void) {
  const isRustFile = file.path.endsWith(".rs")
  if (!isRustFile && !/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) return
  const checks: { title: string; severity: Severity; description: string; find: (text: string) => { line: string; lineNumber: number } | undefined }[] = [
    { find: (text) => findCodeLineMatching(text, /\beval\s*\(/), title: "Dynamic eval call detected", severity: "high", description: "eval executes strings as code and can turn input handling bugs into remote code execution." },
    { find: (text) => findCodeLineMatching(text, /\bnew\s+Function\s*\(/), title: "Dynamic Function constructor detected", severity: "high", description: "new Function executes generated code and is unsafe for user-controlled input." },
    { find: (text) => findCodeLineMatching(text, /\bdangerouslySetInnerHTML\b/), title: "dangerouslySetInnerHTML usage detected", severity: "medium", description: "Rendering raw HTML can introduce XSS unless content is sanitized and trusted." },
    { find: findShellProcessCall, title: "Shell process call detected", severity: "high", description: "exec/spawn calls can become command injection paths when arguments are user-controlled." },
    { find: (text) => findCodeLineMatching(text, /\bfs\.writeFile(?:Sync)?\s*\([^)]*\b(req|request|body|input|params|searchParams)\b/i), title: "File write appears to use request input", severity: "high", description: "Writing files from request input can overwrite project or runtime files if not constrained." },
  ]

  for (const check of checks) {
    if (isRustFile && check.title === "Shell process call detected") continue

    const hit = check.find(file.text)
    if (!hit) continue
    if (isScannerSelfTestOrDetectorLine(file.path, hit.line)) continue
    const postureOnly = isTestOrFixturePath(file.path) || isLowRiskToolingScriptPath(file.path)
    const severity = postureOnly ? "info" : check.severity
    const kind = postureOnly ? "info" : "vulnerability"
    const category = postureOnly ? "repo_security_posture" : "dangerous_code"

    add({
      kind,
      severity,
      category,
      ruleId: `rule.${category}.${slugifyRuleTitle(check.title)}`,
      title: check.title,
      description: postureOnly
        ? `${check.description} This occurrence is in a test, fixture, or repository maintenance script, so it is tracked as low-risk inventory instead of an application vulnerability.`
        : check.description,
      filePath: file.path,
      lineStart: hit.lineNumber,
      evidence: redactSecrets(hit.line.trim()),
      confidence: postureOnly ? 0.52 : 0.8,
      confidenceReason: postureOnly
        ? "Detected in test/fixture/tooling context; useful inventory, not a confirmed reachable vulnerability."
        : "Dangerous-code sink detected in source context.",
      reachability: postureOnly ? "unknown" : "unknown",
      exploitability: postureOnly ? "low" : "unknown",
      recommendation: postureOnly
        ? "Keep this use scoped to trusted test or maintenance code. Do not expose it to user-controlled input or agent-controlled commands."
        : "Avoid dynamic code execution and sanitize all HTML/user input. If shell or file access is required, use strict allowlists and fixed paths.",
      patchable: check.title === "dangerouslySetInnerHTML usage detected",
      source: "rule",
    })
  }
}

function scanRustDangerousCode(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!file.path.endsWith(".rs")) return

  const commandHit = findLineMatching(file.text, /\b(?:std::process::)?Command::new\s*\(/)
  if (commandHit) {
    if (isMcpRustFile(normalizePath(file.path).toLowerCase(), file.text) && /\bconfig\.command\b/.test(commandHit.line)) {
      // Covered by the MCP-specific analyzer above with the right threat model.
    } else if (isAgentShellToolFile(normalizePath(file.path).toLowerCase(), file.text) && /\bCommand::new\s*\(\s*["'](?:bash|sh|cmd(?:\.exe)?)["']\s*\)/i.test(commandHit.line)) {
      // Covered by the agent-shell analyzer above; avoid a duplicate generic process finding.
    } else {
    const processRisk = classifyRustProcessLine(commandHit.line, file)
    add({
      kind: processRisk.userControlled ? "vulnerability" : "repo_posture",
      severity: processRisk.userControlled ? "high" : processRisk.dynamic ? "medium" : "info",
      category: processRisk.userControlled ? "command_injection" : "repo_security_posture",
      ruleId: processRisk.userControlled
        ? "rust.process.user-controlled-command"
        : processRisk.internalBuilder
          ? "rust.process.internal-builder-review"
          : processRisk.dynamic
          ? "rust.process.configured-command-review"
          : "rust.process.fixed-command-review",
      title: processRisk.userControlled
        ? "Rust process execution uses a user-controlled command"
        : processRisk.internalBuilder
          ? "Self-dev build spawns repo-local build command"
          : processRisk.dynamic
          ? "Rust external process command comes from configuration"
          : "Rust fixed process execution should be reviewed",
      description: processRisk.userControlled
        ? "A Rust process command or argument appears to be controlled by a variable, which can become command injection if it reaches user input."
        : processRisk.internalBuilder
          ? "A self-development/build helper starts a command selected by an internal builder. That is an execution surface, but no direct user-controlled command source was proven."
          : processRisk.dynamic
          ? "A Rust process command is selected through a variable such as a configured binary path. That is usually CLI/tooling behavior, but it should be allowlisted and documented."
        : "This Rust code starts a fixed operating-system process. That can be expected in CLI tools, but should stay out of web request paths and keep arguments fixed or allowlisted.",
      filePath: file.path,
      lineStart: commandHit.lineNumber,
      evidence: redactSecrets(commandHit.line.trim()),
      confidence: processRisk.userControlled ? 0.82 : processRisk.dynamic ? 0.68 : 0.58,
      confidenceReason: processRisk.userControlled
        ? "Command::new or nearby arguments use explicit user/input/request-style names."
        : processRisk.internalBuilder
          ? "Command::new uses command.program, but the file references an internal selfdev build command builder rather than request/model/user input."
        : processRisk.dynamic
          ? "Command::new uses a non-literal command, but no direct user/request source is visible on this line."
          : "Command::new uses a literal command on the matched line, so this is posture review rather than a confirmed vulnerability.",
      reachability: "unknown",
      exploitability: processRisk.userControlled ? "high" : processRisk.dynamic ? "medium" : "low",
      cwe: processRisk.userControlled ? "CWE-78" : undefined,
      recommendation: processRisk.userControlled
        ? "Use fixed command names, validate arguments with an allowlist, and never pass request/user-controlled strings into process execution."
        : processRisk.internalBuilder
          ? "Keep build command choices fixed, document when a repo-local shell wrapper is honored, avoid inheriting secrets unnecessarily, and require explicit user approval before self-modifying build flows."
          : processRisk.dynamic
          ? "Resolve configured binaries from trusted config only, validate them against an allowlist, avoid shells, and strip secrets from child environments where possible."
        : "Keep command names fixed, avoid shell invocation, and document why process execution is required.",
      patchable: false,
      source: "rule",
    })
    }
  }

  const unsafeHit = findLineMatching(file.text, /\bunsafe\s*\{/)
  if (!unsafeHit) return

  const unsafeWindow = surroundingLines(file.text, unsafeHit.lineNumber, 4)
  const riskyUnsafe = /\b(from_raw_parts|from_raw_parts_mut|transmute|assume_init|copy_nonoverlapping|read_unaligned|write_unaligned|CStr::from_ptr|CString::from_raw|Box::from_raw|Vec::from_raw_parts|slice::from_raw_parts|ptr::read|ptr::write|malloc|free|realloc)\b|as\s+\*(?:const|mut)\b/i.test(unsafeWindow)

  add({
    kind: riskyUnsafe ? "vulnerability" : "info",
    severity: riskyUnsafe ? "medium" : "info",
    category: riskyUnsafe ? "dangerous_code" : "repo_security_posture",
    ruleId: riskyUnsafe ? "rust.unsafe.memory-risk" : "rust.unsafe.inventory",
    title: riskyUnsafe ? "Risky Rust unsafe memory operation detected" : "Rust unsafe block inventory",
    description: riskyUnsafe
      ? "This unsafe block includes pointer, raw allocation, transmute, or unchecked initialization patterns that deserve focused memory-safety review."
      : "This file contains an unsafe block. Not every unsafe block is a vulnerability; this is tracked as review inventory unless memory-unsafe primitives are visible.",
    filePath: file.path,
    lineStart: unsafeHit.lineNumber,
    evidence: redactSecrets(unsafeHit.line.trim()),
    confidence: riskyUnsafe ? 0.78 : 0.62,
    confidenceReason: riskyUnsafe
      ? "Unsafe block contains high-risk raw memory primitives."
      : "Unsafe block was found, but no high-risk raw memory primitive was detected nearby.",
    reachability: "unknown",
    exploitability: riskyUnsafe ? "medium" : "low",
    recommendation: riskyUnsafe
      ? "Minimize unsafe scope, document invariants, add boundary tests, and wrap raw memory operations in a small audited safe API."
      : "Keep the unsafe block small, document the invariant, and review it during release security checks.",
    patchable: false,
    source: "rule",
  })
}

function classifyRustProcessLine(line: string, file: ProjectFile) {
  const commandArg = line.match(/\bCommand::new\s*\(\s*([^)]*)\)/)?.[1]?.trim() ?? ""
  const dynamic = Boolean(commandArg && !/^["']/.test(commandArg))
  const internalBuilder = dynamic && isInternalRustCommandBuilder(commandArg, file)
  const userControlled =
    !internalBuilder &&
    ((dynamic && /(user|input|request|body|param|untrusted|cmd_str)/i.test(commandArg)) ||
    /\.arg\s*\(\s*(?:user|input|request|body|param|cmd_str|command)[A-Za-z0-9_]*\b/i.test(line)
    )
  return { dynamic, internalBuilder, userControlled }
}

function isInternalRustCommandBuilder(commandArg: string, file: ProjectFile) {
  const normalized = normalizePath(file.path).toLowerCase()
  if (!/command\.program|build_command|selfdev_build_command/i.test(`${commandArg}\n${file.text}`)) return false
  if (/user|input|request|body|param|untrusted|cmd_str/i.test(commandArg)) return false
  return normalized.includes("/selfdev/") || /\bselfdev_build_command\b|\bbuild_command\s*\(/i.test(file.text)
}

function isAgentShellToolFile(normalizedPath: string, text: string) {
  if (/\/tool\/bash\.rs$|^src\/tool\/bash\.rs$|\/tools\/bash\.rs$/i.test(normalizedPath)) return true
  return /\bBashToolInput\b|\bbash\s+tool\b|\btool_name\s*=\s*["']bash["']/i.test(text)
}

function isMcpRustFile(normalizedPath: string, text: string) {
  return normalizedPath.includes("/mcp/") || normalizedPath.startsWith("src/mcp/") || /\bMcp(Client|Config|Server)\b|\bMCP\b/.test(text)
}

type LineHit = NonNullable<ReturnType<typeof findLineMatching>>

function traceFromHit(filePath: string, kind: "source" | "propagator" | "sanitizer" | "guard" | "sink", label: string, hit: LineHit | null | undefined) {
  if (!hit) return null
  return {
    filePath,
    lineStart: hit.lineNumber,
    kind,
    label,
    code: redactSecrets(hit.line.trim()),
  }
}

function compactTrace(steps: Array<ReturnType<typeof traceFromHit>>) {
  return steps.filter((step): step is NonNullable<typeof step> => Boolean(step))
}

const AGENT_SHELL_MITIGATION_PATTERNS = [
  { key: "approval", label: "approval policy", pattern: /(approval|approve|confirm|confirmation|consent|policy)/i },
  { key: "sandbox", label: "sandboxing", pattern: /\b(sandbox|container|jail|isolate|restricted|denylist|allowlist)\b/i },
  { key: "timeout", label: "timeout", pattern: /\b(timeout|deadline|kill_after|DEFAULT_TIMEOUT|Duration::from)\b/i },
  { key: "env", label: "environment isolation", pattern: /\b(env_clear|clear_env|strip.*env|env_allowlist|allowed_env|redact.*env)\b/i },
  { key: "audit", label: "audit logging", pattern: /\b(audit|log_event|trace|telemetry|record)\b/i },
] as const

function detectAgentShellMitigations(text: string) {
  const detected = []
  const missing = []

  for (const item of AGENT_SHELL_MITIGATION_PATTERNS) {
    const hit = findLineMatching(text, item.pattern)
    if (hit) detected.push({ ...item, line: hit.line, lineNumber: hit.lineNumber })
    else missing.push({ key: item.key, label: item.label })
  }

  return { detected, missing }
}

function isGitHubOwnedAction(action: string) {
  const [owner] = action.toLowerCase().split("/")
  return owner === "actions" || owner === "github"
}

function surroundingLines(text: string, lineNumber: number, radius: number) {
  const lines = text.split(/\r?\n/)
  const start = Math.max(0, lineNumber - 1 - radius)
  const end = Math.min(lines.length, lineNumber + radius)
  return lines.slice(start, end).join("\n")
}

function scanSensitiveClientData(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isClientComponent(file.text)) return

  const hit = findSensitiveClientDataLeak(file.text)
  if (!hit) return

  add({
    severity: "medium",
    category: "client_data_exposure",
    title: "Sensitive-looking data appears in a client component",
    description: "This client component references sensitive-looking data fields that may end up in browser JavaScript.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.73,
    recommendation: "Move sensitive data fetching to server components or protected API routes, and avoid shipping secrets or PII in client bundles.",
    patchable: false,
    source: "rule",
  })
}

function findSensitiveClientDataLeak(text: string) {
  const lines = text.split(/\r?\n/)
  for (const [index, line] of lines.entries()) {
    if (isSensitiveClientDataLeakLine(line)) return { line, lineNumber: index + 1 }
  }
  return null
}

function isSensitiveClientDataLeakLine(line: string) {
  if (!CLIENT_SENSITIVE_NAMES.test(line)) return false
  if (isCommentOnlyLine(line)) return false

  const trimmed = line.trim()
  if (!trimmed) return false
  if (/\btype\s*=\s*["']password["']/i.test(trimmed)) return false
  if (/\b(useState|useForm|register|htmlFor|placeholder|aria-label|label)\b/i.test(trimmed) && !hasNonEmptySensitiveLiteral(trimmed)) {
    return false
  }
  if (/^<[^>]+>/.test(trimmed) && !hasSensitiveObjectLiteral(trimmed) && !hasSensitiveEnvRead(trimmed)) return false

  return hasSensitiveEnvRead(trimmed) || hasSensitiveObjectLiteral(trimmed) || hasNonEmptySensitiveLiteral(trimmed)
}

function hasSensitiveEnvRead(line: string) {
  return /\b(process\.env|import\.meta\.env|Deno\.env)\.?[A-Z0-9_]*(SECRET|TOKEN|PRIVATE|API_KEY|DATABASE_URL|SERVICE_ROLE)[A-Z0-9_]*/i.test(line)
}

function hasSensitiveObjectLiteral(line: string) {
  const match = line.match(
    /\b(password|token|apiKey|api_key|secret|ssn|creditCard|credit_card|customerEmail)\b\s*:\s*["'`]([^"'`]+)["'`]/i,
  )
  if (!match) return false
  return isConcreteClientSensitiveValue(match[2])
}

function hasNonEmptySensitiveLiteral(line: string) {
  const directAssignment = line.match(
    /\b(password|token|apiKey|api_key|secret|ssn|creditCard|credit_card|customerEmail)\b\s*=\s*["'`]([^"'`]+)["'`]/i,
  )
  if (directAssignment && isConcreteClientSensitiveValue(directAssignment[2])) return true

  const stateInitializer = line.match(
    /\b(password|token|apiKey|api_key|secret|ssn|creditCard|credit_card|customerEmail)\b[\s\S]{0,80}\buseState\s*\(\s*["'`]([^"'`]+)["'`]/i,
  )
  return Boolean(stateInitializer && isConcreteClientSensitiveValue(stateInitializer[2]))
}

function isConcreteClientSensitiveValue(value: string) {
  const trimmed = value.trim()
  if (trimmed.length < 3) return false
  if (isObviousPlaceholder(trimmed)) return false
  if (/^(true|false|null|undefined)$/i.test(trimmed)) return false
  return true
}

function scanVercelHardening(files: ProjectFile[], signals: ProjectSignals, add: (finding: RuleFinding) => void) {
  if (!signals.isNextApp) return

  const anchor = files.find((file) => basename(file.path) === "package.json") ?? files[0]
  if (!anchor) return

  if (!signals.hasVercelAnalytics) {
    addHardeningFinding(add, anchor.path, "Vercel Web Analytics not detected", "Add Vercel Web Analytics to observe real production traffic and route usage.", "low")
  }

  if (!signals.hasSpeedInsights) {
    addHardeningFinding(add, anchor.path, "Speed Insights not detected", "Add Speed Insights to monitor performance regressions after AI-generated changes.", "info")
  }

  if ((signals.hasAiSdk || signals.hasOpenAiSdk || signals.hasAnthropicSdk) && !signals.hasAiGateway) {
    addHardeningFinding(add, anchor.path, "AI Gateway usage not detected", "Route AI calls through AI Gateway or an equivalent control plane for spend controls, observability, and provider failover.", "low")
  }

  if (signals.hasSignupContactCheckout && !signals.hasBotProtection) {
    addHardeningFinding(add, anchor.path, "Bot protection not detected on abuse-prone flows", "Signup, contact, or checkout routes should include BotID, Turnstile, reCAPTCHA, or equivalent abuse protection.", "low")
  }
}

function addHardeningFinding(
  add: (finding: RuleFinding) => void,
  filePath: string,
  title: string,
  recommendation: string,
  severity: Severity,
) {
  add({
    severity,
    category: "vercel_hardening",
    title,
    description: "Production-readiness hardening recommendation for a Next.js app.",
    filePath,
    confidence: 0.68,
    recommendation,
    patchable: false,
    source: "rule",
  })
}

export function isApiRoute(path: string) {
  const normalized = normalizePath(path)
  return (
    /^app\/api\/.*\/route\.(ts|tsx|js|jsx|mjs|cjs)$/.test(normalized) ||
    /^pages\/api\/.*\.(ts|tsx|js|jsx|mjs|cjs)$/.test(normalized)
  )
}

export function isAiEndpoint(text: string) {
  return AI_ENDPOINT_SIGNALS.test(text) || AI_IMPORT_SIGNALS.test(text)
}

export function isClientComponent(text: string) {
  const firstChunk = text.slice(0, 800)
  return /["']use client["']/.test(firstChunk)
}

export function redactSecrets(input: string) {
  return input
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "-----BEGIN PRIVATE KEY-----...redacted")
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b/g, (value) => `${value.startsWith("sk-proj-") ? "sk-proj" : "sk"}-...redacted`)
    .replace(/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "sk-ant-...redacted")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b/g, (value) => `${value.slice(0, value.indexOf("_", 3) + 1)}...redacted`)
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b/g, (value) => `${value.slice(0, 4)}...redacted`)
    .replace(/\bgithub_pat_[A-Za-z0-9_]{12,}\b/g, "github_pat_...redacted")
    .replace(/\bvercel_[A-Za-z0-9]{12,}\b/gi, "vercel_...redacted")
    .replace(/\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b/g, "eyJ...redacted")
    .replace(
      /((?:NEXT_PUBLIC_)?[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE|API_KEY|DATABASE_URL|SERVICE_ROLE)[A-Z0-9_]*\s*[:=]\s*['"]?)([^'"\s]+)/gi,
      "$1...redacted",
    )
}

function hasSecretLikeContent(file: ProjectFile) {
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0
    for (const match of file.text.matchAll(pattern.regex)) {
      const { line } = lineAtIndex(file.text, match.index ?? 0)
      if (!isObviousPlaceholder(line) && !isExampleSecretPlaceholder(file.path, line)) return true
    }
  }

  return file.text.split(/\r?\n/).some((line) => GENERIC_SECRET_NAMES.test(line) && lineHasConcreteSecretValue(file.path, line))
}

function hasAuthSignal(text: string) {
  if (AUTH_SIGNALS.test(text)) return true
  if (COOKIES_SESSION_SIGNAL.test(text) && SESSION_OR_TOKEN_SIGNAL.test(text)) return true
  if (HEADERS_TOKEN_SIGNAL.test(text) && SESSION_OR_TOKEN_SIGNAL.test(text)) return true
  return false
}

function hasEffectiveAuthGuard(text: string) {
  if (STRONG_AUTH_GUARD_SIGNALS.test(text)) return true
  if (!hasAuthSignal(text)) return false
  if (/\b(verifyToken|jwtVerify|validateSession)\s*\(/i.test(text) && AUTH_DENY_SIGNALS.test(text)) return true
  if ((COOKIES_SESSION_SIGNAL.test(text) || HEADERS_TOKEN_SIGNAL.test(text)) && SESSION_OR_TOKEN_SIGNAL.test(text) && AUTH_DENY_SIGNALS.test(text)) {
    return true
  }
  return AUTH_CONDITION_SIGNALS.test(text) && AUTH_DENY_SIGNALS.test(text)
}

function extractAssignedValue(line: string) {
  const secretAssignment = extractSecretAssignment(line)
  if (secretAssignment) return secretAssignment.value

  const match = line.match(/(?:^|[\s{[,])["']?[A-Za-z0-9_.-]+["']?\s*[:=]\s*['"`]?([^'"`\s#,)]+)/)
  return match?.[1] ?? ""
}

function extractSecretAssignment(line: string) {
  const match = line.match(
    /(?:^|[\s{[,])(?:export\s+)?["']?([A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|DEEPSEEK_API_KEY|VERCEL_TOKEN|GITHUB_TOKEN|STRIPE_SECRET_KEY)[A-Z0-9_]*)["']?\s*[:=]\s*(['"`]?)([^'"`\s#,)]+)/i,
  )
  if (!match) return null
  return { name: match[1], value: match[3], quoted: Boolean(match[2]) }
}

function extractGenericSecretAssignment(line: string) {
  const match = line.match(
    /(?:^|[\s{[,])(?:export\s+)?(?:const|let|var)?\s*["']?([A-Za-z_$][\w$]*|[A-Z0-9_]{3,})["']?\s*[:=]\s*(['"`])([^'"`]{20,})\2/i,
  )
  if (!match) return null
  return { name: match[1], value: match[3] }
}

function isSecretishIdentifier(name: string) {
  const normalized = name.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase()
  return /(secret|token|private|credential|password|passwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|service[_-]?role)/i.test(normalized)
}

function lineHasConcreteSecretValue(path: string, line: string) {
  if (isCommentOnlyLine(line)) return false
  if (isEnvVarReferenceLine(line)) return false
  if (isGitHubActionsSecretReference(line)) return false
  if (isSecretDetectorPatternLine(line)) return false
  if (isTestSecretFixtureLine(path, line)) return false
  if (isObviousPlaceholder(line) || isExampleSecretPlaceholder(path, line)) return false
  if (isDocumentationSecretExample(path, line)) return false

  const assignment = extractSecretAssignment(line)
  if (!assignment) return false
  const assigned = assignment.value
  if (assigned.length < 6) return false
  if (isSecretReferenceValue(assigned)) return false
  if (isLocalOrExampleAssignedValue(assigned)) return false
  if (/\b(process\.env|import\.meta\.env|Deno\.env|os\.environ|env\.)\b/i.test(assigned)) return false
  if (/^[A-Z0-9_]+$/.test(assigned) && !isEnvLike(path)) return false

  const highConfidenceValue = hasHighConfidenceSecretShape(assigned)
  const envStyleName = /^[A-Z0-9_]+$/.test(assignment.name)
  const namedSecretLiteral = envStyleName && (assignment.quoted || isEnvLike(path)) && assigned.length >= 8
  if (!highConfidenceValue && !namedSecretLiteral) return false
  return true
}

function shouldIgnoreSecretPatternMatch(path: string, line: string) {
  if (isObviousPlaceholder(line) || isExampleSecretPlaceholder(path, line)) return true
  if (isDocumentationSecretExample(path, line)) return true
  if (isEnvVarReferenceLine(line)) return true
  if (isGitHubActionsSecretReference(line)) return true
  if (isSecretDetectorPatternLine(line)) return true
  if (isScannerSelfTestOrDetectorLine(path, line)) return true
  if (isTestSecretFixtureLine(path, line)) return true
  return false
}

function isEnvVarReferenceLine(line: string) {
  return /\b(?:std::env::var|env::var|Deno\.env\.get|process\.env\.|import\.meta\.env\.|os\.environ(?:\.get)?|System\.getenv)\s*(?:\(|\[|\.)/i.test(line)
}

function isGitHubActionsSecretReference(line: string) {
  return /\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}/i.test(line) || /\bsecrets\.[A-Z0-9_]+\b/i.test(line)
}

function isSecretReferenceValue(value: string) {
  const normalized = value.trim().replace(/^['"`]|['"`]$/g, "")
  return (
    /^\$\{\{?\s*(?:secrets|env|inputs|vars|github)\.[A-Z0-9_.-]+\s*\}?\}?$/i.test(normalized) ||
    /^\$\{[A-Z0-9_]+\}$/i.test(normalized) ||
    /^%[A-Z0-9_]+%$/i.test(normalized)
  )
}

function isSecretDetectorPatternLine(line: string) {
  if (!/\b(R?egex::new|new\s+RegExp|compile_static_regexes|redact(?:Secrets|_secrets)?|secret[_-]?pattern|patterns?\s*=|assert!\s*\(|expect\s*\(|contains\s*\()/i.test(line)) {
    return false
  }
  return /(?:\\b|\\w|\[A-Z|A-Za-z|\{\d|sk-\[|ghp_\[|github_pat_)/i.test(line) || /\b(redacted|redaction|contains)\b/i.test(line)
}

function isScannerSelfTestOrDetectorLine(path: string, line: string) {
  const normalized = normalizePath(path).toLowerCase()
  if (normalized === "scripts/scanner-smoke.ts" || normalized.endsWith("/scanner-smoke.ts")) {
    return /\b(assert|fixture|mock|redacted|fake|demo|sample|placeholder|NEXT_PUBLIC_|paymentApiSecret|sk-|ghp_|github_pat_)\b/i.test(line)
  }

  const scannerDetectorPath =
    normalized.startsWith("lib/scanner/") ||
    normalized.startsWith("src/scanner/") ||
    normalized.includes("/scanner/") ||
    normalized === "lib/ai/reviewproject.ts" ||
    /(^|\/)(rules?|detectors?|analyzers?|reviewproject)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(normalized)
  if (!scannerDetectorPath) return false

  if (/(NEXT_PUBLIC_[A-Z0-9_]+|SECRET_PATTERNS|DANGEROUS_|SIGNAL|RULE|HARNESS|objective|evidenceRequired|ruleId|title)/.test(line)) {
    return true
  }
  if (/(\\b|\\s|\\(|\\)|\(\?:|\[A-Z|A-Za-z)/.test(line) && /\b(dangerouslySetInnerHTML|eval|exec|spawn|toolName|request|req|Set-Cookie|sameSite|httpOnly)\b/i.test(line)) {
    return true
  }
  if (/\.test\s*\(/.test(line) && /\b(dangerouslySetInnerHTML|eval|exec|spawn|toolName|request|req|Set-Cookie|sameSite|httpOnly|cookies\(\))\b/i.test(line)) {
    return true
  }
  return isSecretDetectorPatternLine(line)
}

function isScannerReportPresentationLine(path: string, line: string) {
  const normalized = normalizePath(path).toLowerCase()
  if (!/components\/scan\/scanresultsclient\.(tsx|jsx|ts|js)$/.test(normalized)) return false
  if (!/(NEXT_PUBLIC_|service-role|service_role|\bsecret\b|\btoken\b|api[_-]?key|database url|DATABASE_URL)/i.test(line)) return false
  return /(return\s+["'`]|\.join\(|templatePatchForFinding|finding\.category|finding\.description|\[\s*$|["'`][,+]?\s*$)/i.test(line)
}

function isTestSecretFixtureLine(path: string, line: string) {
  if (!isTestOrFixturePath(path)) return false
  if (!/\bsk_live_|-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line)) return true
  if (isObviousPlaceholder(line)) return true
  if (/\b(assert|expect|fixture|snapshot|case|redact|from-env|env-ref|mock|legacy)\b/i.test(line)) return true
  const assigned = extractAssignedValue(line)
  if (!assigned) return true
  return !hasHighConfidenceSecretShape(assigned) || /\b(test|fake|demo|sample|redacted|fixture|mock|from-env|env-ref)\b/i.test(assigned)
}

export function isDocumentationSecretExample(path: string, line: string) {
  if (!isDocumentationPath(path)) return false
  if (!GENERIC_SECRET_NAMES.test(line)) return false

  const assigned = extractAssignedValue(line)
  if (!assigned) return true
  if (isObviousPlaceholder(line)) return true
  if (isLocalOrExampleAssignedValue(assigned)) return true
  if (hasHighConfidenceSecretShape(assigned)) return false

  return true
}

function isObviousPlaceholder(line: string) {
  return /\b(your[_-]?|example|placeholder|changeme|change_me|replace_me|todo|dummy|null|undefined|redacted|demo|fake|sample|fixture|mock|legacy|from[_-]?env|env[_-]?ref|not[_-]?real|test[_-]?key|xxxx+|local[_-]?only)\b/i.test(line)
}

function isExampleSecretPlaceholder(path: string, line: string) {
  if (!isExampleOrTemplatePath(path) && !isEnvLike(path)) return false

  const assigned = extractAssignedValue(line)
  if (!assigned) return true
  if (/^<[^>]+>$/.test(assigned)) return true
  if (/^\$\{?[A-Z0-9_]+\}?$/i.test(assigned)) return true
  if (/^\*+$/.test(assigned) || /^x+$/i.test(assigned) || /^\.+$/.test(assigned)) return true
  if (/^(sk|sk-ant|ghp|github_pat|vercel|sk_live|sk_test)[_-]?(demo|fake|redacted|example|placeholder|test)/i.test(assigned)) {
    return true
  }
  return isObviousPlaceholder(line)
}

function isExampleOrTemplatePath(path: string) {
  const normalized = normalizePath(path).toLowerCase()
  const name = basename(path).toLowerCase()
  return (
    name === ".env.example" ||
    name === ".env.sample" ||
    name === ".env.template" ||
    isTestOrFixturePath(path) ||
    normalized.includes("/examples/") ||
    normalized.includes("/fixtures/") ||
    normalized.includes("/docs/")
  )
}

function isTestOrFixturePath(path: string) {
  const normalized = normalizePath(path).toLowerCase()
  const name = basename(path).toLowerCase()
  return (
    normalized.startsWith("test/") ||
    normalized.startsWith("tests/") ||
    normalized.startsWith("fixtures/") ||
    normalized.startsWith("__tests__/") ||
    normalized.startsWith("__fixtures__/") ||
    normalized.includes("/fixtures/") ||
    normalized.includes("/fixture/") ||
    normalized.includes("/snapshots/") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/tests/") ||
    normalized.includes("_tests/") ||
    /(?:^|[._-])(test|tests|spec)\.(?:ts|tsx|js|jsx|rs|py|go|java|rb|php)$/.test(name) ||
    /(?:_test|_tests|_spec)\.(?:rs|py|go|java|rb|php)$/.test(name)
  )
}

function isLowRiskToolingScriptPath(path: string) {
  const normalized = normalizePath(path).toLowerCase()
  return (
    normalized.startsWith(".github/scripts/") ||
    normalized.startsWith("scripts/") ||
    normalized.includes("/scripts/") ||
    normalized.includes("/test-utils/") ||
    normalized.startsWith(".gemini/skills/")
  )
}

function isDocumentationPath(path: string) {
  const normalized = normalizePath(path).toLowerCase()
  const name = basename(path).toLowerCase()
  return (
    name === "readme" ||
    name.startsWith("readme.") ||
    normalized.endsWith(".md") ||
    normalized.endsWith(".mdx") ||
    normalized.endsWith(".txt") ||
    normalized.includes("/docs/")
  )
}

function isLocalOrExampleAssignedValue(value: string) {
  const normalized = value.trim().replace(/^`|`$/g, "")
  if (!normalized) return true
  if (/^<[^>]+>$/.test(normalized)) return true
  if (/^\$\{?[A-Z0-9_]+\}?$/i.test(normalized)) return true
  if (/^\*+$/.test(normalized) || /^x+$/i.test(normalized) || /^\.+$/.test(normalized)) return true
  if (/\b(username|user|password|pass|passwd|dbname|database_name|host|hostname|project|tenant|your-|your_|example|sample|demo|fake|placeholder|redacted)\b/i.test(normalized)) {
    return true
  }

  try {
    const parsed = new URL(normalized)
    const host = parsed.hostname.toLowerCase()
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host === "::1" ||
      host === "example.com" ||
      host.endsWith(".example.com") ||
      host.endsWith(".local")
    ) {
      return true
    }
    if (isObviousPlaceholder(`${parsed.username} ${parsed.password} ${parsed.pathname}`)) return true
  } catch {
    // Non-URL values are handled by placeholder and high-confidence shape checks.
  }

  return false
}

function hasHighConfidenceSecretShape(value: string) {
  const normalized = value.trim().replace(/^`|`$/g, "")

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0
    if (pattern.regex.test(normalized)) return true
  }

  if (looksLikeRealDatabaseUrl(normalized)) return true
  return looksLikeHighEntropyToken(normalized)
}

function looksLikeRealDatabaseUrl(value: string) {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return false
  }

  if (!/^(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):$/.test(parsed.protocol)) return false
  if (isLocalOrExampleAssignedValue(value)) return false
  if (!parsed.password || parsed.password.length < 8) return false
  if (isObviousPlaceholder(`${parsed.username} ${parsed.password} ${parsed.pathname}`)) return false
  return true
}

function looksLikeHighEntropyToken(value: string) {
  const normalized = value.trim().replace(/^`|`$/g, "")
  if (normalized.length < 32 || normalized.length > 512) return false
  if (/^https?:\/\//i.test(normalized)) return false
  if (isObviousPlaceholder(normalized)) return false

  const hasLower = /[a-z]/.test(normalized)
  const hasUpper = /[A-Z]/.test(normalized)
  const hasDigit = /\d/.test(normalized)
  const hasSymbol = /[-_./+=]/.test(normalized)
  return [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length >= 3
}

function shannonEntropy(value: string) {
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

function isEnvLike(path: string) {
  const name = basename(path).toLowerCase()
  return name === ".env" || name.startsWith(".env.")
}

function isCommentOnlyLine(line: string) {
  return /^\s*(#|\/\/|\/\*)/.test(line)
}

function firstNonEmptyLine(text: string) {
  return text.split(/\r?\n/).find((line) => line.trim().length > 0)?.trim()
}

function firstHandlerLine(text: string) {
  return findLineMatching(text, /\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|NextResponse\.json|Response\.json/)?.lineNumber ?? 1
}

function findLineMatching(text: string, regex: RegExp) {
  const flags = regex.flags.includes("i") ? "i" : ""
  const lineRegex = new RegExp(regex.source, flags)
  const lines = text.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    if (lineRegex.test(lines[index])) return { line: lines[index], lineNumber: index + 1 }
  }
  return undefined
}

function findCodeLineMatching(text: string, regex: RegExp) {
  const flags = regex.flags.includes("i") ? "i" : ""
  const lineRegex = new RegExp(regex.source, flags)
  const lines = text.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (isCommentOnlyLine(line)) continue
    if (lineRegex.test(stripInlineComment(line))) return { line, lineNumber: index + 1 }
  }
  return undefined
}

function findShellProcessCall(text: string) {
  return findCodeLineMatching(
    text,
    /\bchild_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|(?:^|[^\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/,
  )
}

function stripInlineComment(line: string) {
  const commentIndex = line.indexOf("//")
  return commentIndex >= 0 ? line.slice(0, commentIndex) : line
}

function slugifyRuleTitle(title: string) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "")
}

function lineAtIndex(text: string, index: number) {
  const before = text.slice(0, index)
  const lineNumber = before.split(/\r?\n/).length
  const line = text.split(/\r?\n/)[lineNumber - 1] ?? ""
  return { line, lineNumber }
}

function basename(path: string) {
  return normalizePath(path).split("/").pop() ?? path
}

function normalizePath(path: string) {
  return path.replaceAll("\\", "/").replace(/^\/+/, "")
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}
