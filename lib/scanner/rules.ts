import type { ProjectFile, ScanFinding, Severity } from "./types"

export type RuleFinding = Omit<ScanFinding, "id">

const ENV_FILE_NAMES = new Set([".env", ".env.local", ".env.production", ".env.development"])

const SENSITIVE_API_SEGMENTS = /\/(admin|internal|billing|users|secrets)\//i
const AUTH_SIGNALS =
  /\b(auth\(|getServerSession|currentUser|clerkClient|verifyToken|getSession|requireAuth|withAuth|middleware|validateSession|session\s*[:=]|jwtVerify)\b/i
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
    scanDangerousNextPublic(file, add)
    scanAdminRouteWithoutAuth(file, add)
    scanAiEndpointWithoutGuard(file, add)
    scanAiToolCallingWithoutBounds(file, add)
    scanUnsafeToolCalling(file, add)
    scanMissingInputValidation(file, add)
    scanWebhookWithoutSignature(file, add)
    scanPermissiveCors(file, add)
    scanCookieHardening(file, add)
    scanUnsafeDatabaseQuery(file, add)
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
      if (isObviousPlaceholder(line) || isExampleSecretPlaceholder(file.path, line)) continue

      add({
        severity: "critical",
        category: "secret_exposure",
        title: `${pattern.name} appears to be exposed`,
        description: `A value matching ${pattern.name} was found in source-controlled project files.`,
        filePath: file.path,
        lineStart: lineNumber,
        evidence: redactSecrets(line.trim()),
        confidence: pattern.name === "JWT-like token" ? 0.78 : 0.94,
        recommendation: "Revoke and rotate this credential, remove it from the repository, and read it only from server-side environment variables.",
        patchable: true,
        source: "rule",
      })
    }
  }

  file.text.split(/\r?\n/).forEach((line, index) => {
    if (!GENERIC_SECRET_NAMES.test(line)) return
    if (!/[=:]/.test(line)) return
    if (!lineHasConcreteSecretValue(file.path, line)) return

    add({
      severity: "critical",
      category: "secret_exposure",
      title: "High-risk secret name with assigned value",
      description: "A high-risk secret variable name appears with a committed value.",
      filePath: file.path,
      lineStart: index + 1,
      evidence: redactSecrets(line.trim()),
      confidence: 0.82,
      recommendation: "Move the value to a server-only environment variable, rotate it if it was real, and commit only placeholders.",
      patchable: true,
      source: "rule",
    })
  })
}

function scanDangerousNextPublic(file: ProjectFile, add: (finding: RuleFinding) => void) {
  file.text.split(/\r?\n/).forEach((line, index) => {
    if (isCommentOnlyLine(line)) return

    const matches = line.match(/\bNEXT_PUBLIC_[A-Z0-9_]+\b/g)
    if (!matches) return

    for (const name of matches) {
      const exactDanger = DANGEROUS_NEXT_PUBLIC_NAMES.includes(name)
      const containsDanger = /SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL/.test(name)
      const tokenLike = /TOKEN/.test(name)
      if (!exactDanger && !containsDanger && !tokenLike) continue
      const examplePlaceholder = isExampleSecretPlaceholder(file.path, line)

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

function scanAdminRouteWithoutAuth(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!SENSITIVE_API_SEGMENTS.test(`/${normalizePath(file.path)}/`)) return
  if (hasAuthSignal(file.text)) return

  add({
    severity: "high",
    category: "missing_auth",
    title: "Sensitive API route lacks an obvious auth guard",
    description: "This admin/internal-style API route does not show an authentication or authorization check before handling data.",
    filePath: file.path,
    lineStart: firstHandlerLine(file.text),
    evidence: redactSecrets(findLineMatching(file.text, /\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|NextResponse\.json|Response\.json/)?.line ?? ""),
    confidence: 0.82,
    recommendation: "Add a server-side authentication/authorization guard before returning data or performing mutations.",
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
    severity: "high",
    category: "input_validation",
    title: "Unsafe database query construction detected",
    description: "This code uses an unsafe raw query helper or appears to interpolate request-controlled data into a SQL query.",
    filePath: file.path,
    lineStart: hit.lineNumber,
    evidence: redactSecrets(hit.line.trim()),
    confidence: 0.82,
    recommendation: "Use parameterized queries or safe ORM methods, and validate request-controlled inputs before they reach the database layer.",
    patchable: false,
    source: "rule",
  })
}

function scanMissingInputValidation(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!isApiRoute(file.path)) return
  if (!JSON_PARSE_SIGNALS.test(file.text)) return
  if (VALIDATION_SIGNALS.test(file.text)) return

  const hit = findLineMatching(file.text, JSON_PARSE_SIGNALS)
  add({
    severity: "medium",
    category: "input_validation",
    title: "API route parses JSON without schema validation",
    description: "The request body is parsed but no Zod/Yup/Valibot/Superstruct validation is visible in the route.",
    filePath: file.path,
    lineStart: hit?.lineNumber,
    evidence: redactSecrets(hit?.line.trim() ?? ""),
    confidence: 0.84,
    recommendation: "Validate the request body with Zod before using it.",
    patchable: true,
    source: "rule",
  })
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
  const checks: { pattern: RegExp; title: string; severity: Severity; description: string }[] = [
    { pattern: /\beval\s*\(/, title: "Dynamic eval call detected", severity: "high", description: "eval executes strings as code and can turn input handling bugs into remote code execution." },
    { pattern: /\bnew\s+Function\s*\(/, title: "Dynamic Function constructor detected", severity: "high", description: "new Function executes generated code and is unsafe for user-controlled input." },
    { pattern: /\bdangerouslySetInnerHTML\b/, title: "dangerouslySetInnerHTML usage detected", severity: "medium", description: "Rendering raw HTML can introduce XSS unless content is sanitized and trusted." },
    { pattern: /\bchild_process\b/, title: "child_process usage detected", severity: "high", description: "Spawning shell processes is high risk in AI/tooling apps and must never use untrusted input." },
    { pattern: /\b(exec|spawn)\s*\(/, title: "Shell process call detected", severity: "high", description: "exec/spawn calls can become command injection paths when arguments are user-controlled." },
    { pattern: /\bfs\.writeFile(?:Sync)?\s*\([^)]*(req|request|body|input|user)/i, title: "File write appears to use request input", severity: "high", description: "Writing files from request input can overwrite project or runtime files if not constrained." },
  ]

  for (const check of checks) {
    if (isRustFile && check.title === "Shell process call detected") continue

    const hit = findLineMatching(file.text, check.pattern)
    if (!hit) continue

    add({
      severity: check.severity,
      category: "dangerous_code",
      title: check.title,
      description: check.description,
      filePath: file.path,
      lineStart: hit.lineNumber,
      evidence: redactSecrets(hit.line.trim()),
      confidence: 0.8,
      recommendation: "Avoid dynamic code execution and sanitize all HTML/user input. If shell or file access is required, use strict allowlists and fixed paths.",
      patchable: check.pattern.source.includes("dangerouslySetInnerHTML"),
      source: "rule",
    })
  }
}

function scanRustDangerousCode(file: ProjectFile, add: (finding: RuleFinding) => void) {
  if (!file.path.endsWith(".rs")) return

  const checks: { pattern: RegExp; title: string; severity: Severity; description: string; recommendation: string }[] = [
    {
      pattern: /\b(?:std::process::)?Command::new\s*\(/,
      title: "Rust process execution detected",
      severity: "medium",
      description: "This Rust code starts an operating-system process. That is expected in some tools, but it becomes command injection risk if command names, arguments, or working directories are user-controlled.",
      recommendation: "Keep command names fixed, pass arguments as structured values, reject shell metacharacters, and never forward untrusted input into a shell.",
    },
    {
      pattern: /\bunsafe\s*\{/,
      title: "Rust unsafe block detected",
      severity: "medium",
      description: "Unsafe Rust bypasses compiler memory-safety guarantees and should receive focused security review before release.",
      recommendation: "Minimize unsafe blocks, document invariants, add tests around boundary conditions, and prefer safe wrappers where possible.",
    },
  ]

  for (const check of checks) {
    const hit = findLineMatching(file.text, check.pattern)
    if (!hit) continue

    add({
      severity: check.severity,
      category: "dangerous_code",
      title: check.title,
      description: check.description,
      filePath: file.path,
      lineStart: hit.lineNumber,
      evidence: redactSecrets(hit.line.trim()),
      confidence: 0.74,
      recommendation: check.recommendation,
      patchable: false,
      source: "rule",
    })
  }
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

function extractAssignedValue(line: string) {
  const match = line.match(/[=:]\s*['"]?([^'"\s#]+)/)
  return match?.[1] ?? ""
}

function lineHasConcreteSecretValue(path: string, line: string) {
  if (isCommentOnlyLine(line)) return false
  if (isObviousPlaceholder(line) || isExampleSecretPlaceholder(path, line)) return false
  if (isDocumentationSecretExample(path, line)) return false

  const assigned = extractAssignedValue(line)
  if (assigned.length < 6) return false
  if (/\b(process\.env|import\.meta\.env|Deno\.env|os\.environ|env\.)\b/i.test(assigned)) return false
  if (/^[A-Z0-9_]+$/.test(assigned) && !isEnvLike(path)) return false
  return true
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
  return /\b(your[_-]?|example|placeholder|changeme|change_me|replace_me|todo|dummy|null|undefined|redacted|demo|fake|sample|not[_-]?real|test[_-]?key|xxxx+|local[_-]?only)\b/i.test(line)
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
    normalized.includes("/examples/") ||
    normalized.includes("/fixtures/") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/docs/")
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
