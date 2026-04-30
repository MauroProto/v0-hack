import { parse } from "@typescript-eslint/typescript-estree"
import type { ProjectFile, RepoInventory } from "./types"
import { isApiRoute } from "./rules"

type AstNode = {
  type?: string
  loc?: { start?: { line?: number } }
  [key: string]: unknown
}

const JS_TS_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i
const AUTH_CALL_RE = /\b(auth|getServerSession|currentUser|verifySession|verifyToken|getSession|requireAuth|withAuth|jwtVerify)\s*\(/i
const VALIDATION_CALL_RE = /\b(zod|\.parse\(|\.safeParse\(|yup|valibot|superstruct)\b/i
const AI_CALL_RE = /\b(generateText|streamText|generateObject|streamObject|openai\.chat\.completions|anthropic\.messages\.create)\b/i
const DB_CALL_RE = /\b(prisma|supabase|db|pool|client)\.(?:from|query|execute|find|create|update|delete|\$queryRaw|\$queryRawUnsafe|\$executeRawUnsafe)\b/i
const DANGEROUS_SINK_RE = /\b(eval|Function|dangerouslySetInnerHTML|exec|spawn|redirect|fetch|\$queryRawUnsafe|\$executeRawUnsafe|Command::new)\b/i

export function buildRepoInventory(files: ProjectFile[], framework?: string): RepoInventory {
  const languages = new Set<string>()
  let routeHandlers = 0
  let serverActions = 0
  let clientComponents = 0
  let imports = 0
  let envReads = 0
  let authCalls = 0
  let validationCalls = 0
  let dangerousSinks = 0
  let aiCalls = 0
  let dbCalls = 0
  let githubWorkflows = 0
  let supabaseMigrations = 0
  let prismaSchemas = 0

  for (const file of files) {
    const path = file.path.toLowerCase()
    addLanguage(languages, path)
    if (isApiRoute(file.path)) routeHandlers += 1
    if (path.startsWith(".github/workflows/") && /\.(ya?ml)$/.test(path)) githubWorkflows += 1
    if (path.includes("supabase/migrations/") && path.endsWith(".sql")) supabaseMigrations += 1
    if (path.endsWith(".prisma")) prismaSchemas += 1
    if (/['"]use client['"]/.test(file.text)) clientComponents += 1
    if (/['"]use server['"]/.test(file.text)) serverActions += countExportedFunctions(file.text) || 1

    envReads += countMatches(file.text, /\b(process\.env|import\.meta\.env|Deno\.env|os\.environ)\b/g)
    authCalls += countMatches(file.text, AUTH_CALL_RE)
    validationCalls += countMatches(file.text, VALIDATION_CALL_RE)
    dangerousSinks += countMatches(file.text, DANGEROUS_SINK_RE)
    aiCalls += countMatches(file.text, AI_CALL_RE)
    dbCalls += countMatches(file.text, DB_CALL_RE)

    if (JS_TS_RE.test(path)) {
      const astSummary = inspectJavaScriptAst(file)
      imports += astSummary.imports
      serverActions += astSummary.serverActionExports
      authCalls += astSummary.authCalls
      validationCalls += astSummary.validationCalls
      dangerousSinks += astSummary.dangerousSinks
      aiCalls += astSummary.aiCalls
      dbCalls += astSummary.dbCalls
    }
  }

  return {
    framework,
    languages: [...languages].sort(),
    routeHandlers,
    serverActions,
    clientComponents,
    imports,
    envReads,
    authCalls,
    validationCalls,
    dangerousSinks,
    aiCalls,
    dbCalls,
    githubWorkflows,
    supabaseMigrations,
    prismaSchemas,
  }
}

function inspectJavaScriptAst(file: ProjectFile) {
  const summary = {
    imports: 0,
    serverActionExports: 0,
    authCalls: 0,
    validationCalls: 0,
    dangerousSinks: 0,
    aiCalls: 0,
    dbCalls: 0,
  }

  let ast: AstNode
  try {
    ast = parse(file.text, {
      jsx: file.path.endsWith(".tsx") || file.path.endsWith(".jsx"),
      loc: true,
      range: false,
      comment: false,
      errorOnUnknownASTType: false,
    }) as unknown as AstNode
  } catch {
    return summary
  }

  const hasUseServer = /['"]use server['"]/.test(file.text)
  walkAst(ast, (node) => {
    if (node.type === "ImportDeclaration") summary.imports += 1
    if (hasUseServer && node.type === "ExportNamedDeclaration") summary.serverActionExports += 1
    if (node.type !== "CallExpression") return

    const callee = calleeName(node)
    if (!callee) return
    if (/^(auth|getServerSession|currentUser|verifySession|verifyToken|getSession|requireAuth|withAuth|jwtVerify)$/.test(callee)) summary.authCalls += 1
    if (/^(parse|safeParse|validate|validateSync)$/.test(callee)) summary.validationCalls += 1
    if (/^(generateText|streamText|generateObject|streamObject)$/.test(callee) || /openai|anthropic/i.test(callee)) summary.aiCalls += 1
    if (/(\$queryRawUnsafe|\$executeRawUnsafe|query|from|findMany|create|update|delete)/.test(callee)) summary.dbCalls += 1
    if (/^(eval|Function|exec|spawn|redirect|fetch|\$queryRawUnsafe|\$executeRawUnsafe)$/.test(callee)) summary.dangerousSinks += 1
  })

  return summary
}

function walkAst(node: unknown, visit: (node: AstNode) => void) {
  if (!node || typeof node !== "object") return
  const astNode = node as AstNode
  visit(astNode)

  for (const value of Object.values(astNode)) {
    if (!value || value === astNode.loc) continue
    if (Array.isArray(value)) {
      for (const item of value) walkAst(item, visit)
    } else if (typeof value === "object") {
      walkAst(value, visit)
    }
  }
}

function calleeName(node: AstNode) {
  const callee = node.callee as AstNode | undefined
  if (!callee) return null
  if (callee.type === "Identifier" && typeof callee.name === "string") return callee.name
  if (callee.type === "MemberExpression") {
    const property = callee.property as AstNode | undefined
    if (property?.type === "Identifier" && typeof property.name === "string") return property.name
  }
  return null
}

function countExportedFunctions(text: string) {
  return countMatches(text, /\bexport\s+(?:async\s+)?function\b/g) + countMatches(text, /\bexport\s+const\s+\w+\s*=\s*async\b/g)
}

function countMatches(text: string, pattern: RegExp) {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`
  const globalPattern = new RegExp(pattern.source, flags)
  return [...text.matchAll(globalPattern)].length
}

function addLanguage(languages: Set<string>, path: string) {
  if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)) languages.add("TypeScript/JavaScript")
  else if (path.endsWith(".rs")) languages.add("Rust")
  else if (path.endsWith(".py")) languages.add("Python")
  else if (path.endsWith(".go")) languages.add("Go")
  else if (path.endsWith(".java")) languages.add("Java")
  else if (path.endsWith(".php")) languages.add("PHP")
  else if (path.endsWith(".rb")) languages.add("Ruby")
  else if (path.endsWith(".sql")) languages.add("SQL")
  else if (path.endsWith(".prisma")) languages.add("Prisma")
  else if (path.endsWith(".yml") || path.endsWith(".yaml")) languages.add("YAML")
}
