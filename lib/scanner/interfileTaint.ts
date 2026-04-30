import { isApiRoute, redactSecrets } from "./rules"
import type { ProjectFile, ScanFinding, TraceStep } from "./types"

type InterfileFinding = Omit<ScanFinding, "id">

type ImportBinding = {
  importedName: string
  localName: string
  sourcePath: string
}

type SourceVariable = {
  name: string
  filePath: string
  line: string
  lineNumber: number
}

type FunctionDefinition = {
  file: ProjectFile
  name: string
  params: string[]
  lineNumber: number
  lines: Array<{ line: string; lineNumber: number }>
  imports: ImportBinding[]
}

type TraceResult = {
  sinkLine: string
  sinkLineNumber: number
  sinkFilePath: string
  sinkKind: "sql" | "command" | "redirect" | "fetch" | "html" | "eval"
  trace: TraceStep[]
}

const MAX_INTERFILE_DEPTH = 3

export function scanInterfileTaint(files: ProjectFile[]): InterfileFinding[] {
  const textFiles = files.filter((file) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file.path))
  const fileMap = new Map(textFiles.map((file) => [normalizePath(file.path), file]))
  const functionIndex = buildFunctionIndex(textFiles)
  const findings: InterfileFinding[] = []
  const seen = new Set<string>()

  for (const file of textFiles) {
    if (!isApiRoute(file.path) && !hasServerActionDirective(file.text)) continue

    const imports = parseImports(file, fileMap)
    if (imports.length === 0) continue

    const sourceVariables = findRequestSources(file)
    if (sourceVariables.length === 0) continue

    const lines = lineRecords(file.text)
    for (const source of sourceVariables) {
      for (const binding of imports) {
        const calls = findCallsWithVariable(lines, binding.localName, source.name, source.lineNumber)
        for (const call of calls) {
          if (isSanitizedCallArgument(call.line, source.name)) continue
          const target = functionIndex.get(functionKey(binding.sourcePath, binding.importedName))
          if (!target) continue

          const trace = traceFunction(target, target.params[0], functionIndex, [
            {
              filePath: source.filePath,
              lineStart: source.lineNumber,
              kind: "source",
              label: "Request input source",
              code: redactSecrets(source.line.trim()),
            },
            {
              filePath: file.path,
              lineStart: call.lineNumber,
              kind: "propagator",
              label: `Request data passed to ${binding.localName}()`,
              code: redactSecrets(call.line.trim()),
            },
          ], new Set([functionKey(target.file.path, target.name)]), 1)

          if (!trace) continue
          const key = `${source.filePath}:${source.lineNumber}:${trace.sinkFilePath}:${trace.sinkLineNumber}`
          if (seen.has(key)) continue
          seen.add(key)

          findings.push({
            kind: "vulnerability",
            severity: severityForSink(trace.sinkKind),
            category: categoryForSink(trace.sinkKind),
            ruleId: "taint.interfile.request-to-dangerous-sink",
            title: "Request data reaches a dangerous sink across files",
            description:
              "Request-controlled data appears to cross a route/service boundary and reach a dangerous operation without a visible validator or allowlist.",
            filePath: trace.sinkFilePath,
            lineStart: trace.sinkLineNumber,
            evidence: redactSecrets(trace.sinkLine.trim()),
            confidence: 0.78,
            confidenceReason:
              "A bounded inter-file trace connected request parsing to a service call and then to a sink. This is conservative and limited to direct argument propagation.",
            reachability: "reachable",
            exploitability: trace.sinkKind === "sql" || trace.sinkKind === "command" ? "high" : "medium",
            cwe: cweForSink(trace.sinkKind),
            evidenceTrace: trace.trace,
            recommendation:
              "Validate request input at the route boundary, pass only parsed DTO fields across service layers, and replace raw/dynamic sink APIs with parameterized or allowlisted alternatives.",
            patchable: false,
            source: "rule",
          })
        }
      }
    }
  }

  return findings
}

function traceFunction(
  fn: FunctionDefinition,
  taintedParam: string | undefined,
  functionIndex: Map<string, FunctionDefinition>,
  trace: TraceStep[],
  visited: Set<string>,
  depth: number,
): TraceResult | null {
  if (!taintedParam || depth > MAX_INTERFILE_DEPTH) return null

  const tainted = escapeRegExp(taintedParam)
  for (const item of fn.lines) {
    if (!new RegExp(`\\b${tainted}\\b`).test(item.line)) continue

    const sinkKind = classifyDangerousSink(item.line)
    if (sinkKind) {
      return {
        sinkLine: item.line,
        sinkLineNumber: item.lineNumber,
        sinkFilePath: fn.file.path,
        sinkKind,
        trace: [
          ...trace,
          {
            filePath: fn.file.path,
            lineStart: item.lineNumber,
            kind: "sink",
            label: labelForSink(sinkKind),
            code: redactSecrets(item.line.trim()),
          },
        ],
      }
    }

    for (const binding of fn.imports) {
      if (!new RegExp(`\\b${escapeRegExp(binding.localName)}\\s*\\(`).test(item.line)) continue
      const target = functionIndex.get(functionKey(binding.sourcePath, binding.importedName))
      if (!target) continue
      const targetKey = functionKey(target.file.path, target.name)
      if (visited.has(targetKey)) continue

      const taintedArgumentIndex = findTaintedArgumentIndex(item.line, binding.localName, taintedParam)
      if (taintedArgumentIndex < 0) continue

      const nextParam = target.params[taintedArgumentIndex] ?? target.params[0]
      const result = traceFunction(
        target,
        nextParam,
        functionIndex,
        [
          ...trace,
          {
            filePath: fn.file.path,
            lineStart: item.lineNumber,
            kind: "propagator",
            label: `Tainted value passed to ${binding.localName}()`,
            code: redactSecrets(item.line.trim()),
          },
        ],
        new Set([...visited, targetKey]),
        depth + 1,
      )
      if (result) return result
    }
  }

  return null
}

function buildFunctionIndex(files: ProjectFile[]) {
  const out = new Map<string, FunctionDefinition>()
  const fileMap = new Map(files.map((file) => [normalizePath(file.path), file]))

  for (const file of files) {
    const imports = parseImports(file, fileMap)
    for (const definition of parseFunctionDefinitions(file, imports)) {
      out.set(functionKey(file.path, definition.name), definition)
    }
  }

  return out
}

function parseFunctionDefinitions(file: ProjectFile, imports: ImportBinding[]): FunctionDefinition[] {
  const lines = lineRecords(file.text)
  const definitions: FunctionDefinition[] = []

  for (let index = 0; index < lines.length; index += 1) {
    const record = lines[index]
    const fnMatch = record.line.match(/\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/)
    const constMatch = record.line.match(/\bexport\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/)
    const name = fnMatch?.[1] ?? constMatch?.[1]
    const rawParams = fnMatch?.[2] ?? constMatch?.[2]
    if (!name || rawParams === undefined) continue

    definitions.push({
      file,
      name,
      params: parseParams(rawParams),
      lineNumber: record.lineNumber,
      lines: lines.slice(index, Math.min(lines.length, index + 80)),
      imports,
    })
  }

  return definitions
}

function parseImports(file: ProjectFile, fileMap: Map<string, ProjectFile>): ImportBinding[] {
  const bindings: ImportBinding[] = []
  const importRegex = /import\s+(?:type\s+)?(?:{([^}]+)}|([A-Za-z_$][\w$]*))\s+from\s+["']([^"']+)["']/g

  for (const match of file.text.matchAll(importRegex)) {
    const sourcePath = resolveImportPath(file.path, match[3], fileMap)
    if (!sourcePath) continue

    if (match[1]) {
      for (const raw of match[1].split(",")) {
        const part = raw.trim()
        if (!part) continue
        const alias = part.match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/)
        if (!alias) continue
        bindings.push({ importedName: alias[1], localName: alias[2] ?? alias[1], sourcePath })
      }
    } else if (match[2]) {
      bindings.push({ importedName: "default", localName: match[2], sourcePath })
    }
  }

  return bindings
}

function resolveImportPath(fromPath: string, specifier: string, fileMap: Map<string, ProjectFile>) {
  if (!specifier.startsWith("@/") && !specifier.startsWith(".")) return null

  const base = specifier.startsWith("@/")
    ? specifier.slice(2)
    : normalizePath(joinPath(dirname(fromPath), specifier))
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.jsx`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
    `${base}/index.js`,
    `${base}/index.jsx`,
  ].map(normalizePath)

  return candidates.find((candidate) => fileMap.has(candidate)) ?? null
}

function findRequestSources(file: ProjectFile): SourceVariable[] {
  return lineRecords(file.text).flatMap((record) => {
    const direct = record.line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+(?:req|request)\.json\(\)/)
    if (direct) return [{ name: direct[1], filePath: file.path, line: record.line, lineNumber: record.lineNumber }]
    return []
  })
}

function findCallsWithVariable(
  lines: Array<{ line: string; lineNumber: number }>,
  functionName: string,
  variableName: string,
  afterLine: number,
) {
  const callRegex = new RegExp(`\\b${escapeRegExp(functionName)}\\s*\\(([^)]*)\\)`)
  const variableRegex = new RegExp(`\\b${escapeRegExp(variableName)}\\b`)
  return lines.filter((record) => record.lineNumber > afterLine && callRegex.test(record.line) && variableRegex.test(record.line))
}

function findTaintedArgumentIndex(line: string, functionName: string, taintedParam: string) {
  const call = line.match(new RegExp(`\\b${escapeRegExp(functionName)}\\s*\\(([^)]*)\\)`))
  if (!call) return -1
  const args = splitArguments(call[1])
  return args.findIndex((arg) => new RegExp(`\\b${escapeRegExp(taintedParam)}\\b`).test(arg))
}

function classifyDangerousSink(line: string): TraceResult["sinkKind"] | null {
  if (/\$queryRawUnsafe|\$executeRawUnsafe/i.test(line)) return "sql"
  if (/\b(?:exec|spawn)\s*\(|Command::new\s*\(/.test(line)) return "command"
  if (/\bredirect\s*\(/.test(line)) return "redirect"
  if (/\bfetch\s*\(/.test(line)) return "fetch"
  if (/dangerouslySetInnerHTML/.test(line)) return "html"
  if (/\beval\s*\(|new\s+Function\s*\(/.test(line)) return "eval"
  return null
}

function categoryForSink(sinkKind: TraceResult["sinkKind"]): InterfileFinding["category"] {
  if (sinkKind === "sql") return "sql_injection"
  if (sinkKind === "command") return "command_injection"
  if (sinkKind === "redirect") return "unsafe_redirect"
  if (sinkKind === "html") return "xss"
  return "input_validation"
}

function severityForSink(sinkKind: TraceResult["sinkKind"]): InterfileFinding["severity"] {
  if (sinkKind === "sql" || sinkKind === "command") return "high"
  return "medium"
}

function cweForSink(sinkKind: TraceResult["sinkKind"]) {
  if (sinkKind === "sql") return "CWE-89"
  if (sinkKind === "command") return "CWE-78"
  if (sinkKind === "redirect") return "CWE-601"
  if (sinkKind === "html") return "CWE-79"
  return undefined
}

function labelForSink(sinkKind: TraceResult["sinkKind"]) {
  if (sinkKind === "sql") return "Raw SQL sink"
  if (sinkKind === "command") return "Process execution sink"
  if (sinkKind === "redirect") return "Redirect sink"
  if (sinkKind === "html") return "HTML rendering sink"
  return "Dangerous sink"
}

function isSanitizedCallArgument(line: string, variableName: string) {
  const variable = escapeRegExp(variableName)
  return new RegExp(`\\.(?:parse|safeParse)\\s*\\([^)]*\\b${variable}\\b`, "i").test(line)
}

function parseParams(rawParams: string) {
  return rawParams
    .split(",")
    .map((param) => param.trim().match(/^([A-Za-z_$][\w$]*)/)?.[1])
    .filter((param): param is string => Boolean(param))
}

function splitArguments(raw: string) {
  return raw.split(",").map((arg) => arg.trim())
}

function hasServerActionDirective(text: string) {
  return /["']use server["']/.test(text.slice(0, 1200))
}

function lineRecords(text: string) {
  return text.split(/\r?\n/).map((line, index) => ({ line, lineNumber: index + 1 }))
}

function functionKey(filePath: string, name: string) {
  return `${normalizePath(filePath)}#${name}`
}

function dirname(filePath: string) {
  const normalized = normalizePath(filePath)
  return normalized.includes("/") ? normalized.slice(0, normalized.lastIndexOf("/")) : "."
}

function joinPath(base: string, relative: string) {
  const parts = `${base}/${relative}`.split("/")
  const out: string[] = []
  for (const part of parts) {
    if (!part || part === ".") continue
    if (part === "..") out.pop()
    else out.push(part)
  }
  return out.join("/")
}

function normalizePath(path: string) {
  return path.replaceAll("\\", "/").replace(/^\/+/, "")
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}
