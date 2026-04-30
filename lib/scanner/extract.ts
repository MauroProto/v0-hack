import path from "node:path"
import type { ScanMode } from "./types"

const SUPPORTED_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".lock",
  ".md",
  ".mdx",
  ".rs",
  ".py",
  ".go",
  ".java",
  ".php",
  ".rb",
  ".sh",
  ".sql",
  ".prisma",
  ".graphql",
  ".html",
  ".txt",
  ".toml",
  ".yml",
  ".yaml",
])

const IGNORED_SEGMENTS = new Set(["node_modules", ".next", "dist", "build", ".git"])
const SUPPORTED_EXTENSIONLESS_FILES = new Set(["README", "LICENSE", "NOTICE", "DOCKERFILE", ".VIBESHIELDIGNORE"])
const IMAGE_VIDEO_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".avif",
  ".svg",
  ".ico",
  ".mp4",
  ".mov",
  ".webm",
  ".mp3",
  ".wav",
  ".pdf",
  ".zip",
])

const SECURITY_PATH_KEYWORDS = [
  "auth",
  "session",
  "token",
  "secret",
  "credential",
  "api",
  "admin",
  "internal",
  "billing",
  "webhook",
  "mcp",
  "agent",
  "tool",
  "shell",
  "command",
  "openai",
  "anthropic",
  "deepseek",
  "ai",
  "db",
  "database",
  "supabase",
  "prisma",
  "stripe",
  "payment",
  "security",
  "sandbox",
  "policy",
]

const LOW_VALUE_PATH_SEGMENTS = new Set(["test", "tests", "__tests__", "__fixtures__", "fixtures", "docs", "doc", "examples", "example", "samples", "sample"])

export interface ScannerLimits {
  maxFiles: number
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
}

export function getScannerLimits(): ScannerLimits {
  return {
    maxFiles: readPositiveInt(process.env.MAX_SCAN_FILES, 500),
    maxFileSizeBytes: readPositiveInt(process.env.MAX_SCAN_FILE_SIZE_BYTES, 500_000),
    maxTotalSizeBytes: readPositiveInt(process.env.MAX_SCAN_TOTAL_SIZE_BYTES, 10_000_000),
  }
}

export function getScannerLimitsForMode(mode: ScanMode): ScannerLimits {
  const base = getScannerLimits()
  if (mode !== "max") return base

  return {
    maxFiles: Math.min(readPositiveInt(process.env.MAX_SCAN_FILES_MAX, Math.max(base.maxFiles * 2, 900)), 1_200),
    maxFileSizeBytes: base.maxFileSizeBytes,
    maxTotalSizeBytes: Math.min(
      readPositiveInt(process.env.MAX_SCAN_TOTAL_SIZE_BYTES_MAX, Math.max(base.maxTotalSizeBytes * 2, 20_000_000)),
      25_000_000,
    ),
  }
}

export function shouldConsiderProjectPath(filePath: string) {
  const normalized = normalizeProjectPath(filePath)
  if (!normalized || normalized.endsWith("/")) return false

  const segments = normalized.split("/")
  if (segments.some((segment) => segment === "." || segment === "..")) return false
  if (segments.some((segment) => IGNORED_SEGMENTS.has(segment))) return false

  const extension = path.posix.extname(normalized).toLowerCase()
  const basename = path.posix.basename(normalized).toUpperCase()
  if (IMAGE_VIDEO_EXTENSIONS.has(extension)) return false
  if (isEnvFile(normalized)) return true
  if (!extension && SUPPORTED_EXTENSIONLESS_FILES.has(basename)) return true
  return SUPPORTED_EXTENSIONS.has(extension)
}

export function compareProjectPathPriority(a: string, b: string) {
  const scoreDelta = projectPathPriorityScore(b) - projectPathPriorityScore(a)
  if (scoreDelta !== 0) return scoreDelta
  return a.localeCompare(b)
}

export function projectPathPriorityScore(filePath: string) {
  const normalized = normalizeProjectPath(filePath)
  const lower = normalized.toLowerCase()
  const name = path.posix.basename(normalized)
  const lowerName = name.toLowerCase()
  const extension = path.posix.extname(normalized).toLowerCase()
  const segments = lower.split("/")
  let score = 0

  if (isEnvFile(normalized)) score += 10_000
  if (lowerName === ".vibeshieldignore") score += 9_500
  if (lower.startsWith(".github/workflows/")) score += 9_000
  if (isLockfilePath(normalized)) score += 8_700
  if (isManifestPath(lowerName)) score += 8_500
  if (isPrimaryConfigPath(lowerName)) score += 8_100
  if (/^app\/api\/.*\/route\.(ts|tsx|js|jsx)$/.test(lower)) score += 7_800
  if (/^pages\/api\//.test(lower)) score += 7_700
  if (/(^|\/)(actions?|server-actions?)\.(ts|tsx|js|jsx)$/.test(lower)) score += 7_400
  if (/(^|\/)(middleware|proxy)\.(ts|tsx|js)$/.test(lower)) score += 7_200
  if (lower.startsWith("supabase/migrations/") && extension === ".sql") score += 7_000
  if (extension === ".prisma") score += 6_800
  if (lowerName === "dockerfile" || lowerName.endsWith(".dockerfile")) score += 6_400
  if (lowerName === "readme.md" || lowerName === "readme") score += 6_200
  if (SECURITY_PATH_KEYWORDS.some((keyword) => lower.includes(keyword))) score += 2_500
  if ([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".py", ".go", ".java", ".php", ".rb", ".sh"].includes(extension)) score += 1_800
  if ([".sql", ".graphql", ".yaml", ".yml", ".toml", ".json"].includes(extension)) score += 1_400
  if ([".md", ".mdx", ".txt", ".html"].includes(extension)) score += 500
  if (segments.some((segment) => LOW_VALUE_PATH_SEGMENTS.has(segment))) score -= 1_200
  if (/(\.test|\.spec|_test|test_)\.(ts|tsx|js|jsx|rs|py|go)$/i.test(lower)) score -= 1_500
  if (lowerName === "license" || lowerName === "notice") score -= 2_000

  return score
}

export function shouldSkipLargeLockfile(filePath: string, size: number) {
  if (!isLockfilePath(filePath)) return false
  return size > maxLockfileSizeBytes()
}

export function maxBytesForProjectPath(filePath: string, defaultMax: number) {
  if (isLockfilePath(filePath)) return Math.max(defaultMax, maxLockfileSizeBytes())
  return defaultMax
}

export function isLockfilePath(filePath: string) {
  return /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|Cargo\.lock|Pipfile\.lock|poetry\.lock|Gemfile\.lock|composer\.lock|go\.sum)$/i.test(filePath)
}

function isEnvFile(filePath: string) {
  const name = path.posix.basename(filePath)
  return name === ".env" || name.startsWith(".env.")
}

function isManifestPath(lowerName: string) {
  return [
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "cargo.toml",
    "go.mod",
    "gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "deno.json",
    "bunfig.toml",
  ].includes(lowerName)
}

function isPrimaryConfigPath(lowerName: string) {
  return /^(next|vite|nuxt|astro|svelte|tailwind|tsconfig|eslint|vercel|netlify|wrangler|drizzle|prisma|supabase)\b/.test(lowerName)
}

export function isProbablyBinary(bytes: Uint8Array) {
  const sample = bytes.slice(0, Math.min(bytes.byteLength, 4096))
  if (sample.includes(0)) return true

  let suspicious = 0
  for (const byte of sample) {
    if (byte < 7 || (byte > 14 && byte < 32)) suspicious += 1
  }

  return sample.length > 0 && suspicious / sample.length > 0.08
}

export function decodeUtf8(bytes: Uint8Array) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

export function normalizeProjectPath(filePath: string) {
  return filePath.replaceAll("\\", "/").replace(/^\/+/, "").replace(/\/+/g, "/")
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}

function maxLockfileSizeBytes() {
  return readPositiveInt(process.env.MAX_SCAN_LOCKFILE_SIZE_BYTES, 2_000_000)
}
