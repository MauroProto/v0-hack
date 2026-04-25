import path from "node:path"

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
  ".rs",
  ".txt",
  ".toml",
  ".yml",
  ".yaml",
])

const IGNORED_SEGMENTS = new Set(["node_modules", ".next", "dist", "build", ".git"])
const SUPPORTED_EXTENSIONLESS_FILES = new Set(["README", "LICENSE", "NOTICE"])
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

export function shouldSkipLargeLockfile(filePath: string, size: number) {
  if (size <= 250_000) return false
  return /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|Cargo\.lock)$/i.test(filePath)
}

function isEnvFile(filePath: string) {
  const name = path.posix.basename(filePath)
  return name === ".env" || name.startsWith(".env.")
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
