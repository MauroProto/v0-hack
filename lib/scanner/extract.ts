import { promises as fs } from "node:fs"
import path from "node:path"
import type { ExtractedProject, ProjectFile } from "./types"
import { auditEvent } from "./scan"

const SUPPORTED_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".md",
  ".txt",
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

export async function extractProjectFromDirectory(
  rootDir: string,
  projectName: string,
  limits = getScannerLimits(),
): Promise<ExtractedProject> {
  const files: ProjectFile[] = []
  let totalTextBytes = 0

  async function walk(currentDir: string) {
    const entries = await fs.readdir(currentDir, { withFileTypes: true })
    for (const entry of entries) {
      const absolutePath = path.join(currentDir, entry.name)
      const relativePath = normalizeZipPath(path.relative(rootDir, absolutePath))

      if (entry.isDirectory()) {
        if (relativePath.split("/").some((segment) => IGNORED_SEGMENTS.has(segment))) continue
        await walk(absolutePath)
        continue
      }

      if (!entry.isFile()) continue
      if (!shouldConsiderProjectPath(relativePath)) continue

      const stat = await fs.stat(absolutePath)
      if (stat.size > limits.maxFileSizeBytes || shouldSkipLargeLockfile(relativePath, stat.size)) continue
      totalTextBytes += stat.size
      if (totalTextBytes > limits.maxTotalSizeBytes) {
        throw new Error(`Project text files exceed ${formatBytes(limits.maxTotalSizeBytes)}.`)
      }

      const bytes = await fs.readFile(absolutePath)
      if (isProbablyBinary(bytes)) continue
      const text = decodeUtf8(bytes)
      if (text === null) continue

      files.push({ path: relativePath, size: stat.size, text })
      if (files.length > limits.maxFiles) {
        throw new Error(`Project has too many supported files. Limit is ${limits.maxFiles}.`)
      }
    }
  }

  await walk(rootDir)

  if (files.length === 0) {
    throw new Error("No supported text files were found in the demo project.")
  }

  return {
    projectName,
    files,
    auditTrail: [
      auditEvent("Load bundled vulnerable demo project", "complete", {
        files: files.length,
        totalTextBytes,
      }),
    ],
  }
}

export function shouldConsiderProjectPath(filePath: string) {
  const normalized = normalizeZipPath(filePath)
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
  return /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?)$/i.test(filePath)
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

function formatBytes(bytes: number) {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} bytes`
}

const normalizeZipPath = normalizeProjectPath
