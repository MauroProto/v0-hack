import { auditEvent } from "@/lib/scanner/scan"
import {
  decodeUtf8,
  getScannerLimits,
  isProbablyBinary,
  normalizeProjectPath,
  shouldConsiderProjectPath,
  shouldSkipLargeLockfile,
  type ScannerLimits,
} from "@/lib/scanner/extract"
import type { ExtractedProject, ProjectFile } from "@/lib/scanner/types"
import JSZip from "jszip"

export interface ParsedGitHubUrl {
  owner: string
  repo: string
}

export interface GitHubRepositorySummary {
  id: number
  fullName: string
  private: boolean
  defaultBranch: string
  htmlUrl: string
  updatedAt: string
  language?: string | null
}

type GitHubRepoApi = {
  id: number
  name: string
  full_name: string
  private: boolean
  default_branch: string
  html_url: string
  updated_at: string
  language?: string | null
}

type GitHubTreeApi = {
  truncated?: boolean
  tree?: Array<{
    path?: string
    type?: string
    size?: number
    sha?: string
    url?: string
  }>
}

type GitHubBlobApi = {
  content?: string
  encoding?: string
  size?: number
}

const GITHUB_API = "https://api.github.com"
const GITHUB_CODELOAD = "https://codeload.github.com"
const GITHUB_REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})(?:\.git)?\/?$/
const GITHUB_FULL_NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/
const DEFAULT_PUBLIC_ARCHIVE_REFS = ["main", "master"]

export function parsePublicGitHubUrl(input: string): ParsedGitHubUrl {
  const trimmed = input.trim()
  const match = trimmed.match(GITHUB_REPO_RE)
  if (!match) {
    throw new Error("Only GitHub repo URLs in the form https://github.com/owner/repo are supported.")
  }

  return normalizeRepoParts(match[1], match[2])
}

export function parseGitHubFullName(input: string): ParsedGitHubUrl {
  const match = input.trim().match(GITHUB_FULL_NAME_RE)
  if (!match) throw new Error("Repository must be in owner/repo format.")
  return normalizeRepoParts(match[1], match[2])
}

export function getGitHubTokenFromRequest(request: Request) {
  const header = request.headers.get("x-github-token")
  const token = header?.trim()
  if (!token) return undefined
  if (!/^[A-Za-z0-9_./:=+-]{20,500}$/.test(token)) {
    throw new Error("Invalid GitHub token format.")
  }

  return token
}

export async function listAuthenticatedGitHubRepos(token: string): Promise<GitHubRepositorySummary[]> {
  const response = await githubFetch(
    `${GITHUB_API}/user/repos?per_page=100&sort=updated&direction=desc&affiliation=owner,collaborator,organization_member`,
    token,
  )
  const repos = (await response.json()) as GitHubRepoApi[]

  return repos.map((repo) => ({
    id: repo.id,
    fullName: repo.full_name,
    private: repo.private,
    defaultBranch: repo.default_branch,
    htmlUrl: repo.html_url,
    updatedAt: repo.updated_at,
    language: repo.language,
  }))
}

export async function extractProjectFromGitHubRepo(input: {
  owner: string
  repo: string
  ref?: string
  token?: string
  limits?: ScannerLimits
}): Promise<ExtractedProject & { sourceLabel: string; private: boolean; defaultBranch: string }> {
  const { owner, repo } = normalizeRepoParts(input.owner, input.repo)
  const limits = input.limits ?? getScannerLimits()
  try {
    const repository = await getRepository(owner, repo, input.token)
    const ref = sanitizeRef(input.ref || repository.default_branch)

    if (repository.private && !input.token) {
      throw new Error("Private repositories require GitHub login.")
    }

    const tree = await getRepositoryTree(owner, repo, ref, input.token)
    const files = await fetchProjectFiles(owner, repo, tree, input.token, limits)

    if (files.length === 0) {
      throw new Error("No supported text files were found in the GitHub repository.")
    }

    return {
      projectName: repository.name,
      sourceLabel: `github.com/${owner}/${repo}#${ref}`,
      private: repository.private,
      defaultBranch: repository.default_branch,
      files,
      auditTrail: [
        auditEvent("Connect to GitHub repository", "complete", {
          repository: `${owner}/${repo}`,
          private: repository.private,
          ref,
        }),
        auditEvent("Fetch GitHub tree via REST API", "complete", {
          entries: tree.length,
          truncated: false,
        }),
        auditEvent("Fetch supported blobs from GitHub", "complete", {
          files: files.length,
          totalTextBytes: files.reduce((total, file) => total + file.size, 0),
        }),
      ],
    }
  } catch (error) {
    if (!input.token && isGitHubRateLimitError(error)) {
      return extractPublicProjectFromArchive({ owner, repo, ref: input.ref, limits })
    }

    throw error
  }
}

async function getRepository(owner: string, repo: string, token?: string) {
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}`, token)
  const data = (await response.json()) as GitHubRepoApi
  return data
}

async function getRepositoryTree(owner: string, repo: string, ref: string, token?: string) {
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`, token)
  const data = (await response.json()) as GitHubTreeApi

  if (data.truncated) {
    throw new Error("GitHub tree is too large for the MVP scan. Narrow the repository or scan a smaller project.")
  }

  return data.tree ?? []
}

async function fetchProjectFiles(
  owner: string,
  repo: string,
  tree: NonNullable<GitHubTreeApi["tree"]>,
  token: string | undefined,
  limits: ScannerLimits,
) {
  const candidates = tree
    .filter((entry) => entry.type === "blob" && entry.path && entry.sha)
    .map((entry) => ({
      path: normalizeProjectPath(entry.path ?? ""),
      size: entry.size ?? 0,
      sha: entry.sha ?? "",
    }))
    .filter((entry) => shouldConsiderProjectPath(entry.path))
    .filter((entry) => entry.size <= limits.maxFileSizeBytes && !shouldSkipLargeLockfile(entry.path, entry.size))
    .slice(0, limits.maxFiles + 1)

  if (candidates.length > limits.maxFiles) {
    throw new Error(`Project has too many supported files. Limit is ${limits.maxFiles}.`)
  }

  const files: ProjectFile[] = []
  let totalTextBytes = 0

  for (const candidate of candidates) {
    const blob = await getBlob(owner, repo, candidate.sha, token)
    const bytes = decodeBlob(blob)

    if (bytes.byteLength > limits.maxFileSizeBytes || shouldSkipLargeLockfile(candidate.path, bytes.byteLength)) continue
    if (isProbablyBinary(bytes)) continue

    totalTextBytes += bytes.byteLength
    if (totalTextBytes > limits.maxTotalSizeBytes) {
      throw new Error(`Project text files exceed ${limits.maxTotalSizeBytes} bytes.`)
    }

    const text = decodeUtf8(bytes)
    if (text === null) continue
    files.push({ path: candidate.path, size: bytes.byteLength, text })
  }

  return files
}

async function getBlob(owner: string, repo: string, sha: string, token?: string) {
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/blobs/${sha}`, token)
  return (await response.json()) as GitHubBlobApi
}

async function githubFetch(url: string, token?: string) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "VibeShield",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
  })

  if (!response.ok) {
    if (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0") {
      throw new GitHubApiError("GitHub public API rate limit exceeded.", response.status, "github_rate_limited")
    }
    if (response.status === 401 || response.status === 403) throw new Error("GitHub authorization failed.")
    if (response.status === 404) throw new Error("GitHub repository or file was not found.")
    throw new Error(`GitHub API request failed with status ${response.status}.`)
  }

  return response
}

async function extractPublicProjectFromArchive(input: {
  owner: string
  repo: string
  ref?: string
  limits: ScannerLimits
}): Promise<ExtractedProject & { sourceLabel: string; private: boolean; defaultBranch: string }> {
  const refs = input.ref ? [sanitizeRef(input.ref)] : DEFAULT_PUBLIC_ARCHIVE_REFS
  const errors: string[] = []

  for (const ref of refs) {
    try {
      const archiveBytes = await downloadPublicArchive(input.owner, input.repo, ref, input.limits)
      const files = await extractFilesFromArchive(archiveBytes, input.limits)

      if (files.length === 0) {
        throw new Error("No supported text files were found in the GitHub repository archive.")
      }

      return {
        projectName: input.repo,
        sourceLabel: `github.com/${input.owner}/${input.repo}#${ref}`,
        private: false,
        defaultBranch: ref,
        files,
        auditTrail: [
          auditEvent("Connect to GitHub public archive", "complete", {
            repository: `${input.owner}/${input.repo}`,
            private: false,
            ref,
          }),
          auditEvent("Download GitHub archive via codeload", "complete", {
            compressedBytes: archiveBytes.byteLength,
          }),
          auditEvent("Extract supported files from GitHub archive", "complete", {
            files: files.length,
            totalTextBytes: files.reduce((total, file) => total + file.size, 0),
          }),
        ],
      }
    } catch (error) {
      if (error instanceof ArchiveNotFoundError) {
        errors.push(error.message)
        continue
      }

      throw error
    }
  }

  throw new Error(errors[0] ?? "GitHub repository archive was not found.")
}

async function downloadPublicArchive(owner: string, repo: string, ref: string, limits: ScannerLimits) {
  const maxArchiveBytes = readPositiveInt(process.env.MAX_SCAN_ARCHIVE_SIZE_BYTES, Math.max(limits.maxTotalSizeBytes * 2, 20_000_000))
  const response = await fetch(`${GITHUB_CODELOAD}/${owner}/${repo}/zip/refs/heads/${encodeURIComponent(ref)}`, {
    headers: {
      "User-Agent": "VibeShield",
    },
    cache: "no-store",
  })

  if (response.status === 404) throw new ArchiveNotFoundError(`GitHub archive ref ${ref} was not found.`)
  if (!response.ok) throw new Error(`GitHub archive download failed with status ${response.status}.`)

  const contentLength = Number(response.headers.get("content-length") ?? 0)
  if (Number.isFinite(contentLength) && contentLength > maxArchiveBytes) {
    throw new Error(`GitHub archive is too large. Maximum compressed size is ${maxArchiveBytes} bytes.`)
  }

  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > maxArchiveBytes) {
    throw new Error(`GitHub archive is too large. Maximum compressed size is ${maxArchiveBytes} bytes.`)
  }

  return bytes
}

async function extractFilesFromArchive(archiveBytes: Uint8Array, limits: ScannerLimits) {
  const zip = await JSZip.loadAsync(archiveBytes)
  const candidates = Object.values(zip.files)
    .filter((entry) => !entry.dir)
    .map((entry) => ({
      path: stripArchiveRoot(entry.name),
      entry,
    }))
    .filter((candidate) => shouldConsiderProjectPath(candidate.path))

  if (candidates.length > limits.maxFiles) {
    throw new Error(`Project has too many supported files. Limit is ${limits.maxFiles}.`)
  }

  const files: ProjectFile[] = []
  let totalTextBytes = 0

  for (const candidate of candidates) {
    const bytes = await candidate.entry.async("uint8array")
    if (bytes.byteLength > limits.maxFileSizeBytes || shouldSkipLargeLockfile(candidate.path, bytes.byteLength)) continue
    if (isProbablyBinary(bytes)) continue

    totalTextBytes += bytes.byteLength
    if (totalTextBytes > limits.maxTotalSizeBytes) {
      throw new Error(`Project text files exceed ${limits.maxTotalSizeBytes} bytes.`)
    }

    const text = decodeUtf8(bytes)
    if (text === null) continue
    files.push({ path: candidate.path, size: bytes.byteLength, text })
  }

  return files
}

function stripArchiveRoot(entryName: string) {
  const normalized = normalizeProjectPath(entryName)
  const parts = normalized.split("/")
  return parts.length > 1 ? parts.slice(1).join("/") : normalized
}

function isGitHubRateLimitError(error: unknown) {
  return error instanceof GitHubApiError && error.code === "github_rate_limited"
}

class GitHubApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
  ) {
    super(message)
  }
}

class ArchiveNotFoundError extends Error {}

function decodeBlob(blob: GitHubBlobApi) {
  if (blob.encoding !== "base64" || !blob.content) {
    throw new Error("Unsupported GitHub blob encoding.")
  }

  return Buffer.from(blob.content.replace(/\s/g, ""), "base64")
}

function normalizeRepoParts(owner: string, repoInput: string): ParsedGitHubUrl {
  const repo = repoInput.replace(/\.git$/, "")
  if (repo.includes("..") || repo.startsWith(".") || repo.endsWith(".")) {
    throw new Error("Unsupported GitHub repository name.")
  }

  return { owner, repo }
}

function sanitizeRef(ref: string) {
  const trimmed = ref.trim().slice(0, 120)
  if (!/^[A-Za-z0-9._/-]+$/.test(trimmed) || trimmed.includes("..")) {
    throw new Error("Unsupported GitHub ref.")
  }

  return trimmed
}

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback
  return Math.floor(parsed)
}
