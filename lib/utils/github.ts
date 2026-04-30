import { auditEvent } from "@/lib/scanner/scan"
import {
  decodeUtf8,
  getScannerLimits,
  isProbablyBinary,
  maxBytesForProjectPath,
  normalizeProjectPath,
  compareProjectPathPriority,
  shouldConsiderProjectPath,
  shouldSkipLargeLockfile,
  type ScannerLimits,
} from "@/lib/scanner/extract"
import { getGitHubSessionFromHeaders } from "@/lib/security/github-session"
import type { ExtractedProject, ProjectFile, ScanFinding, ScanPullRequest, ScanReport, ScanRepositoryRef } from "@/lib/scanner/types"

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
  owner?: {
    login?: string
  }
  parent?: {
    full_name?: string
  }
  source?: {
    full_name?: string
  }
  permissions?: {
    admin?: boolean
    maintain?: boolean
    push?: boolean
    pull?: boolean
    triage?: boolean
  }
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

type GitHubRefApi = {
  object?: {
    sha?: string
    type?: string
  }
}

type GitHubContentFileApi = {
  type?: string
  path?: string
  sha?: string
  content?: string
  encoding?: string
}

type GitHubPullRequestApi = {
  html_url: string
  number: number
  head: {
    ref: string
  }
  base: {
    ref: string
  }
}

type GitHubUserApi = {
  login?: string
}

const GITHUB_API = "https://api.github.com"
const GITHUB_REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})(?:\.git)?\/?$/
const GITHUB_FULL_NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/
const RETRYABLE_GITHUB_STATUSES = new Set([408, 500, 502, 503, 504])
const DEFAULT_GITHUB_FETCH_RETRIES = 2
const DEFAULT_GITHUB_RETRY_DELAY_MS = 450

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
  return getGitHubSessionFromHeaders(request.headers)?.token ?? getLocalGitHubToken()
}

export async function listAuthenticatedGitHubRepos(token: string): Promise<GitHubRepositorySummary[]> {
  const maxPages = readPositiveInt(process.env.VIBESHIELD_GITHUB_REPO_LIST_MAX_PAGES, 5)
  const repos: GitHubRepoApi[] = []

  for (let page = 1; page <= maxPages; page += 1) {
    const response = await githubFetch(
      `${GITHUB_API}/user/repos?per_page=100&page=${page}&sort=updated&direction=desc&affiliation=owner,collaborator,organization_member`,
      token,
    )
    const pageRepos = (await response.json()) as GitHubRepoApi[]
    repos.push(...pageRepos)
    if (pageRepos.length < 100) break
  }

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
}): Promise<ExtractedProject & { sourceLabel: string; private: boolean; defaultBranch: string; ref: string; htmlUrl: string }> {
  const { owner, repo } = normalizeRepoParts(input.owner, input.repo)
  const limits = input.limits ?? getScannerLimits()
  const repository = await getRepository(owner, repo, input.token)
  const ref = sanitizeRef(input.ref || repository.default_branch)

  if (repository.private && !input.token) {
    throw new Error("Private repositories require GitHub login.")
  }

  const tree = await getRepositoryTree(owner, repo, ref, input.token)
  const fetchResult = await fetchProjectFiles(owner, repo, tree, input.token, limits)
  const files = fetchResult.files

  if (files.length === 0) {
    throw new Error("No supported text files were found in the GitHub repository.")
  }

  return {
    projectName: repository.name,
    sourceLabel: `github.com/${owner}/${repo}#${ref}`,
    private: repository.private,
    defaultBranch: repository.default_branch,
    ref,
    htmlUrl: repository.html_url,
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
        supportedFiles: fetchResult.supportedFiles,
        selectedFiles: fetchResult.selectedFiles,
        skippedByFileLimit: fetchResult.skippedByFileLimit,
        skippedByTotalSizeLimit: fetchResult.skippedByTotalSizeLimit,
        skippedUnsupportedEncoding: fetchResult.skippedUnsupportedEncoding,
        totalTextBytes: fetchResult.totalTextBytes,
        partialCoverage:
          fetchResult.skippedByFileLimit > 0 || fetchResult.skippedByTotalSizeLimit > 0 || fetchResult.skippedUnsupportedEncoding > 0,
      }),
    ],
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
  const supportedCandidates = tree
    .filter((entry) => entry.type === "blob" && entry.path && entry.sha)
    .map((entry) => ({
      path: normalizeProjectPath(entry.path ?? ""),
      size: entry.size ?? 0,
      sha: entry.sha ?? "",
    }))
    .filter((entry) => shouldConsiderProjectPath(entry.path))
    .filter((entry) => entry.size <= maxBytesForProjectPath(entry.path, limits.maxFileSizeBytes) && !shouldSkipLargeLockfile(entry.path, entry.size))
    .sort((a, b) => compareProjectPathPriority(a.path, b.path))
  const candidates = supportedCandidates.slice(0, limits.maxFiles)

  const files: ProjectFile[] = []
  let totalTextBytes = 0
  let skippedByTotalSizeLimit = 0
  let skippedUnsupportedEncoding = 0
  const concurrency = Math.min(readPositiveInt(process.env.VIBESHIELD_GITHUB_BLOB_CONCURRENCY, 6), 10)

  for (let index = 0; index < candidates.length; index += concurrency) {
    const batch = candidates.slice(index, index + concurrency)
    const blobs = await Promise.all(batch.map((candidate) => getBlob(owner, repo, candidate.sha, token)))

    for (let batchIndex = 0; batchIndex < batch.length; batchIndex += 1) {
      const candidate = batch[batchIndex]
      const bytes = decodeBlob(blobs[batchIndex])
      if (!bytes) {
        skippedUnsupportedEncoding += 1
        continue
      }

      if (bytes.byteLength > maxBytesForProjectPath(candidate.path, limits.maxFileSizeBytes) || shouldSkipLargeLockfile(candidate.path, bytes.byteLength)) continue
      if (isProbablyBinary(bytes)) continue

      if (totalTextBytes + bytes.byteLength > limits.maxTotalSizeBytes) {
        skippedByTotalSizeLimit += 1
        continue
      }

      const text = decodeUtf8(bytes)
      if (text === null) continue
      totalTextBytes += bytes.byteLength
      files.push({ path: candidate.path, size: bytes.byteLength, text })
    }
  }

  return {
    files,
    supportedFiles: supportedCandidates.length,
    selectedFiles: candidates.length,
    skippedByFileLimit: Math.max(0, supportedCandidates.length - candidates.length),
    skippedByTotalSizeLimit,
    skippedUnsupportedEncoding,
    totalTextBytes,
  }
}

async function getBlob(owner: string, repo: string, sha: string, token?: string) {
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/blobs/${sha}`, token)
  return (await response.json()) as GitHubBlobApi
}

export function repositoryRefFromReport(report: ScanReport): ScanRepositoryRef | undefined {
  if (report.repository) return report.repository

  const match = report.sourceLabel.match(/^github\.com\/([^/#\s]+)\/([^/#\s]+)#([^#\s]+)$/)
  if (!match) return undefined
  if (!GITHUB_FULL_NAME_RE.test(`${match[1]}/${match[2]}`)) return undefined

  const normalized = normalizeRepoParts(match[1], match[2])
  const ref = sanitizeRef(match[3])
  return {
    owner: normalized.owner,
    repo: normalized.repo,
    ref,
    defaultBranch: ref,
    private: false,
    htmlUrl: `https://github.com/${normalized.owner}/${normalized.repo}`,
  }
}

export async function createRemediationPullRequest(input: {
  report: ScanReport
  token: string
}): Promise<ScanPullRequest> {
  const report = {
    ...input.report,
    findings: input.report.findings.filter((finding) => !finding.suppressed),
  }
  if (report.findings.length === 0) {
    throw new Error("Select at least one active finding before creating a PR.")
  }

  const repository = repositoryRefFromReport(report)
  if (!repository) {
    throw new Error("This report does not include enough GitHub repository metadata to create a PR.")
  }

  const owner = repository.owner
  const repo = repository.repo
  const base = sanitizeRef(repository.ref || repository.defaultBranch)
  const repositoryInfo = await getRepository(owner, repo, input.token)
  const baseSha = await getBranchHeadSha(owner, repo, base, input.token)
  const target = await resolvePullRequestTarget({
    owner,
    repo,
    token: input.token,
    repositoryInfo,
  })
  const branch = await createUniqueBranch(target.writeOwner, target.writeRepo, input.token, baseSha, report.id)
  const filesChanged: string[] = []
  const appliedFixes: string[] = []
  const skippedFixes = summarizeReviewRequiredFindings(report.findings)

  if (shouldApplyGitignoreHardening(report.findings)) {
    const gitignoreChanged = await hardenGitignore(target.writeOwner, target.writeRepo, branch, input.token)
    if (gitignoreChanged) {
      filesChanged.push(".gitignore")
      appliedFixes.push("Updated .gitignore because this scan selected a committed environment-file finding.")
    }
  }

  const envChanges = await removeCommittedEnvironmentFiles(target.writeOwner, target.writeRepo, branch, input.token, report)
  filesChanged.push(...envChanges.filesChanged)
  appliedFixes.push(...envChanges.appliedFixes)

  const reportPath = `.github/security-reports/static-analysis-${report.id}.md`
  const reportMarkdown = buildRemediationReportMarkdown(report, {
    branch,
    base,
    appliedFixes,
    skippedFixes,
    filesChanged: [...filesChanged, reportPath],
  })

  await putRepositoryFile({
    owner: target.writeOwner,
    repo: target.writeRepo,
    token: input.token,
    branch,
    path: reportPath,
    content: reportMarkdown,
    message: "Add static security review report",
  })
  filesChanged.push(reportPath)

  const pullRequest = await openPullRequest({
    owner,
    repo,
    token: input.token,
    branch,
    head: target.prHeadOwner ? `${target.prHeadOwner}:${branch}` : branch,
    base,
    title: "Add static security review report",
    body: buildPullRequestBody(report, {
      appliedFixes,
      skippedFixes,
      filesChanged,
      forkFullName: target.forkFullName,
    }),
  })

  return {
    url: pullRequest.html_url,
    number: pullRequest.number,
    branch: pullRequest.head.ref,
    base: pullRequest.base.ref,
    filesChanged,
    appliedFixes,
    skippedFixes,
    createdAt: new Date().toISOString(),
  }
}

async function getBranchHeadSha(owner: string, repo: string, ref: string, token: string) {
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/ref/heads/${encodeGitHubPath(ref)}`, token)
  const data = (await response.json()) as GitHubRefApi
  const sha = data.object?.sha
  if (!sha) throw new Error("GitHub branch head could not be resolved.")
  return sha
}

async function resolvePullRequestTarget(input: {
  owner: string
  repo: string
  token: string
  repositoryInfo: GitHubRepoApi
}) {
  if (canPushToRepository(input.repositoryInfo)) {
    return {
      writeOwner: input.owner,
      writeRepo: input.repo,
      prHeadOwner: undefined,
      forkFullName: undefined,
    }
  }

  if (input.repositoryInfo.private) {
    throw new Error("GitHub token does not have permission to push a branch to this private repository.")
  }

  const fork = await ensureUserFork(input.owner, input.repo, input.token)
  const [forkOwner, forkRepo] = fork.full_name.split("/")
  if (!forkOwner || !forkRepo) {
    throw new Error("GitHub fork metadata was incomplete.")
  }

  return {
    writeOwner: forkOwner,
    writeRepo: forkRepo,
    prHeadOwner: forkOwner,
    forkFullName: fork.full_name,
  }
}

function canPushToRepository(repository: GitHubRepoApi) {
  if (!repository.permissions) return false
  return Boolean(repository.permissions.push || repository.permissions.admin || repository.permissions.maintain)
}

async function ensureUserFork(owner: string, repo: string, token: string): Promise<GitHubRepoApi> {
  const user = await getAuthenticatedGitHubUser(token)
  const existing = await getExistingUserFork(owner, repo, user.login, token)
  if (existing) return existing

  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/forks`, token, {
    method: "POST",
    body: JSON.stringify({}),
  })
  const fork = (await response.json()) as GitHubRepoApi
  const forkFullName = fork.full_name || `${user.login}/${repo}`
  return waitForForkRepository(forkFullName, token)
}

async function getAuthenticatedGitHubUser(token: string) {
  const response = await githubFetch(`${GITHUB_API}/user`, token)
  const data = (await response.json()) as GitHubUserApi
  if (!data.login) throw new Error("GitHub user could not be resolved for fork creation.")
  return { login: data.login }
}

async function getExistingUserFork(owner: string, repo: string, userLogin: string, token: string) {
  try {
    const candidate = await getRepository(userLogin, repo, token)
    const sourceFullName = candidate.source?.full_name ?? candidate.parent?.full_name
    if (sourceFullName?.toLowerCase() === `${owner}/${repo}`.toLowerCase()) return candidate
    return null
  } catch (error) {
    if (isGitHubNotFoundError(error)) return null
    throw error
  }
}

async function waitForForkRepository(fullName: string, token: string) {
  const [owner, repo] = fullName.split("/")
  if (!owner || !repo) throw new Error("GitHub fork metadata was incomplete.")

  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      return await getRepository(owner, repo, token)
    } catch (error) {
      if (!isGitHubNotFoundError(error) || attempt === 7) throw error
      await sleep(750 + attempt * 500)
    }
  }

  throw new Error("GitHub fork was created but was not ready yet. Retry creating the PR in a moment.")
}

async function createUniqueBranch(owner: string, repo: string, token: string, baseSha: string, scanId: string) {
  const prefix = `security/review-${scanId.slice(0, 8)}`

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const branch = attempt === 0 ? prefix : `${prefix}-${attempt + 1}`
    try {
      await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/refs`, token, {
        method: "POST",
        body: JSON.stringify({
          ref: `refs/heads/${branch}`,
          sha: baseSha,
        }),
      })
      return branch
    } catch (error) {
      if (isGitHubValidationError(error)) continue
      throw error
    }
  }

  throw new Error("Could not create a unique security review branch in this repository.")
}

async function hardenGitignore(owner: string, repo: string, branch: string, token: string) {
  const existing = await getRepositoryContentFile(owner, repo, ".gitignore", branch, token)
  const current = existing ? decodeContentFile(existing) : ""
  const next = withRequiredGitignoreLines(current)
  if (next === current) return false

  await putRepositoryFile({
    owner,
    repo,
    token,
    branch,
    path: ".gitignore",
    content: next,
    sha: existing?.sha,
    message: "Harden environment file ignores",
  })

  return true
}

async function removeCommittedEnvironmentFiles(owner: string, repo: string, branch: string, token: string, report: ScanReport) {
  const envPaths = committedEnvironmentFindingPaths(report.findings)
  const filesChanged: string[] = []
  const appliedFixes: string[] = []
  const examplesByPath = new Map<string, Set<string>>()

  for (const envPath of envPaths) {
    const existing = await getRepositoryContentFile(owner, repo, envPath, branch, token)
    if (!existing?.sha) continue

    const envText = decodeContentFile(existing)
    const examplePath = examplePathForEnvPath(envPath)
    const envKeys = extractEnvExampleKeys(envText)
    if (envKeys.length > 0) {
      const keys = examplesByPath.get(examplePath) ?? new Set<string>()
      for (const key of envKeys) keys.add(key)
      examplesByPath.set(examplePath, keys)
    }

    await deleteRepositoryFile({
      owner,
      repo,
      token,
      branch,
      path: envPath,
      sha: existing.sha,
      message: `Remove committed environment file ${envPath}`,
    })

    filesChanged.push(envPath)
    appliedFixes.push(`Removed committed environment file ${envPath}. Rotate any real credentials that were ever committed.`)
  }

  for (const [examplePath, keys] of examplesByPath) {
    const changed = await mergeEnvExample(owner, repo, branch, token, examplePath, [...keys].sort())
    if (changed) {
      filesChanged.push(examplePath)
      appliedFixes.push(`Added redacted placeholders to ${examplePath}.`)
    }
  }

  return { filesChanged, appliedFixes }
}

async function mergeEnvExample(owner: string, repo: string, branch: string, token: string, path: string, keys: string[]) {
  const existing = await getRepositoryContentFile(owner, repo, path, branch, token)
  const current = existing ? decodeContentFile(existing) : ""
  const currentKeys = new Set(
    current
      .split(/\r?\n/)
      .map((line) => line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)?.[1])
      .filter(Boolean) as string[],
  )
  const missing = keys.filter((key) => !currentKeys.has(key))
  if (missing.length === 0) return false

  const separator = current.trim().length > 0 ? "\n\n" : ""
  const next = `${current.replace(/\s*$/, "")}${separator}# Added by security review. Values intentionally omitted.\n${missing
    .map((key) => `${key}=`)
    .join("\n")}\n`

  await putRepositoryFile({
    owner,
    repo,
    token,
    branch,
    path,
    content: next,
    sha: existing?.sha,
    message: `Add redacted environment example ${path}`,
  })

  return true
}

async function getRepositoryContentFile(owner: string, repo: string, path: string, ref: string, token: string) {
  try {
    const response = await githubFetch(
      `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeGitHubPath(path)}?ref=${encodeURIComponent(ref)}`,
      token,
    )
    const data = (await response.json()) as GitHubContentFileApi | GitHubContentFileApi[]
    if (Array.isArray(data) || data.type !== "file") return null
    return data
  } catch (error) {
    if (isGitHubNotFoundError(error)) return null
    throw error
  }
}

async function putRepositoryFile(input: {
  owner: string
  repo: string
  token: string
  branch: string
  path: string
  content: string
  message: string
  sha?: string
}) {
  await githubFetch(`${GITHUB_API}/repos/${input.owner}/${input.repo}/contents/${encodeGitHubPath(input.path)}`, input.token, {
    method: "PUT",
    body: JSON.stringify({
      message: input.message,
      content: Buffer.from(input.content, "utf8").toString("base64"),
      branch: input.branch,
      ...(input.sha ? { sha: input.sha } : {}),
    }),
  })
}

async function deleteRepositoryFile(input: {
  owner: string
  repo: string
  token: string
  branch: string
  path: string
  sha: string
  message: string
}) {
  await githubFetch(`${GITHUB_API}/repos/${input.owner}/${input.repo}/contents/${encodeGitHubPath(input.path)}`, input.token, {
    method: "DELETE",
    body: JSON.stringify({
      message: input.message,
      sha: input.sha,
      branch: input.branch,
    }),
  })
}

async function openPullRequest(input: {
  owner: string
  repo: string
  token: string
  branch: string
  head?: string
  base: string
  title: string
  body: string
}) {
  const response = await githubFetch(`${GITHUB_API}/repos/${input.owner}/${input.repo}/pulls`, input.token, {
    method: "POST",
    body: JSON.stringify({
      title: input.title.slice(0, 240),
      head: input.head ?? input.branch,
      base: input.base,
      body: input.body.slice(0, 60_000),
      draft: false,
    }),
  })
  return (await response.json()) as GitHubPullRequestApi
}

async function githubFetch(url: string, token?: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers)
  headers.set("Accept", "application/vnd.github+json")
  headers.set("User-Agent", "StaticSecurityReview")
  headers.set("X-GitHub-Api-Version", "2022-11-28")
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  if (token) headers.set("Authorization", `Bearer ${token}`)

  const maxRetries = Math.min(readPositiveInt(process.env.VIBESHIELD_GITHUB_FETCH_RETRIES, DEFAULT_GITHUB_FETCH_RETRIES), 5)
  const baseDelayMs = readPositiveInt(process.env.VIBESHIELD_GITHUB_RETRY_DELAY_MS, DEFAULT_GITHUB_RETRY_DELAY_MS)

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    let response: Response
    try {
      response = await fetch(url, {
        ...init,
        headers,
        cache: "no-store",
      })
    } catch {
      if (attempt < maxRetries) {
        await sleep(githubRetryDelayMs(attempt, baseDelayMs))
        continue
      }

      throw new GitHubApiError(
        "GitHub could not be reached while reading the repository. Retry the scan in a moment.",
        502,
        "github_network_failed",
      )
    }

    if (response.ok) return response

    if (shouldRetryGitHubResponse(response, attempt, maxRetries)) {
      await response.body?.cancel().catch(() => undefined)
      await sleep(githubRetryDelayMs(attempt, baseDelayMs))
      continue
    }

    await throwGitHubResponseError(response)
  }

  throw new GitHubApiError(
    "GitHub is temporarily unavailable while reading this repository. Retry the scan in a moment.",
    502,
    "github_temporarily_unavailable",
  )
}

function getLocalGitHubToken() {
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") return undefined

  const explicit = process.env.VIBESHIELD_ALLOW_LOCAL_GITHUB_TOKEN?.trim().toLowerCase()
  const localAllowed = explicit !== "false"
  if (!localAllowed) return undefined

  return (
    process.env.VIBESHIELD_GITHUB_TOKEN?.trim() ||
    process.env.GITHUB_TOKEN?.trim() ||
    process.env.GH_TOKEN?.trim() ||
    undefined
  )
}

function withRequiredGitignoreLines(current: string) {
  const required = [".env", ".env.*", ".env*.local", "!.env.example"]
  const existing = new Set(
    current
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#")),
  )
  const missing = required.filter((line) => !existing.has(line))
  if (missing.length === 0) return current

  const prefix = current.trim().length > 0 ? `${current.replace(/\s*$/, "")}\n\n` : ""
  return `${prefix}# Keep local secrets out of git\n${missing.join("\n")}\n`
}

function committedEnvironmentFindingPaths(findings: ScanFinding[]) {
  const envNames = new Set([".env", ".env.local", ".env.production", ".env.development"])
  const paths = new Set<string>()

  for (const finding of findings) {
    if (finding.category !== "secret_exposure" && finding.category !== "public_env_misuse") continue
    const name = finding.filePath.split("/").pop() ?? finding.filePath
    if (envNames.has(name)) paths.add(finding.filePath)
  }

  return [...paths].sort()
}

function examplePathForEnvPath(path: string) {
  const parts = path.split("/")
  parts[parts.length - 1] = ".env.example"
  return parts.join("/")
}

function extractEnvExampleKeys(text: string) {
  const keys = new Set<string>()
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)
    if (match) keys.add(match[1])
  }
  return [...keys]
}

function decodeContentFile(file: GitHubContentFileApi) {
  if (file.encoding !== "base64" || !file.content) return ""
  return Buffer.from(file.content.replace(/\s/g, ""), "base64").toString("utf8")
}

function buildRemediationReportMarkdown(
  report: ScanReport,
  pr: {
    branch: string
    base: string
    filesChanged: string[]
    appliedFixes: string[]
    skippedFixes: string[]
  },
) {
  return [
    "# Static security review report",
    "",
    "This report was generated from static repository analysis. It is intended for maintainer review and does not claim that every finding has been automatically fixed.",
    "",
    "## Scan metadata",
    "",
    `- Project: \`${report.projectName}\``,
    `- Source: \`${report.sourceLabel}\``,
    `- Scan ID: \`${report.id}\``,
    `- Mode: \`${report.analysisMode ?? "unknown"}\``,
    `- Risk score: **${report.riskScore}/100**`,
    `- Findings included: **${report.findings.length}**`,
    `- Files inspected: **${report.filesInspected}**`,
    `- Baseline: **${formatPullRequestBaseline(report)}**`,
    "",
    ...formatPullRequestRiskBreakdown(report),
    "## Findings requiring review",
    "",
    ...formatPullRequestFindings(report),
    "",
    "## GitHub PR follow-up",
    "",
    `**Branch:** \`${pr.branch}\``,
    `**Base:** \`${pr.base}\``,
    "",
    "### Low-risk changes applied",
    "",
    ...(pr.appliedFixes.length > 0 ? pr.appliedFixes.map((item) => `- ${item}`) : ["- No code files were changed automatically."]),
    "",
    "### Files changed",
    "",
    ...pr.filesChanged.map((file) => `- \`${file}\``),
    "",
    "### Findings requiring human review",
    "",
    ...(pr.skippedFixes.length > 0 ? pr.skippedFixes.map((item) => `- ${item}`) : ["- No selected findings require additional manual notes in this PR."]),
    "",
    "## Review policy",
    "",
    "- This pull request does not include speculative code patches.",
    "- Architecture-sensitive findings, including auth, rate limits, agent tools, MCP, CI permissions, and supply-chain posture, remain maintainer-reviewed.",
    "- Local-only report links are intentionally omitted because public maintainers cannot open them.",
    "",
    "_Generated from static security analysis._",
    "",
  ].join("\n")
}

function buildPullRequestBody(
  report: ScanReport,
  pr: {
    filesChanged: string[]
    appliedFixes: string[]
    skippedFixes: string[]
    forkFullName?: string
  },
) {
  return [
    "## Summary",
    "",
    `This PR adds a static security review report for \`${report.sourceLabel}\` and applies only low-risk repository hygiene changes when available.`,
    "",
    "It does not claim to fully remediate every finding. Items that require product, auth, rate-limit, agent, MCP, or CI policy decisions are listed for human review.",
    "",
    "## Scan metadata",
    "",
    `- Risk score: **${report.riskScore}/100**`,
    `- Findings included: **${report.findings.length}**`,
    `- Baseline: **${formatPullRequestBaseline(report)}**`,
    ...(pr.forkFullName ? [`- Head fork: \`${pr.forkFullName}\``] : []),
    "",
    "## Changes in this PR",
    "",
    ...(pr.appliedFixes.length > 0 ? pr.appliedFixes.map((item) => `- ${item}`) : ["- No safe automatic code changes were available for this report."]),
    "",
    "## Files changed",
    "",
    ...pr.filesChanged.map((file) => `- \`${file}\``),
    "",
    "## Findings requiring review",
    "",
    ...(pr.skippedFixes.length > 0 ? pr.skippedFixes.map((item) => `- ${item}`) : ["- No selected findings require additional manual notes in this PR."]),
    "",
    "## Notes",
    "",
    "- The full review report is included under `.github/security-reports/`.",
    "- This is a report-first pull request. It does not include speculative or placeholder fixes.",
    "- Placeholder fixes that could break production behavior are intentionally avoided.",
    "- Review all security-sensitive changes before merging.",
  ].join("\n")
}

function formatPullRequestBaseline(report: ScanReport) {
  const summary = report.baselineSummary
  if (!summary) return "no saved baseline"
  return `${summary.new} new / ${summary.existing} existing / ${summary.resolved} resolved / ${summary.suppressed} suppressed`
}

function summarizeReviewRequiredFindings(reportFindings: ScanFinding[]) {
  return reportFindings
    .filter((finding) => !finding.suppressed)
    .slice(0, 12)
    .map(
      (finding) =>
        `${finding.id} ${finding.title} in ${formatFindingLocation(finding)} is review-required; no automatic code change was applied for it.`,
    )
}

function shouldApplyGitignoreHardening(findings: ScanFinding[]) {
  return findings.some((finding) => {
    if (finding.suppressed || finding.category !== "secret_exposure") return false
    if (!isCommittedEnvironmentPath(finding.filePath)) return false
    return /committed environment file|environment file detected/i.test(`${finding.title}\n${finding.description}\n${finding.recommendation}`)
  })
}

function isCommittedEnvironmentPath(filePath: string) {
  const name = filePath.split("/").pop() ?? filePath
  return /^\.env(?:$|\.|-)/.test(name)
}

function formatPullRequestRiskBreakdown(report: ScanReport) {
  const breakdown = report.riskBreakdown
  if (!breakdown) return []
  return [
    "## Risk breakdown",
    "",
    `- Runtime / agent risk: **${breakdown.runtimeAgentRisk.label}** (${breakdown.runtimeAgentRisk.score}/100)`,
    `- CI / supply-chain posture: **${breakdown.repoPostureRisk.label}** (${breakdown.repoPostureRisk.score}/100)`,
    `- Dependency risk: **${breakdown.dependencyRisk.label}** (${breakdown.dependencyRisk.score}/100)`,
    `- Secrets risk: **${breakdown.secretsRisk.label}** (${breakdown.secretsRisk.score}/100)`,
    "",
  ]
}

function formatPullRequestFindings(report: ScanReport) {
  const findings = [...report.findings].sort(compareFindingsForPullRequest).slice(0, 20)
  if (findings.length === 0) return ["No active findings were selected for this pull request.", ""]

  return findings.flatMap((finding, index) => [
    `### ${index + 1}. ${finding.title}`,
    "",
    `- Severity: \`${finding.severity}\``,
    `- Category: \`${finding.category}\``,
    `- Rule: \`${finding.ruleId ?? "unknown"}\``,
    `- Location: \`${formatFindingLocation(finding)}\``,
    `- Confidence: ${Math.round(finding.confidence * 100)}%${finding.confidenceReason ? ` - ${finding.confidenceReason}` : ""}`,
    `- Recommendation: ${finding.recommendation}`,
    ...(finding.evidence ? [`- Evidence: \`${finding.evidence}\``] : []),
    "",
  ])
}

function compareFindingsForPullRequest(a: ScanFinding, b: ScanFinding) {
  const severityDelta = severityRank(b.severity) - severityRank(a.severity)
  if (severityDelta !== 0) return severityDelta
  return b.confidence - a.confidence
}

function severityRank(severity: ScanFinding["severity"]) {
  switch (severity) {
    case "critical":
      return 5
    case "high":
      return 4
    case "medium":
      return 3
    case "low":
      return 2
    case "info":
      return 1
    default:
      return 0
  }
}

function formatFindingLocation(finding: ScanFinding) {
  return finding.lineStart ? `${finding.filePath}:${finding.lineStart}` : finding.filePath
}

function encodeGitHubPath(path: string) {
  return path.split("/").map(encodeURIComponent).join("/")
}

function isGitHubNotFoundError(error: unknown) {
  return error instanceof GitHubApiError && error.code === "github_not_found"
}

function isGitHubValidationError(error: unknown) {
  return error instanceof GitHubApiError && error.code === "github_validation_failed"
}

function shouldRetryGitHubResponse(response: Response, attempt: number, maxRetries: number) {
  if (attempt >= maxRetries) return false
  if (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0") return false
  return RETRYABLE_GITHUB_STATUSES.has(response.status)
}

async function throwGitHubResponseError(response: Response): Promise<never> {
  const details = await response.text().catch(() => "")
  const message = extractGitHubErrorMessage(details)

  if (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0") {
    throw new GitHubApiError(
      "GitHub public API rate limit exceeded. In local development, login with GitHub or set VIBESHIELD_GITHUB_TOKEN in .env.local.",
      response.status,
      "github_rate_limited",
    )
  }

  if (response.status === 401 || response.status === 403) throw new Error("GitHub authorization failed.")
  if (response.status === 404) throw new GitHubApiError("GitHub repository or file was not found.", response.status, "github_not_found")
  if (response.status === 422) {
    throw new GitHubApiError(`GitHub API validation failed${message ? `: ${message}` : ""}.`, response.status, "github_validation_failed")
  }
  if (RETRYABLE_GITHUB_STATUSES.has(response.status)) {
    throw new GitHubApiError(
      "GitHub is temporarily unavailable while reading this repository. Retry the scan in a moment.",
      502,
      "github_temporarily_unavailable",
    )
  }

  throw new Error(`GitHub API request failed with status ${response.status}${message ? `: ${message}` : ""}.`)
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

function decodeBlob(blob: GitHubBlobApi) {
  if (!blob.content) return null
  if (blob.encoding === "base64") return Buffer.from(blob.content.replace(/\s/g, ""), "base64")
  if (blob.encoding === "utf-8") return Buffer.from(blob.content, "utf8")

  return null
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

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function githubRetryDelayMs(attempt: number, baseDelayMs: number) {
  return baseDelayMs * 2 ** attempt
}

function extractGitHubErrorMessage(raw: string) {
  if (!raw) return ""
  if (looksLikeHtml(raw)) return ""
  try {
    const parsed = JSON.parse(raw) as { message?: unknown }
    return typeof parsed.message === "string" ? parsed.message.replace(/\s+/g, " ").slice(0, 220) : ""
  } catch {
    return raw.replace(/\s+/g, " ").slice(0, 220)
  }
}

function looksLikeHtml(raw: string) {
  const trimmed = raw.trimStart().slice(0, 120).toLowerCase()
  return trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html") || trimmed.includes("<body")
}
