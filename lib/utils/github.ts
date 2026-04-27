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
import { generateIssueBody } from "@/lib/scanner/patches"
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

const GITHUB_API = "https://api.github.com"
const GITHUB_REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})(?:\.git)?\/?$/
const GITHUB_FULL_NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/

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
  const files = await fetchProjectFiles(owner, repo, tree, input.token, limits)

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
        totalTextBytes: files.reduce((total, file) => total + file.size, 0),
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
  const concurrency = Math.min(readPositiveInt(process.env.VIBESHIELD_GITHUB_BLOB_CONCURRENCY, 6), 10)

  for (let index = 0; index < candidates.length; index += concurrency) {
    const batch = candidates.slice(index, index + concurrency)
    const blobs = await Promise.all(batch.map((candidate) => getBlob(owner, repo, candidate.sha, token)))

    for (let batchIndex = 0; batchIndex < batch.length; batchIndex += 1) {
      const candidate = batch[batchIndex]
      const bytes = decodeBlob(blobs[batchIndex])

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
  }

  return files
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
  const repository = repositoryRefFromReport(input.report)
  if (!repository) {
    throw new Error("This report does not include enough GitHub repository metadata to create a PR.")
  }

  const owner = repository.owner
  const repo = repository.repo
  const base = sanitizeRef(repository.ref || repository.defaultBranch)
  const repositoryInfo = await getRepository(owner, repo, input.token)

  if (repositoryInfo.permissions && !repositoryInfo.permissions.push && !repositoryInfo.permissions.admin && !repositoryInfo.permissions.maintain) {
    throw new Error("GitHub token does not have permission to push a branch to this repository.")
  }

  const baseSha = await getBranchHeadSha(owner, repo, base, input.token)
  const branch = await createUniqueBranch(owner, repo, input.token, baseSha, input.report.id)
  const filesChanged: string[] = []
  const appliedFixes: string[] = []
  const skippedFixes = summarizeReviewRequiredFindings(input.report.findings)

  const gitignoreChanged = await hardenGitignore(owner, repo, branch, input.token)
  if (gitignoreChanged) {
    filesChanged.push(".gitignore")
    appliedFixes.push("Updated .gitignore so local environment files stay out of future commits.")
  }

  const envChanges = await removeCommittedEnvironmentFiles(owner, repo, branch, input.token, input.report)
  filesChanged.push(...envChanges.filesChanged)
  appliedFixes.push(...envChanges.appliedFixes)

  const reportPath = `.github/vibeshield/security-scan-${input.report.id}.md`
  const reportMarkdown = buildRemediationReportMarkdown(input.report, {
    branch,
    base,
    appliedFixes,
    skippedFixes,
    filesChanged: [...filesChanged, reportPath],
  })

  await putRepositoryFile({
    owner,
    repo,
    token: input.token,
    branch,
    path: reportPath,
    content: reportMarkdown,
    message: "Add VibeShield security remediation report",
  })
  filesChanged.push(reportPath)

  const pullRequest = await openPullRequest({
    owner,
    repo,
    token: input.token,
    branch,
    base,
    title: `VibeShield security remediation for ${input.report.projectName}`,
    body: buildPullRequestBody(input.report, {
      appliedFixes,
      skippedFixes,
      filesChanged,
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

async function createUniqueBranch(owner: string, repo: string, token: string, baseSha: string, scanId: string) {
  const prefix = `vibeshield/scan-${scanId.slice(0, 8)}`

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

  throw new Error("Could not create a unique VibeShield branch in this repository.")
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
  const next = `${current.replace(/\s*$/, "")}${separator}# Added by VibeShield. Values intentionally omitted.\n${missing
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
  base: string
  title: string
  body: string
}) {
  const response = await githubFetch(`${GITHUB_API}/repos/${input.owner}/${input.repo}/pulls`, input.token, {
    method: "POST",
    body: JSON.stringify({
      title: input.title.slice(0, 240),
      head: input.branch,
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
  headers.set("User-Agent", "VibeShield")
  headers.set("X-GitHub-Api-Version", "2022-11-28")
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  if (token) headers.set("Authorization", `Bearer ${token}`)

  const response = await fetch(url, {
    ...init,
    headers,
    cache: "no-store",
  })

  if (!response.ok) {
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
    throw new Error(`GitHub API request failed with status ${response.status}${message ? `: ${message}` : ""}.`)
  }

  return response
}

function getLocalGitHubToken() {
  if (process.env.VERCEL === "1") return undefined

  const explicit = process.env.VIBESHIELD_ALLOW_LOCAL_GITHUB_TOKEN?.trim().toLowerCase()
  const localAllowed = explicit === "true" || (explicit !== "false" && process.env.NODE_ENV !== "production")
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
  return `${prefix}# VibeShield: keep local secrets out of git\n${missing.join("\n")}\n`
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
  const patchPreviews = report.findings
    .filter((finding) => finding.patch)
    .slice(0, 12)
    .flatMap((finding) => [
      `### ${finding.id} - ${finding.title}`,
      "",
      `- Severity: \`${finding.severity}\``,
      `- Category: \`${finding.category}\``,
      `- File: \`${formatFindingLocation(finding)}\``,
      `- Recommendation: ${finding.recommendation}`,
      `- Patch preview: ${finding.patch?.summary ?? "No patch preview available."}`,
      "",
      finding.patch?.unifiedDiff ? `\`\`\`diff\n${finding.patch.unifiedDiff.slice(0, 2500)}\n\`\`\`\n` : "",
    ])

  return [
    generateIssueBody(report),
    "",
    "## GitHub PR remediation",
    "",
    `**Branch:** \`${pr.branch}\``,
    `**Base:** \`${pr.base}\``,
    "",
    "### Applied automatically",
    "",
    ...(pr.appliedFixes.length > 0 ? pr.appliedFixes.map((item) => `- ${item}`) : ["- No code files were changed automatically."]),
    "",
    "### Files changed by this PR",
    "",
    ...pr.filesChanged.map((file) => `- \`${file}\``),
    "",
    "### Review-required fixes",
    "",
    ...pr.skippedFixes.map((item) => `- ${item}`),
    "",
    "## Patch previews",
    "",
    ...(patchPreviews.length > 0 ? patchPreviews : ["No patch previews were generated for this scan."]),
    "",
    "_VibeShield only applies low-risk repository hygiene automatically. Auth, rate-limit, validation and tool-calling fixes remain review-required because they depend on the target app architecture._",
    "",
  ].join("\n")
}

function buildPullRequestBody(
  report: ScanReport,
  pr: {
    filesChanged: string[]
    appliedFixes: string[]
    skippedFixes: string[]
  },
) {
  return [
    `VibeShield scanned \`${report.sourceLabel}\` and opened this remediation PR.`,
    "",
    `Risk score: **${report.riskScore}/100**`,
    `Findings: **${report.findings.length}**`,
    "",
    "## Applied automatically",
    "",
    ...(pr.appliedFixes.length > 0 ? pr.appliedFixes.map((item) => `- ${item}`) : ["- No safe automatic code changes were available for this report."]),
    "",
    "## Files changed",
    "",
    ...pr.filesChanged.map((file) => `- \`${file}\``),
    "",
    "## Still needs review",
    "",
    ...pr.skippedFixes.map((item) => `- ${item}`),
    "",
    "VibeShield intentionally does not insert placeholder auth or rate-limit code that could break production. The full report and patch previews are included in `.github/vibeshield/`.",
  ].join("\n")
}

function summarizeReviewRequiredFindings(reportFindings: ScanFinding[]) {
  return reportFindings
    .filter((finding) => finding.patchable)
    .slice(0, 12)
    .map((finding) => `${finding.id} ${finding.title} in ${formatFindingLocation(finding)} requires project-specific review.`)
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

function extractGitHubErrorMessage(raw: string) {
  if (!raw) return ""
  try {
    const parsed = JSON.parse(raw) as { message?: unknown }
    return typeof parsed.message === "string" ? parsed.message.replace(/\s+/g, " ").slice(0, 220) : ""
  } catch {
    return raw.replace(/\s+/g, " ").slice(0, 220)
  }
}
