import { gunzipSync } from "node:zlib"
import { auditEvent } from "@/lib/scanner/scan"
import { generateProfessionalPullRequestCopy } from "@/lib/ai/pullRequestCopy"
import { reviewPullRequestWithClaude, type PullRequestSafetyChangedFile } from "@/lib/ai/reviewPullRequest"
import { sanitizePublicPullRequestCopy } from "@/lib/ai/publicPullRequestCopy"
import { badgerEnv } from "@/lib/config/env"
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
import {
  createDefaultGitHubAppInstallationToken,
  isGitHubAppInstallationConfigured,
} from "@/lib/utils/github-app"
import {
  pinThirdPartyActionRefsInText,
  type ActionRef,
} from "@/lib/utils/githubActions"
import { formatGitHubNotFoundMessage } from "@/lib/utils/githubErrors"
import {
  buildProfessionalPullRequestBody,
  buildProfessionalPullRequestTitle,
  formatPinnedActionFix,
  shouldAttachReviewNotesFileToPullRequest,
} from "@/lib/utils/pullRequestDraft"
import { isSafePullRequestFinding } from "@/lib/utils/prSafety"
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

type ReviewBranch = {
  name: string
  created: boolean
}

type GitHubUserApi = {
  login?: string
}

const GITHUB_API = "https://api.github.com"
const GITHUB_CODELOAD = "https://codeload.github.com"
const GITHUB_REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})(?:\.git)?\/?$/
const GITHUB_FULL_NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/
const RETRYABLE_GITHUB_STATUSES = new Set([408, 500, 502, 503, 504])
const DEFAULT_GITHUB_FETCH_RETRIES = 2
const DEFAULT_GITHUB_RETRY_DELAY_MS = 450
const DEFAULT_CODELOAD_MAX_ARCHIVE_BYTES = 50_000_000
const DEFAULT_CODELOAD_MAX_TAR_BYTES = 160_000_000

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

export async function getPublicGitHubReadTokenFromRequest(request: Request) {
  return getGitHubSessionFromHeaders(request.headers)?.token ?? await getServerGitHubReadToken()
}

export function isGitHubApiError(error: unknown): error is GitHubApiError {
  return error instanceof GitHubApiError
}

export async function listAuthenticatedGitHubRepos(token: string): Promise<GitHubRepositorySummary[]> {
  const maxPages = readPositiveInt(badgerEnv("GITHUB_REPO_LIST_MAX_PAGES"), 5)
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
  try {
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
  } catch (error) {
    if (shouldUsePublicArchiveFallback(error, input.token)) {
      return extractProjectFromPublicGitHubArchive({ owner, repo, ref: input.ref, limits })
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
  const concurrency = Math.min(readPositiveInt(badgerEnv("GITHUB_BLOB_CONCURRENCY"), 6), 10)

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

function shouldUsePublicArchiveFallback(error: unknown, token: string | undefined) {
  if (token) return false
  if (badgerEnv("GITHUB_CODELOAD_FALLBACK") === "false") return false
  return error instanceof GitHubApiError && error.code === "github_rate_limited"
}

async function extractProjectFromPublicGitHubArchive(input: {
  owner: string
  repo: string
  ref?: string
  limits: ScannerLimits
}): Promise<ExtractedProject & { sourceLabel: string; private: boolean; defaultBranch: string; ref: string; htmlUrl: string }> {
  const refCandidates = input.ref ? [sanitizeRef(input.ref)] : ["HEAD", "main", "master"]
  const attempted: string[] = []
  let lastError: unknown

  for (const candidateRef of refCandidates) {
    try {
      const archive = await fetchPublicGitHubTarball(input.owner, input.repo, candidateRef)
      const fetchResult = extractProjectFilesFromTarball(archive, input.limits)

      if (fetchResult.files.length === 0) {
        throw new Error("No supported text files were found in the GitHub repository archive.")
      }

      return {
        projectName: input.repo,
        sourceLabel: `github.com/${input.owner}/${input.repo}#${candidateRef}`,
        private: false,
        defaultBranch: candidateRef,
        ref: candidateRef,
        htmlUrl: `https://github.com/${input.owner}/${input.repo}`,
        files: fetchResult.files,
        auditTrail: [
          auditEvent("Connect to public GitHub archive", "complete", {
            repository: `${input.owner}/${input.repo}`,
            private: false,
            ref: candidateRef,
            fallback: "codeload",
          }),
          auditEvent("Fetch public repository tarball", "complete", {
            source: "github-codeload",
            compressedBytes: archive.length,
          }),
          auditEvent("Extract supported files from public archive", "complete", {
            files: fetchResult.files.length,
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
    } catch (error) {
      attempted.push(candidateRef)
      lastError = error
    }
  }

  if (lastError instanceof GitHubApiError) throw lastError
  throw new GitHubApiError(
    `GitHub public archive could not be read for ${input.owner}/${input.repo} (${attempted.join(", ")}). Sign in with GitHub or try a specific branch.`,
    502,
    "github_archive_unavailable",
  )
}

async function fetchPublicGitHubTarball(owner: string, repo: string, ref: string) {
  const response = await fetch(`${GITHUB_CODELOAD}/${owner}/${repo}/tar.gz/${encodeGitHubRefPath(ref)}`, {
    headers: {
      Accept: "application/x-gzip",
      "User-Agent": "BadgerSecurityReview",
    },
    cache: "no-store",
  })

  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined)
    if (response.status === 404) {
      throw new GitHubApiError(
        "GitHub repository archive was not found. Confirm this is a public repository, or sign in with GitHub for private access.",
        404,
        "github_archive_not_found",
      )
    }
    if (response.status === 403 || response.status === 429) {
      throw new GitHubApiError(
        "GitHub public archive downloads are temporarily limited. Sign in with GitHub or try again in a few minutes.",
        response.status,
        "github_archive_rate_limited",
      )
    }
    throw new GitHubApiError(
      `GitHub public archive download failed with status ${response.status}.`,
      response.status,
      "github_archive_failed",
    )
  }

  const maxArchiveBytes = readPositiveInt(badgerEnv("GITHUB_CODELOAD_MAX_ARCHIVE_BYTES"), DEFAULT_CODELOAD_MAX_ARCHIVE_BYTES)
  return readResponseBufferWithLimit(response, maxArchiveBytes)
}

function extractProjectFilesFromTarball(archive: Buffer, limits: ScannerLimits) {
  const maxTarBytes = readPositiveInt(badgerEnv("GITHUB_CODELOAD_MAX_TAR_BYTES"), DEFAULT_CODELOAD_MAX_TAR_BYTES)
  const tarball = gunzipSync(archive, { maxOutputLength: maxTarBytes })
  const supportedCandidates = readTarEntries(tarball)
    .filter((entry) => shouldConsiderProjectPath(entry.path))
    .filter((entry) => entry.bytes.byteLength <= maxBytesForProjectPath(entry.path, limits.maxFileSizeBytes) && !shouldSkipLargeLockfile(entry.path, entry.bytes.byteLength))
    .sort((a, b) => compareProjectPathPriority(a.path, b.path))
  const candidates = supportedCandidates.slice(0, limits.maxFiles)
  const files: ProjectFile[] = []
  let totalTextBytes = 0
  let skippedByTotalSizeLimit = 0
  let skippedUnsupportedEncoding = 0

  for (const candidate of candidates) {
    const bytes = candidate.bytes
    if (isProbablyBinary(bytes)) continue
    if (totalTextBytes + bytes.byteLength > limits.maxTotalSizeBytes) {
      skippedByTotalSizeLimit += 1
      continue
    }

    const text = decodeUtf8(bytes)
    if (text === null) {
      skippedUnsupportedEncoding += 1
      continue
    }

    totalTextBytes += bytes.byteLength
    files.push({ path: candidate.path, size: bytes.byteLength, text })
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

async function readResponseBufferWithLimit(response: Response, maxBytes: number) {
  const contentLength = Number(response.headers.get("content-length"))
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    await response.body?.cancel().catch(() => undefined)
    throw new GitHubApiError(
      "GitHub repository archive is too large for guest scanning. Sign in with GitHub or scan a smaller repository.",
      413,
      "github_archive_too_large",
    )
  }

  if (!response.body) {
    const bytes = Buffer.from(await response.arrayBuffer())
    if (bytes.byteLength > maxBytes) {
      throw new GitHubApiError(
        "GitHub repository archive is too large for guest scanning. Sign in with GitHub or scan a smaller repository.",
        413,
        "github_archive_too_large",
      )
    }
    return bytes
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined)
        throw new GitHubApiError(
          "GitHub repository archive is too large for guest scanning. Sign in with GitHub or scan a smaller repository.",
          413,
          "github_archive_too_large",
        )
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total)
}

function readTarEntries(tarball: Buffer) {
  const entries: Array<{ path: string; bytes: Buffer }> = []
  let offset = 0

  while (offset + 512 <= tarball.length) {
    const header = tarball.subarray(offset, offset + 512)
    if (isZeroBlock(header)) break

    const name = readTarString(header, 0, 100)
    const size = readTarOctal(header, 124, 12)
    const type = readTarString(header, 156, 1)
    const prefix = readTarString(header, 345, 155)
    const rawPath = prefix ? `${prefix}/${name}` : name
    const dataStart = offset + 512
    const dataEnd = dataStart + size

    if (dataEnd > tarball.length) break

    if ((type === "" || type === "0") && rawPath) {
      const normalized = normalizeArchivePath(rawPath)
      if (normalized) entries.push({ path: normalized, bytes: tarball.subarray(dataStart, dataEnd) })
    }

    offset = dataStart + Math.ceil(size / 512) * 512
  }

  return entries
}

function normalizeArchivePath(rawPath: string) {
  const withoutRoot = rawPath.split("/").slice(1).join("/")
  return normalizeProjectPath(withoutRoot)
}

function readTarString(buffer: Buffer, offset: number, length: number) {
  const raw = buffer.subarray(offset, offset + length)
  const end = raw.indexOf(0)
  return raw.subarray(0, end === -1 ? raw.length : end).toString("utf8").trim()
}

function readTarOctal(buffer: Buffer, offset: number, length: number) {
  const value = readTarString(buffer, offset, length).replace(/\0/g, "").trim()
  if (!value) return 0
  const parsed = Number.parseInt(value, 8)
  return Number.isFinite(parsed) ? parsed : 0
}

function isZeroBlock(buffer: Buffer) {
  for (const byte of buffer) {
    if (byte !== 0) return false
  }
  return true
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
    findings: input.report.findings.filter(isSafePullRequestFinding),
  }
  if (report.findings.length === 0) {
    throw new Error("No safe PR fixes were available. Badger only opens public pull requests for deterministic, low-risk code changes.")
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
  const branch = await getOrCreateReviewBranch(target.writeOwner, target.writeRepo, input.token, baseSha, report.id)
  const filesChanged: string[] = []
  const appliedFixes: string[] = []
  const skippedFixes = summarizeReviewRequiredFindings(report.findings)
  const prHead = target.prHeadOwner ? `${target.prHeadOwner}:${branch.name}` : branch.name
  const existingPullRequest = await findOpenPullRequest(owner, repo, prHead, input.token)

  if (shouldApplyGitignoreHardening(report.findings)) {
    const gitignoreChanged = await hardenGitignore(target.writeOwner, target.writeRepo, branch.name, input.token)
    if (gitignoreChanged) {
      filesChanged.push(".gitignore")
      appliedFixes.push("Updated .gitignore because the selected findings included committed environment files.")
    }
  }

  const envChanges = await removeCommittedEnvironmentFiles(target.writeOwner, target.writeRepo, branch.name, input.token, report)
  filesChanged.push(...envChanges.filesChanged)
  appliedFixes.push(...envChanges.appliedFixes)

  const actionPinning = await pinSelectedThirdPartyActions(target.writeOwner, target.writeRepo, branch.name, input.token, report)
  filesChanged.push(...actionPinning.filesChanged)
  appliedFixes.push(...actionPinning.appliedFixes)
  skippedFixes.push(...actionPinning.reviewNotes)

  const isExternalPublicPullRequest = Boolean(target.forkFullName)

  if (isExternalPublicPullRequest && appliedFixes.length === 0) {
    if (branch.created) await deleteReviewBranch(target.writeOwner, target.writeRepo, branch.name, input.token)
    throw new Error(
      "No safe code changes were available for a public pull request. Use the issue-body copy flow or select findings with deterministic fixes instead of opening a report-only PR.",
    )
  }

  const reportPath = `.github/security-notes/security-review-${formatReviewDate(report.createdAt)}-${report.id.slice(0, 8)}.md`
  const includeReviewNotesFile = shouldAttachReviewNotesFileToPullRequest(target.forkFullName)
  const publicSkippedFixes = isExternalPublicPullRequest ? [] : skippedFixes
  const publicFilesChanged = includeReviewNotesFile ? [...filesChanged, reportPath] : [...filesChanged]
  const deterministicReportMarkdown = buildRemediationReportMarkdown(report, {
    branch: branch.name,
    base,
    appliedFixes,
    skippedFixes: publicSkippedFixes,
    filesChanged: publicFilesChanged,
  })
  const deterministicTitle = buildPullRequestTitle(report, appliedFixes)
  const deterministicBody = buildPullRequestBody(report, {
    appliedFixes,
    skippedFixes: publicSkippedFixes,
    filesChanged: publicFilesChanged,
    forkFullName: target.forkFullName,
  })
  const draftCopy = {
    title: deterministicTitle,
    body: deterministicBody,
    reportMarkdown: deterministicReportMarkdown,
  }
  const copy = isExternalPublicPullRequest
    ? sanitizePublicPullRequestCopy(draftCopy)
    : await generateProfessionalPullRequestCopy({
        report,
        draft: draftCopy,
        filesChanged: publicFilesChanged,
        appliedFixes,
        skippedFixes: publicSkippedFixes,
      })

  const changedFilesForSafetyReview = await collectChangedFilesForSafetyReview({
    baseOwner: owner,
    baseRepo: repo,
    baseRef: base,
    headOwner: target.writeOwner,
    headRepo: target.writeRepo,
    headRef: branch.name,
    token: input.token,
    filesChanged: publicFilesChanged,
  })
  if (includeReviewNotesFile) {
    changedFilesForSafetyReview.push({
      path: reportPath,
      status: "added",
      diff: buildCompactFileDiff(reportPath, null, copy.reportMarkdown),
    })
  }

  const safetyReview = await reviewPullRequestWithClaude({
    report,
    draft: {
      title: copy.title,
      body: copy.body,
    },
    filesChanged: publicFilesChanged,
    appliedFixes,
    selectedFindings: report.findings,
    changedFiles: changedFilesForSafetyReview,
    externalPublicPullRequest: isExternalPublicPullRequest,
  })

  if (!safetyReview.approved || !safetyReview.title || !safetyReview.body) {
    if (branch.created) await deleteReviewBranch(target.writeOwner, target.writeRepo, branch.name, input.token)
    throw new Error(safetyReview.error ?? "Claude Opus PR safety review blocked this pull request.")
  }

  copy.title = safetyReview.title
  copy.body = safetyReview.body

  if (includeReviewNotesFile) {
    await putRepositoryFile({
      owner: target.writeOwner,
      repo: target.writeRepo,
      token: input.token,
      branch: branch.name,
      path: reportPath,
      content: copy.reportMarkdown,
      sha: (await getRepositoryContentFile(target.writeOwner, target.writeRepo, reportPath, branch.name, input.token))?.sha,
      message: "Add security review notes",
    })
    filesChanged.push(reportPath)
  } else {
    await removeReviewNotesFileIfPresent(target.writeOwner, target.writeRepo, branch.name, input.token, reportPath)
  }

  let pullRequest: GitHubPullRequestApi
  try {
    pullRequest = existingPullRequest
      ? await updatePullRequest({
          owner,
          repo,
          token: input.token,
          number: existingPullRequest.number,
          title: copy.title,
          body: copy.body,
        })
      : await openPullRequest({
          owner,
          repo,
          token: input.token,
          branch: branch.name,
          head: prHead,
          base,
          title: copy.title,
          body: copy.body,
        })
  } catch (error) {
    const existing = await findOpenPullRequest(owner, repo, prHead, input.token)
    if (existing) {
      pullRequest = await updatePullRequest({
        owner,
        repo,
        token: input.token,
        number: existing.number,
        title: copy.title,
        body: copy.body,
      })
    } else {
      if (branch.created) await deleteReviewBranch(target.writeOwner, target.writeRepo, branch.name, input.token)
      throw error
    }
  }

  return {
    url: pullRequest.html_url,
    number: pullRequest.number,
    branch: pullRequest.head.ref,
    base: pullRequest.base.ref,
    filesChanged,
    appliedFixes,
    skippedFixes,
    safetyReview: {
      provider: safetyReview.provider,
      model: safetyReview.model,
      summary: safetyReview.summary,
      blockingReasons: safetyReview.blockingReasons,
      requiredChanges: safetyReview.requiredChanges,
    },
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

async function getOrCreateReviewBranch(owner: string, repo: string, token: string, baseSha: string, scanId: string): Promise<ReviewBranch> {
  const branch = `security/review-${scanId.slice(0, 8)}`

  try {
    await getBranchHeadSha(owner, repo, branch, token)
    return { name: branch, created: false }
  } catch (error) {
    if (!isGitHubNotFoundError(error)) throw error
  }

  try {
    await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/refs`, token, {
      method: "POST",
      body: JSON.stringify({
        ref: `refs/heads/${branch}`,
        sha: baseSha,
      }),
    })
    return { name: branch, created: true }
  } catch (error) {
    if (!isGitHubValidationError(error)) throw error

    await getBranchHeadSha(owner, repo, branch, token)
    return { name: branch, created: false }
  }
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

async function pinSelectedThirdPartyActions(owner: string, repo: string, branch: string, token: string, report: ScanReport) {
  const paths = githubActionsFindingPaths(report.findings)
  const filesChanged: string[] = []
  const appliedFixes: string[] = []
  const reviewNotes: string[] = []

  for (const path of paths) {
    const existing = await getRepositoryContentFile(owner, repo, path, branch, token)
    if (!existing?.sha) continue

    const current = decodeContentFile(existing)
    const result = await pinThirdPartyActionRefsInText(current, (action) => resolveActionCommitSha(action, token))
    if (result.text === current) {
      if (result.unresolved.length > 0) {
        reviewNotes.push(`Review ${path}: could not resolve ${result.unresolved.join(", ")} to immutable commit SHAs.`)
      }
      continue
    }

    await putRepositoryFile({
      owner,
      repo,
      token,
      branch,
      path,
      content: result.text,
      sha: existing.sha,
      message: `Pin third-party GitHub Actions in ${path}`,
    })

    filesChanged.push(path)
    appliedFixes.push(...result.pinned.map((pin) => formatPinnedActionFix(path, pin.from, pin.to, pin.originalRef)))
    if (result.unresolved.length > 0) {
      reviewNotes.push(`Review ${path}: could not resolve ${result.unresolved.join(", ")} to immutable commit SHAs.`)
    }
  }

  return { filesChanged, appliedFixes, reviewNotes }
}

function githubActionsFindingPaths(findings: ScanFinding[]) {
  const paths = new Set<string>()
  for (const finding of findings) {
    if (!isSafePullRequestFinding(finding)) continue
    if (!finding.filePath.startsWith(".github/")) continue
    if (!/\.(ya?ml)$/.test(finding.filePath)) continue
    paths.add(finding.filePath)
  }
  return [...paths].sort()
}

async function resolveActionCommitSha(action: ActionRef, token: string) {
  try {
    const response = await githubFetch(
      `${GITHUB_API}/repos/${encodeURIComponent(action.owner)}/${encodeURIComponent(action.repo)}/commits/${encodeURIComponent(action.ref)}`,
      token,
    )
    const data = (await response.json()) as { sha?: string }
    return data.sha ?? null
  } catch {
    return null
  }
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

async function collectChangedFilesForSafetyReview(input: {
  baseOwner: string
  baseRepo: string
  baseRef: string
  headOwner: string
  headRepo: string
  headRef: string
  token: string
  filesChanged: string[]
}): Promise<PullRequestSafetyChangedFile[]> {
  const files: PullRequestSafetyChangedFile[] = []
  for (const path of [...new Set(input.filesChanged)].slice(0, 30)) {
    const [baseFile, headFile] = await Promise.all([
      getRepositoryContentFile(input.baseOwner, input.baseRepo, path, input.baseRef, input.token),
      getRepositoryContentFile(input.headOwner, input.headRepo, path, input.headRef, input.token),
    ])
    const before = baseFile ? decodeContentFile(baseFile) : null
    const after = headFile ? decodeContentFile(headFile) : null
    if (before === after) continue

    files.push({
      path,
      status: before == null ? "added" : after == null ? "deleted" : "modified",
      diff: buildCompactFileDiff(path, before, after),
    })
  }

  return files
}

function buildCompactFileDiff(path: string, before: string | null, after: string | null) {
  const oldLines = before?.split(/\r?\n/) ?? []
  const newLines = after?.split(/\r?\n/) ?? []
  const output = [`--- ${before == null ? "/dev/null" : `a/${path}`}`, `+++ ${after == null ? "/dev/null" : `b/${path}`}`]
  const maxLines = 240

  if (before == null) {
    for (const line of newLines.slice(0, maxLines)) output.push(`+${line}`)
    if (newLines.length > maxLines) output.push(`+... truncated ${newLines.length - maxLines} added lines`)
    return output.join("\n")
  }

  if (after == null) {
    for (const line of oldLines.slice(0, maxLines)) output.push(`-${line}`)
    if (oldLines.length > maxLines) output.push(`-... truncated ${oldLines.length - maxLines} removed lines`)
    return output.join("\n")
  }

  const maxLength = Math.max(oldLines.length, newLines.length)
  let emitted = 0
  for (let index = 0; index < maxLength && emitted < maxLines; index += 1) {
    const oldLine = oldLines[index]
    const newLine = newLines[index]
    if (oldLine === newLine) {
      if (index > 0 && oldLines[index - 1] !== newLines[index - 1]) {
        output.push(` ${oldLine ?? ""}`)
        emitted += 1
      }
      continue
    }

    if (oldLine != null) {
      output.push(`-${oldLine}`)
      emitted += 1
    }
    if (newLine != null && emitted < maxLines) {
      output.push(`+${newLine}`)
      emitted += 1
    }
  }

  if (maxLength > maxLines) output.push("... diff truncated")
  return output.join("\n")
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

async function removeReviewNotesFileIfPresent(owner: string, repo: string, branch: string, token: string, path: string) {
  const existing = await getRepositoryContentFile(owner, repo, path, branch, token)
  if (!existing?.sha) return

  await deleteRepositoryFile({
    owner,
    repo,
    token,
    branch,
    path,
    sha: existing.sha,
    message: `Remove review notes file ${path}`,
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

async function updatePullRequest(input: {
  owner: string
  repo: string
  token: string
  number: number
  title: string
  body: string
}) {
  const response = await githubFetch(`${GITHUB_API}/repos/${input.owner}/${input.repo}/pulls/${input.number}`, input.token, {
    method: "PATCH",
    body: JSON.stringify({
      title: input.title.slice(0, 240),
      body: input.body.slice(0, 60_000),
    }),
  })
  return (await response.json()) as GitHubPullRequestApi
}

async function findOpenPullRequest(owner: string, repo: string, head: string, token: string) {
  const params = new URLSearchParams({
    head,
    state: "open",
    per_page: "1",
  })
  const response = await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/pulls?${params.toString()}`, token)
  const data = (await response.json()) as GitHubPullRequestApi[]
  return data[0] ?? null
}

async function deleteReviewBranch(owner: string, repo: string, branch: string, token: string) {
  try {
    await githubFetch(`${GITHUB_API}/repos/${owner}/${repo}/git/refs/heads/${encodeGitHubPath(branch)}`, token, {
      method: "DELETE",
    })
  } catch {
    // Best-effort cleanup only. The original GitHub error is more useful to the caller.
  }
}

async function githubFetch(url: string, token?: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers)
  headers.set("Accept", "application/vnd.github+json")
  headers.set("User-Agent", "StaticSecurityReview")
  headers.set("X-GitHub-Api-Version", "2022-11-28")
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  if (token) headers.set("Authorization", `Bearer ${token}`)

  const maxRetries = Math.min(readPositiveInt(badgerEnv("GITHUB_FETCH_RETRIES"), DEFAULT_GITHUB_FETCH_RETRIES), 5)
  const baseDelayMs = readPositiveInt(badgerEnv("GITHUB_RETRY_DELAY_MS"), DEFAULT_GITHUB_RETRY_DELAY_MS)

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

    await throwGitHubResponseError(response, url, Boolean(token))
  }

  throw new GitHubApiError(
    "GitHub is temporarily unavailable while reading this repository. Retry the scan in a moment.",
    502,
    "github_temporarily_unavailable",
  )
}

function getLocalGitHubToken() {
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") return undefined

  const explicit = badgerEnv("ALLOW_LOCAL_GITHUB_TOKEN")?.toLowerCase()
  const localAllowed = explicit !== "false"
  if (!localAllowed) return undefined

  return (
    badgerEnv("GITHUB_TOKEN") ||
    process.env.GITHUB_TOKEN?.trim() ||
    process.env.GH_TOKEN?.trim() ||
    undefined
  )
}

async function getServerGitHubReadToken() {
  if (isGitHubAppInstallationConfigured()) return createDefaultGitHubAppInstallationToken()
  if (process.env.NODE_ENV === "production" || process.env.VERCEL === "1") return undefined

  return (
    badgerEnv("GITHUB_TOKEN") ||
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
    "# Security review notes",
    "",
    "These notes summarize security-relevant findings that are worth maintainer review. They do not claim that every item is remediated.",
    "",
    "## Review context",
    "",
    `- Project: \`${report.projectName}\``,
    `- Source: \`${report.sourceLabel}\``,
    `- Risk score: **${report.riskScore}/100**`,
    `- Findings included: **${report.findings.length}**`,
    `- Baseline: **${formatPullRequestBaseline(report)}**`,
    "",
    ...formatPullRequestAiSummary(report),
    ...formatPullRequestRiskBreakdown(report),
    "## Findings requiring review",
    "",
    ...formatPullRequestFindings(report),
    "",
    "## Pull request context",
    "",
    `**Branch:** \`${pr.branch}\``,
    `**Base:** \`${pr.base}\``,
    "",
    "### Low-risk changes applied",
    "",
    ...(pr.appliedFixes.length > 0 ? pr.appliedFixes.map((item) => `- ${item}`) : ["- No code files were changed in this PR."]),
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
  return buildProfessionalPullRequestBody({
    sourceLabel: report.sourceLabel,
    appliedFixes: pr.appliedFixes,
    skippedFixes: pr.skippedFixes,
    filesChanged: pr.filesChanged,
    forkFullName: pr.forkFullName,
  })
}

function buildPullRequestTitle(report: ScanReport, appliedFixes: string[]) {
  return buildProfessionalPullRequestTitle({
    sourceLabel: report.sourceLabel,
    appliedFixes,
    skippedFixes: summarizeReviewRequiredFindings(report.findings),
    filesChanged: [],
  })
}

function formatReviewDate(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return new Date().toISOString().slice(0, 10)
  return date.toISOString().slice(0, 10)
}

function formatPullRequestBaseline(report: ScanReport) {
  const summary = report.baselineSummary
  if (!summary) return "no saved baseline"
  return `${summary.new} new / ${summary.existing} existing / ${summary.resolved} resolved / ${summary.suppressed} suppressed`
}

function summarizeReviewRequiredFindings(reportFindings: ScanFinding[]) {
  return groupFindingsForPullRequest(reportFindings.filter((finding) => !finding.suppressed))
    .slice(0, 12)
    .map((group) => {
      const locations = group.findings.map(formatFindingLocation)
      return `${group.title} (${formatInlineList(locations, 4)}) remains review-required.`
    })
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

function formatPullRequestAiSummary(report: ScanReport) {
  const summary = report.aiTriage
  if (!summary) return []

  return [
    "## Review summary",
    "",
    summary.riskNarrative ? `${summary.riskNarrative}` : "",
    "",
    ...(summary.recommendedNextSteps.length > 0
      ? [
          "### Recommended next steps",
          "",
          ...summary.recommendedNextSteps.slice(0, 5).map((step, index) => `${index + 1}. ${step}`),
          "",
        ]
      : []),
  ].filter(Boolean)
}

function formatPullRequestFindings(report: ScanReport) {
  const groups = groupFindingsForPullRequest(report.findings).slice(0, 12)
  if (groups.length === 0) return ["No active findings were selected for this pull request.", ""]

  return groups.flatMap((group, index) => [
    `### ${index + 1}. ${group.title}`,
    "",
    `- Severity: \`${group.severity}\``,
    `- Category: \`${group.category}\``,
    `- Rule: \`${group.ruleId ?? "unknown"}\``,
    `- Locations: ${formatInlineList(group.findings.map(formatFindingLocation), 8)}`,
    `- Confidence: ${Math.round(group.confidence * 100)}%`,
    ...(group.triageReason ? [`- Triage: ${group.triageReason}`] : []),
    ...(group.detectedControls.length > 0 ? [`- Detected controls: ${formatInlineList(group.detectedControls, 5)}`] : []),
    ...(group.missingControls.length > 0 ? [`- Missing controls: ${formatInlineList(group.missingControls, 5)}`] : []),
    `- Recommendation: ${group.recommendation}`,
    ...group.evidence.slice(0, 3).map((evidence) => `- Evidence: \`${evidence}\``),
    "",
  ])
}

type PullRequestFindingGroup = {
  key: string
  title: string
  severity: ScanFinding["severity"]
  category: ScanFinding["category"]
  ruleId?: string
  confidence: number
  recommendation: string
  evidence: string[]
  triageReason?: string
  detectedControls: string[]
  missingControls: string[]
  findings: ScanFinding[]
}

function groupFindingsForPullRequest(findings: ScanFinding[]): PullRequestFindingGroup[] {
  const groups = new Map<string, PullRequestFindingGroup>()

  for (const finding of [...findings].sort(compareFindingsForPullRequest)) {
    const key = pullRequestRootCauseKey(finding)
    const current = groups.get(key)
    if (!current) {
      groups.set(key, {
        key,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        ruleId: finding.ruleId,
        confidence: finding.confidence,
        recommendation: finding.recommendation,
        evidence: finding.evidence ? [finding.evidence] : [],
        triageReason: finding.triage?.reason,
        detectedControls: finding.triage?.detectedControls ?? [],
        missingControls: finding.triage?.missingControls ?? [],
        findings: [finding],
      })
      continue
    }

    current.findings.push(finding)
    current.severity = severityRank(finding.severity) > severityRank(current.severity) ? finding.severity : current.severity
    current.confidence = Math.max(current.confidence, finding.confidence)
    if (finding.evidence && !current.evidence.includes(finding.evidence)) current.evidence.push(finding.evidence)
    if (!current.triageReason && finding.triage?.reason) current.triageReason = finding.triage.reason
    for (const control of finding.triage?.detectedControls ?? []) {
      if (!current.detectedControls.includes(control)) current.detectedControls.push(control)
    }
    for (const control of finding.triage?.missingControls ?? []) {
      if (!current.missingControls.includes(control)) current.missingControls.push(control)
    }
  }

  return [...groups.values()].sort((a, b) => {
    const severityDelta = severityRank(b.severity) - severityRank(a.severity)
    if (severityDelta !== 0) return severityDelta
    return b.confidence - a.confidence
  })
}

function pullRequestRootCauseKey(finding: ScanFinding) {
  if (finding.ruleId === "supply-chain.remote-install-piped-shell") return finding.ruleId
  if (finding.ruleId === "github-actions.unpinned-actions.grouped") return finding.ruleId
  return `${finding.ruleId ?? finding.title}:${finding.category}:${finding.title}`
}

function formatInlineList(items: string[], maxItems: number) {
  const unique = [...new Set(items.filter(Boolean))]
  const shown = unique.slice(0, maxItems)
  const suffix = unique.length > shown.length ? `, and ${unique.length - shown.length} more` : ""
  return shown.map((item) => `\`${item}\``).join(", ") + suffix
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

function encodeGitHubRefPath(ref: string) {
  return ref.split("/").map(encodeURIComponent).join("/")
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

async function throwGitHubResponseError(response: Response, url: string, authenticated: boolean): Promise<never> {
  const details = await response.text().catch(() => "")
  const message = extractGitHubErrorMessage(details)

  if (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0") {
    throw new GitHubApiError(
      "The public scan service is busy right now. Sign in with GitHub to keep testing with your own GitHub session, or try again in a few minutes.",
      response.status,
      "github_rate_limited",
    )
  }

  if (response.status === 401 || response.status === 403) throw new Error("GitHub authorization failed.")
  if (response.status === 404) {
    throw new GitHubApiError(formatGitHubNotFoundMessage(url, authenticated), response.status, "github_not_found")
  }
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
