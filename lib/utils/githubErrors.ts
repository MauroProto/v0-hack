export function formatGitHubNotFoundMessage(url: string, authenticated: boolean) {
  const accessHint = authenticated
    ? "Confirm that your GitHub account has access to it."
    : "For private repositories, login with GitHub first. For public scans, check the owner/repo spelling."

  const parsed = parseGitHubApiUrl(url)
  if (!parsed) return `GitHub resource was not found. ${accessHint}`

  const { owner, repo, segments } = parsed
  const fullName = `${owner}/${repo}`
  const remainder = segments.slice(3)

  if (remainder.length === 0) {
    return `GitHub repository ${fullName} was not found or is private. ${accessHint}`
  }

  if (remainder[0] === "git" && remainder[1] === "trees") {
    const ref = remainder.slice(2).join("/") || "selected ref"
    return `GitHub branch or ref "${ref}" was not found in ${fullName}. Check the branch name or scan the repository default branch.`
  }

  if (remainder[0] === "git" && remainder[1] === "ref" && remainder[2] === "heads") {
    const branch = remainder.slice(3).join("/") || "selected branch"
    return `GitHub branch "${branch}" was not found in ${fullName}. The report may point to a deleted or renamed branch.`
  }

  if (remainder[0] === "git" && remainder[1] === "blobs") {
    return `A GitHub file blob could not be read from ${fullName}. Retry the scan; if the repository is private, login with GitHub first.`
  }

  if (remainder[0] === "contents") {
    const path = remainder.slice(1).join("/") || "selected file"
    return `GitHub file "${path}" was not found in ${fullName} on the selected branch. The report may be stale because the file moved or the branch changed.`
  }

  if (remainder[0] === "forks") {
    return `GitHub could not create or read a fork for ${fullName}. Confirm the repository exists and your account can access it.`
  }

  if (remainder[0] === "pulls") {
    return `GitHub could not open a pull request against ${fullName}. Confirm the repository exists and your account can access it.`
  }

  return `GitHub resource in ${fullName} was not found. ${accessHint}`
}

function parseGitHubApiUrl(url: string) {
  try {
    const parsed = new URL(url)
    if (parsed.hostname !== "api.github.com") return null
    const segments = parsed.pathname.split("/").filter(Boolean).map(safeDecodeURIComponent)
    if (segments[0] !== "repos" || !segments[1] || !segments[2]) return null
    return {
      owner: segments[1],
      repo: segments[2],
      segments,
    }
  } catch {
    return null
  }
}

function safeDecodeURIComponent(value: string) {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
