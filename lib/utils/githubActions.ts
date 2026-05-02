export interface ActionRef {
  owner: string
  repo: string
  path?: string
  ref: string
  raw: string
}

export interface PinnedActionRef {
  from: string
  to: string
  originalRef: string
}

export interface PinActionRefsResult {
  text: string
  pinned: PinnedActionRef[]
  unresolved: string[]
}

export type ActionRefResolver = (action: ActionRef) => Promise<string | null>

const USES_LINE_RE = /^(\s*(?:-\s*)?uses:\s*)(['"]?)([^'"\s#]+)(\2)(.*)$/
const SHA_RE = /^[a-f0-9]{40}$/i

export async function pinThirdPartyActionRefsInText(
  text: string,
  resolveSha: ActionRefResolver,
): Promise<PinActionRefsResult> {
  const pinned: PinnedActionRef[] = []
  const unresolved: string[] = []
  const cache = new Map<string, Promise<string | null>>()

  const lines = await Promise.all(text.split(/\n/).map(async (line) => {
    const match = line.match(USES_LINE_RE)
    if (!match) return line

    const [, prefix, quote, usesValue, closingQuote, suffix] = match
    const action = parseActionRef(usesValue)
    if (!action || !shouldPinActionRef(action)) return line

    const cacheKey = `${action.owner}/${action.repo}@${action.ref}`
    const shaPromise = cache.get(cacheKey) ?? resolveSha(action)
    cache.set(cacheKey, shaPromise)
    const sha = await shaPromise
    if (!sha || !SHA_RE.test(sha)) {
      unresolved.push(action.raw)
      return line
    }

    const next = formatPinnedActionRef(action, sha)
    pinned.push({
      from: action.raw,
      to: next,
      originalRef: action.ref,
    })

    return `${prefix}${quote}${next}${closingQuote}${formatUsesSuffix(suffix, action.ref)}`
  }))

  return {
    text: lines.join("\n"),
    pinned: dedupePinnedRefs(pinned),
    unresolved: [...new Set(unresolved)],
  }
}

export function parseActionRef(value: string): ActionRef | null {
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("docker://")) return null

  const atIndex = value.lastIndexOf("@")
  if (atIndex <= 0 || atIndex === value.length - 1) return null

  const target = value.slice(0, atIndex)
  const ref = value.slice(atIndex + 1)
  const parts = target.split("/")
  const [owner, repo, ...pathParts] = parts
  if (!owner || !repo || !ref) return null

  return {
    owner,
    repo,
    path: pathParts.length > 0 ? pathParts.join("/") : undefined,
    ref,
    raw: value,
  }
}

export function shouldPinActionRef(action: ActionRef) {
  if (SHA_RE.test(action.ref)) return false
  if (isGitHubOwnedAction(action.owner)) return false
  return true
}

function formatPinnedActionRef(action: ActionRef, sha: string) {
  const path = action.path ? `/${action.path}` : ""
  return `${action.owner}/${action.repo}${path}@${sha}`
}

function formatUsesSuffix(suffix: string, originalRef: string) {
  if (suffix.includes("#")) return suffix
  return `${suffix} # ${originalRef}`
}

function isGitHubOwnedAction(owner: string) {
  const normalized = owner.toLowerCase()
  return normalized === "actions" || normalized === "github"
}

function dedupePinnedRefs(items: PinnedActionRef[]) {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = `${item.from}->${item.to}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
