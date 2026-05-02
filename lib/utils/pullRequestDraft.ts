export type PullRequestDraftContext = {
  sourceLabel: string
  appliedFixes: string[]
  skippedFixes: string[]
  filesChanged: string[]
  forkFullName?: string
}

export type PinnedActionFix = {
  path: string
  from: string
  to: string
  originalRef: string
}

export function shouldAttachReviewNotesFileToPullRequest(forkFullName?: string) {
  return !forkFullName
}

const PINNED_ACTION_FIX_RE =
  /^Pinned third-party GitHub Action `([^`]+)` to `([^`]+)` in `([^`]+)` \(kept `# ([^`]+)` comment\)\.$/

export function buildProfessionalPullRequestTitle(input: PullRequestDraftContext) {
  const pinnedActions = parsePinnedActionFixes(input.appliedFixes)
  if (pinnedActions.length === 1) {
    return `Pin ${actionDisplayName(pinnedActions[0].from)} action to commit SHA`
  }
  if (pinnedActions.length > 1) return "Pin third-party GitHub Actions to commit SHAs"

  const applied = input.appliedFixes.join("\n")
  if (/removed committed environment file|redacted environment example/i.test(applied)) return "Remove committed environment files"
  if (/security|review|posture/i.test(`${applied}\n${input.skippedFixes.join("\n")}`)) return "Document security review notes"
  return "Add security review notes"
}

export function buildProfessionalPullRequestBody(input: PullRequestDraftContext) {
  const pinnedActions = parsePinnedActionFixes(input.appliedFixes)
  if (pinnedActions.length > 0) return buildPinnedActionsPullRequestBody(input, pinnedActions)

  return [
    "## Summary",
    "",
    input.appliedFixes.length > 0
      ? `This PR applies focused repository hygiene changes for \`${input.sourceLabel}\` and records remaining review items.`
      : `This PR records focused security review notes for \`${input.sourceLabel}\` without applying speculative code changes.`,
    "",
    "## What changed",
    "",
    ...(input.appliedFixes.length > 0 ? input.appliedFixes.map((item) => `- ${item}`) : ["- Added maintainer-facing review notes."]),
    "",
    "## Findings for maintainer review",
    "",
    ...(input.skippedFixes.length > 0 ? input.skippedFixes.map((item) => `- ${item}`) : ["- No selected findings require additional manual notes in this PR."]),
    "",
    "## Notes",
    "",
    "- The detailed review notes are included under `.github/security-notes/`.",
    "- This PR avoids speculative or placeholder fixes that could change production behavior.",
    "- Review all security-sensitive changes before merging.",
    ...(input.forkFullName ? [`- Head fork: \`${input.forkFullName}\`.`] : []),
  ].join("\n")
}

export function formatPinnedActionFix(path: string, from: string, to: string, originalRef: string) {
  return `Pinned third-party GitHub Action \`${from}\` to \`${to}\` in \`${path}\` (kept \`# ${originalRef}\` comment).`
}

export function parsePinnedActionFixes(appliedFixes: string[]) {
  const fixes: PinnedActionFix[] = []
  for (const appliedFix of appliedFixes) {
    const match = appliedFix.match(PINNED_ACTION_FIX_RE)
    if (!match?.[1] || !match[2] || !match[3] || !match[4]) continue
    fixes.push({
      from: match[1],
      to: match[2],
      path: match[3],
      originalRef: match[4],
    })
  }
  return fixes
}

function buildPinnedActionsPullRequestBody(input: PullRequestDraftContext, pinnedActions: PinnedActionFix[]) {
  return [
    "## Summary",
    "",
    pinnedActions.length === 1
      ? `This PR pins the third-party \`${actionName(pinnedActions[0].from)}\` GitHub Action used in \`${pinnedActions[0].path}\` to a full commit SHA instead of the mutable \`${pinnedActions[0].originalRef}\` tag.`
      : `This PR pins ${pinnedActions.length} third-party GitHub Action references to full commit SHAs instead of mutable tags or version refs.`,
    "",
    "## Change",
    "",
    ...formatPinnedActionDiffs(pinnedActions),
    "",
    "## Motivation",
    "",
    "Pinning third-party Actions to immutable commit SHAs reduces supply-chain risk in CI. Tags such as `v1` can move over time, while a full commit SHA keeps the workflow running the exact code that was reviewed.",
    "",
    "This follows GitHub's hardening guidance for third-party Actions and the OpenSSF Scorecard pinned-dependencies check:",
    "",
    "- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
    "- https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies",
    "",
    "## Notes",
    "",
    "- Only selected third-party Action references were changed. GitHub-owned actions were left unchanged to keep this PR narrowly scoped; maintainers can pin those separately if they want a stricter all-actions SHA policy.",
    "- This is intended to be a no-op behavioral change: each SHA was resolved from the previous tag or ref when this PR was prepared.",
    "- Future updates can be managed with Dependabot or a scheduled workflow that refreshes reviewed GitHub Action pins.",
    ...(input.skippedFixes.length > 0
      ? [
          "",
          "## Other review items",
          "",
          ...input.skippedFixes.map((item) => `- ${item}`),
        ]
      : []),
  ].join("\n")
}

function formatPinnedActionDiffs(pinnedActions: PinnedActionFix[]) {
  if (pinnedActions.length === 1) return [formatPinnedActionDiff(pinnedActions[0])]

  return pinnedActions.flatMap((fix) => [
    `### \`${fix.path}\``,
    "",
    formatPinnedActionDiff(fix),
    "",
  ])
}

function formatPinnedActionDiff(fix: PinnedActionFix) {
  return [
    "```diff",
    `- - uses: ${fix.from}`,
    `+ - uses: ${fix.to} # ${fix.originalRef}`,
    "```",
  ].join("\n")
}

function actionDisplayName(value: string) {
  return actionName(value).split("/").pop() ?? actionName(value)
}

function actionName(value: string) {
  return value.split("@")[0] ?? value
}
