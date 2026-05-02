import type { ScanFinding } from "@/lib/scanner/types"

const MIN_SAFE_PR_CONFIDENCE = 0.74

export function isSafePullRequestFinding(finding: ScanFinding) {
  return getSafePullRequestFindingReason(finding) !== null
}

export function getSafePullRequestFindingReason(finding: ScanFinding) {
  if (finding.suppressed) return null
  if (finding.confidence < MIN_SAFE_PR_CONFIDENCE) return null

  if (isGitHubActionPinFinding(finding)) {
    return "Deterministic fix: pin third-party GitHub Actions to immutable commit SHAs."
  }

  return null
}

function isGitHubActionPinFinding(finding: ScanFinding) {
  if (!finding.filePath.startsWith(".github/")) return false
  if (!/\.(?:ya?ml)$/.test(finding.filePath)) return false

  const text = `${finding.ruleId ?? ""}\n${finding.category}\n${finding.title}\n${finding.description}\n${finding.recommendation}`
  if (!/github.?actions|unpinned action|commit sha|sha pin/i.test(text)) return false

  return finding.ruleId === "github-actions.unpinned-actions.grouped" || /third-party|commit sha|sha pin/i.test(text)
}
