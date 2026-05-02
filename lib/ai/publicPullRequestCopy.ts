import { redactSecrets } from "@/lib/scanner/rules"

export interface PullRequestCopyDraft {
  title: string
  body: string
  reportMarkdown: string
}

const BLOCKED_PUBLIC_PR_TERMS = [
  /\bVibeShield(?:\s+Labs)?\b/gi,
  /\bAI-generated\b/gi,
  /\bauto-generated\b/gi,
  /\bautomated\s+(?:scanner|scan|analysis|tool|review)\b/gi,
  /\bgenerated\s+(?:by|from)\s+(?:a\s+)?(?:scanner|scan|tool|static analysis)\b/gi,
  /\bstatic\s+security\s+review\s+report\b/gi,
  /\bstatic\s+analysis\s+report\b/gi,
  /\bscanner\s+vendor\b/gi,
  /\bsecurity\s+scanner\b/gi,
  /\bscanner\b/gi,
  /\bscan\s+metadata\b/gi,
  /\bscan\s+id\b/gi,
]

export function sanitizePublicPullRequestCopy(draft: PullRequestCopyDraft): PullRequestCopyDraft {
  return {
    title: sanitizeTitle(draft.title),
    body: sanitizeText(draft.body),
    reportMarkdown: sanitizeText(draft.reportMarkdown),
  }
}

export function isUsablePullRequestCopy(draft: PullRequestCopyDraft) {
  const all = `${draft.title}\n${draft.body}\n${draft.reportMarkdown}`
  if (/VibeShield/i.test(all)) return false
  if (/localhost|\/api\/scan\//i.test(all)) return false
  if (/(guaranteed|fully fixed|completely fixed|100% secure|unhackable)/i.test(all)) return false
  if (/(generated|auto-generated|automated scanner|security scanner|scan metadata|scan id)/i.test(all)) return false
  if (!/review/i.test(draft.body)) return false
  return true
}

function sanitizeTitle(value: string) {
  return sanitizeText(value)
    .replace(/^add\s+security\s+review\s+report$/i, "Add security review notes")
    .replace(/^document\s+static\s+analysis\s+findings$/i, "Document security review findings")
    .split(/\r?\n/)[0]
    .trim()
    .slice(0, 90) || "Add security review notes"
}

function sanitizeText(value: string) {
  let sanitized = redactSecrets(value)
    .replace(/^\s*-\s*(?:Scan ID|Mode|Files inspected):.*$/gim, "")
    .replace(
      /\b(?:stop|ignore|disregard|forget|override|bypass)\s+(?:claude|chatgpt|codex|assistant|previous instructions|all instructions|system prompt|developer instructions)\b/gi,
      "[removed untrusted prompt instruction]",
    )
    .replace(
      /\b(?:you are now|act as|system:|developer:)\s+(?:claude|chatgpt|codex|an? assistant|a different assistant)\b[^\n]*/gi,
      "[removed untrusted prompt instruction]",
    )

  for (const pattern of BLOCKED_PUBLIC_PR_TERMS) {
    sanitized = sanitized.replace(pattern, (match) => humanizeBlockedTerm(match))
  }

  return sanitized
    .replace(/\bgenerated\s+(?:by|from)\b[^.\n]*(?:\.|$)/gi, "prepared for maintainer review.")
    .replace(/https?:\/\/localhost:\d+\/\S*/gi, "")
    .replace(/http:\/\/127\.0\.0\.1:\d+\/\S*/gi, "")
    .replace(/\/api\/scan\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)?/g, "")
    .replace(/\.github\/security-reports\//g, ".github/security-notes/")
    .replace(/\b(100%\s+secure|unhackable|fully fixed|completely fixed|guaranteed fixed)\b/gi, "review-required")
    .replace(/^\s*_?Generated.*$/gim, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
}

function humanizeBlockedTerm(value: string) {
  if (/metadata|scan id/i.test(value)) return "review context"
  if (/report/i.test(value)) return "security review notes"
  return "security review"
}
