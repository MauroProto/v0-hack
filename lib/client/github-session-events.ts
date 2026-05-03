"use client"

export type GitHubSessionChangeReason = "signed_out" | "disconnected"

export type GitHubSessionChange = {
  authenticated: false
  reason: GitHubSessionChangeReason
  at: number
}

const SESSION_EVENT = "vibeshield:github-session"
const STORAGE_KEY = "vibeshield:github-session-event"
const CHANNEL_NAME = "vibeshield:github-session"

export function publishGitHubSessionChange(reason: GitHubSessionChangeReason) {
  if (typeof window === "undefined") return

  const detail: GitHubSessionChange = {
    authenticated: false,
    reason,
    at: Date.now(),
  }

  window.dispatchEvent(new CustomEvent<GitHubSessionChange>(SESSION_EVENT, { detail }))

  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(detail))
    window.localStorage.removeItem(STORAGE_KEY)
  } catch {
    // localStorage can be unavailable in private or restricted browser contexts.
  }

  try {
    const channel = new BroadcastChannel(CHANNEL_NAME)
    channel.postMessage(detail)
    channel.close()
  } catch {
    // BroadcastChannel is progressive enhancement; same-tab updates use the DOM event above.
  }
}

export function subscribeGitHubSessionChange(handler: (detail: GitHubSessionChange) => void) {
  if (typeof window === "undefined") return () => {}

  const handleWindowEvent = (event: Event) => {
    const detail = (event as CustomEvent<GitHubSessionChange>).detail
    if (isGitHubSessionChange(detail)) handler(detail)
  }

  const handleStorageEvent = (event: StorageEvent) => {
    if (event.key !== STORAGE_KEY || !event.newValue) return

    try {
      const detail = JSON.parse(event.newValue) as unknown
      if (isGitHubSessionChange(detail)) handler(detail)
    } catch {
      // Ignore malformed cross-tab events.
    }
  }

  let channel: BroadcastChannel | null = null
  try {
    channel = new BroadcastChannel(CHANNEL_NAME)
    channel.onmessage = (event: MessageEvent<unknown>) => {
      if (isGitHubSessionChange(event.data)) handler(event.data)
    }
  } catch {
    channel = null
  }

  window.addEventListener(SESSION_EVENT, handleWindowEvent)
  window.addEventListener("storage", handleStorageEvent)

  return () => {
    window.removeEventListener(SESSION_EVENT, handleWindowEvent)
    window.removeEventListener("storage", handleStorageEvent)
    channel?.close()
  }
}

function isGitHubSessionChange(value: unknown): value is GitHubSessionChange {
  return Boolean(
    value &&
      typeof value === "object" &&
      (value as GitHubSessionChange).authenticated === false &&
      ((value as GitHubSessionChange).reason === "signed_out" ||
        (value as GitHubSessionChange).reason === "disconnected") &&
      typeof (value as GitHubSessionChange).at === "number",
  )
}
