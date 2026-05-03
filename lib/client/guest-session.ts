"use client"

import { useSyncExternalStore } from "react"

export type GuestSession = {
  id: string
  name: string
  handle: string
  initials: string
  colorA: string
  colorB: string
  createdAt: string
}

const STORAGE_KEY = "badger_guest_session"
const EVENT_NAME = "badger:guest-session"

const ADJECTIVES = ["Signal", "Quiet", "Sharp", "North", "Bright", "Steady", "Atomic", "Silver"]
const NOUNS = ["Scout", "Analyst", "Builder", "Reviewer", "Pilot", "Operator", "Keeper", "Runner"]
const PALETTES = [
  ["#7FE7C4", "#8B7CF6"],
  ["#9BE7FF", "#7FE7C4"],
  ["#F6B65F", "#7FE7C4"],
  ["#D8B4FE", "#67E8F9"],
  ["#A7F3D0", "#60A5FA"],
  ["#FCA5A5", "#C4B5FD"],
]

let cachedRaw: string | null | undefined
let cachedSession: GuestSession | null = null

export function getGuestSession(): GuestSession | null {
  if (typeof window === "undefined") return null

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (raw === cachedRaw) return cachedSession

    cachedRaw = raw
    if (!raw) return null

    const parsed = JSON.parse(raw) as Partial<GuestSession>
    cachedSession = isGuestSession(parsed) ? parsed : null
    return cachedSession
  } catch {
    cachedRaw = undefined
    cachedSession = null
    return null
  }
}

export function ensureGuestSession(): GuestSession {
  const existing = getGuestSession()
  if (existing) return existing

  const session = createGuestSession()
  storeGuestSession(session)
  return session
}

export function clearGuestSession() {
  if (typeof window === "undefined") return
  cachedRaw = null
  cachedSession = null
  window.localStorage.removeItem(STORAGE_KEY)
  window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: null }))
}

export function subscribeGuestSessionChange(listener: () => void) {
  if (typeof window === "undefined") return () => undefined

  const handler = () => listener()
  window.addEventListener(EVENT_NAME, handler)
  window.addEventListener("storage", handler)
  return () => {
    window.removeEventListener(EVENT_NAME, handler)
    window.removeEventListener("storage", handler)
  }
}

export function useGuestSession() {
  return useSyncExternalStore(subscribeGuestSessionChange, getGuestSession, () => null)
}

function storeGuestSession(session: GuestSession) {
  const raw = JSON.stringify(session)
  cachedRaw = raw
  cachedSession = session
  window.localStorage.setItem(STORAGE_KEY, raw)
  window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: session }))
}

function createGuestSession(): GuestSession {
  const id = randomId()
  const adjective = pick(ADJECTIVES)
  const noun = pick(NOUNS)
  const [colorA, colorB] = pick(PALETTES)
  const suffix = id.slice(-4).toUpperCase()

  return {
    id,
    name: `${adjective} ${noun}`,
    handle: `guest-${suffix.toLowerCase()}`,
    initials: `${adjective[0]}${noun[0]}`,
    colorA,
    colorB,
    createdAt: new Date().toISOString(),
  }
}

function randomId() {
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
}

function pick<T>(items: T[]) {
  return items[Math.floor(Math.random() * items.length)]
}

function isGuestSession(value: Partial<GuestSession>): value is GuestSession {
  return Boolean(
    value &&
      typeof value.id === "string" &&
      typeof value.name === "string" &&
      typeof value.handle === "string" &&
      typeof value.initials === "string" &&
      typeof value.colorA === "string" &&
      typeof value.colorB === "string" &&
      typeof value.createdAt === "string",
  )
}
