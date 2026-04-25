"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Icon } from "./icons"

type Repo = { name: string; status: "warn" | "ok"; href: string }

const REPOS: Repo[] = [
  { name: "demo vulnerable app", status: "warn", href: "/report/demo" },
  { name: "GitHub login", status: "ok", href: "/scan" },
  { name: "public GitHub URL", status: "ok", href: "/scan" },
]

type Item = {
  key: string
  label: string
  icon: keyof typeof Icon
  href: string
  count?: number
  live?: boolean
  match?: (path: string) => boolean
}

const PRIMARY: Item[] = [
  { key: "home", label: "Home", icon: "home", href: "/home" },
  { key: "scans", label: "Scans", icon: "scan", href: "/scans" },
  {
    key: "current",
    label: "New scan",
    icon: "focus",
    href: "/scan",
    match: (p) => p === "/scan" || p.startsWith("/report/"),
  },
  {
    key: "agent",
    label: "Agent runs",
    icon: "sparkle",
    href: "/agent-runs",
    match: (p) => p.startsWith("/agent-runs"),
  },
  {
    key: "patches",
    label: "Patches",
    icon: "brackets",
    href: "/patches",
    match: (p) => p.startsWith("/patches"),
  },
  {
    key: "repos",
    label: "Repositories",
    icon: "book",
    href: "/repositories",
    match: (p) => p.startsWith("/repositories"),
  },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname() || ""

  const isActive = (it: Item) => {
    if (it.match) return it.match(pathname)
    return pathname === it.href
  }

  return (
    <>
      <aside className="app-side" data-open={open}>
        <div className="app-side-scroll">
          <div className="brand-row">
            <Link href="/scan" className="brand">
              <span className="brand-mark"><Icon.shield /></span>
              <span>VibeShield</span>
            </Link>
            <button className="brand-chev" aria-label="Switch workspace">
              <Icon.chevDown style={{ width: 14, height: 14 }} />
            </button>
          </div>

          <div className="org-card">
            <div className="avatar">A</div>
            <div className="name">local demo</div>
            <span className="plan">MVP · BETA</span>
          </div>

          <div className="side-search">
            <Icon.search style={{ width: 14, height: 14, color: "var(--fg-5)" }} />
            <input placeholder="Jump to..." />
            <span className="kbd">⌘K</span>
          </div>

          <nav className="side-nav">
            {PRIMARY.map((it) => {
              const I = Icon[it.icon]
              const active = isActive(it)
              return (
                <Link key={it.key} href={it.href} className="side-link" data-active={active} onClick={onClose}>
                  <I />
                  <span className="label">{it.label}</span>
                  {it.live && <span className="live-dot" aria-label="live" />}
                  {typeof it.count === "number" && <span className="count">{it.count}</span>}
                </Link>
              )
            })}
          </nav>

          <div className="side-section-label">Repositories</div>
          <div className="side-nav">
            {REPOS.map((r) => (
              <Link
                key={r.name}
                href={r.href}
                className="repo-link"
                data-active={r.href === "/report/demo" && pathname === "/report/demo"}
                onClick={onClose}
              >
                <span className="dot" data-status={r.status} />
                <span>{r.name}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="app-side-bottom">
          <div className="cycle-meter">
            <div className="row">
              <span>Beta · free for now</span>
              <b>MVP</b>
            </div>
            <div className="bar"><span style={{ width: "100%" }} /></div>
          </div>
          <div className="user-card">
            <div className="avatar">FC</div>
            <div className="info">
              <b>Hackathon</b>
              <span>local session</span>
            </div>
            <button className="more" aria-label="User menu">
              <Icon.moreH style={{ width: 16, height: 16 }} />
            </button>
          </div>
        </div>
      </aside>

      <div
        className="app-side-overlay"
        data-open={open}
        onClick={onClose}
        aria-hidden="true"
      />
    </>
  )
}
