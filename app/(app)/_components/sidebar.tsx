"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Icon } from "./icons"

type Repo = { name: string; status: "warn" | "ok"; href: string }

const REPOS: Repo[] = [
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
  {
    key: "current",
    label: "New scan",
    icon: "focus",
    href: "/scan",
    match: (p) => p === "/scan" || p.startsWith("/report/"),
  },
  { key: "scans", label: "Scan history", icon: "scan", href: "/scans" },
  {
    key: "repos",
    label: "GitHub repos",
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
          </div>

          <div className="org-card">
            <div className="avatar">VS</div>
            <div className="name">GitHub security scanner</div>
            <span className="plan">20 scans/day</span>
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

          <div className="side-section-label">Scan sources</div>
          <div className="side-nav">
            {REPOS.map((r) => (
              <Link
                key={r.name}
                href={r.href}
                className="repo-link"
                data-active={pathname === r.href}
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
            <div className="avatar">GH</div>
            <div className="info">
              <b>GitHub-first</b>
              <span>server-side analysis</span>
            </div>
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
