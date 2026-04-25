"use client"

import { useState, type ReactNode } from "react"
import { Sidebar } from "./_components/sidebar"
import { Icon } from "./_components/icons"

export default function AppLayout({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="app-shell">
      <button
        className="app-menu-btn"
        onClick={() => setOpen(true)}
        aria-label="Open menu"
      >
        <Icon.menu style={{ width: 18, height: 18 }} />
      </button>
      <Sidebar open={open} onClose={() => setOpen(false)} />
      <div className="app-content">{children}</div>
    </div>
  )
}
