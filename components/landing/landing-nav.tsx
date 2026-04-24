"use client"

import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ShieldLogo } from "@/components/shield-logo"
import { Menu } from "lucide-react"
import { useState } from "react"

export function LandingNav() {
  const [open, setOpen] = useState(false)

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-border/40 bg-background/70 backdrop-blur-xl">
      <nav className="mx-auto max-w-6xl px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <ShieldLogo size="sm" animate={false} />
          <span className="font-semibold tracking-tight text-base">VibeShield</span>
        </Link>

        <div className="hidden md:flex items-center gap-8">
          <a
            href="#tools"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Supported tools
          </a>
          <a
            href="#features"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Features
          </a>
          <a
            href="#how"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            How it works
          </a>
          <a
            href="#pricing"
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Pricing
          </a>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" asChild className="hidden sm:inline-flex">
            <Link href="/dashboard">Sign in</Link>
          </Button>
          <Button size="sm" asChild className="rounded-full px-4">
            <Link href="/scan">Start free scan</Link>
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={() => setOpen(!open)}
            aria-label="Toggle menu"
          >
            <Menu className="w-5 h-5" />
          </Button>
        </div>
      </nav>

      {open && (
        <div className="md:hidden border-t border-border/40 bg-background/95 backdrop-blur-xl">
          <div className="px-6 py-4 flex flex-col gap-3">
            <a href="#tools" className="text-sm text-muted-foreground" onClick={() => setOpen(false)}>
              Supported tools
            </a>
            <a href="#features" className="text-sm text-muted-foreground" onClick={() => setOpen(false)}>
              Features
            </a>
            <a href="#how" className="text-sm text-muted-foreground" onClick={() => setOpen(false)}>
              How it works
            </a>
            <a href="#pricing" className="text-sm text-muted-foreground" onClick={() => setOpen(false)}>
              Pricing
            </a>
          </div>
        </div>
      )}
    </header>
  )
}
