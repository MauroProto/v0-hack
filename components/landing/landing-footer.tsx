import Link from "next/link"
import { ShieldLogo } from "@/components/shield-logo"

export function LandingFooter() {
  return (
    <footer className="border-t border-border/40 py-12">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
          <div className="flex items-center gap-2.5">
            <ShieldLogo size="sm" animate={false} />
            <span className="font-semibold tracking-tight">VibeShield</span>
          </div>

          <nav className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-muted-foreground">
            <Link href="/scan" className="hover:text-foreground transition-colors">
              Scan
            </Link>
            <Link href="/report" className="hover:text-foreground transition-colors">
              Sample report
            </Link>
            <a href="#features" className="hover:text-foreground transition-colors">
              Features
            </a>
            <a href="#how" className="hover:text-foreground transition-colors">
              How it works
            </a>
            <a href="#" className="hover:text-foreground transition-colors">
              Privacy
            </a>
            <a href="#" className="hover:text-foreground transition-colors">
              Terms
            </a>
          </nav>
        </div>

        <div className="mt-10 pt-6 border-t border-border/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-muted-foreground">
          <p>© {new Date().getFullYear()} VibeShield. Ship fast. Stay safe.</p>
          <p>Made for the vibe-coding generation.</p>
        </div>
      </div>
    </footer>
  )
}
