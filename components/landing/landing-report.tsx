"use client"

import { motion } from "framer-motion"
import { AlertTriangle, ShieldCheck, KeyRound, Lock, FileWarning, Sparkles } from "lucide-react"

const findings = [
  {
    severity: "critical",
    icon: KeyRound,
    title: "Supabase service role key exposed in client",
    file: "lib/supabase.ts",
    line: 12,
  },
  {
    severity: "critical",
    icon: Lock,
    title: "Missing auth check on /api/admin/users route",
    file: "app/api/admin/users/route.ts",
    line: 8,
  },
  {
    severity: "high",
    icon: FileWarning,
    title: "User input passed directly to SQL query",
    file: "app/api/search/route.ts",
    line: 24,
  },
  {
    severity: "medium",
    icon: AlertTriangle,
    title: "CORS configured to allow all origins",
    file: "middleware.ts",
    line: 14,
  },
]

const severityStyles: Record<string, string> = {
  critical: "text-destructive bg-destructive/10 border-destructive/30",
  high: "text-warning bg-warning/10 border-warning/30",
  medium: "text-info bg-info/10 border-info/30",
}

export function LandingReport() {
  return (
    <section className="relative py-20 sm:py-28 border-t border-border/40">
      <div className="mx-auto max-w-6xl px-6">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left: copy */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-80px" }}
            transition={{ duration: 0.6 }}
            className="max-w-xl"
          >
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-secondary/40 px-3 py-1 text-xs">
              <Sparkles className="w-3.5 h-3.5 text-primary" />
              <span className="text-muted-foreground">A real report, not a wall of warnings</span>
            </div>
            <h2 className="mt-5 text-3xl sm:text-4xl md:text-5xl font-semibold tracking-tight text-balance leading-[1.1]">
              The flaws AI tools love to ship.
              <br />
              <span className="text-muted-foreground">We catch them all.</span>
            </h2>
            <p className="mt-5 text-base text-muted-foreground leading-relaxed">
              Most AI-generated apps look great until someone reads the code.
              VibeShield reads it for you, ranked by what could actually hurt
              your users — with one-click fixes you can review and apply.
            </p>

            <ul className="mt-8 space-y-3.5">
              {[
                "Exposed API keys, tokens, and database credentials",
                "Broken auth and missing route protection",
                "Insecure direct object references and IDOR",
                "Unsafe SQL, unsanitized inputs, and XSS gaps",
                "Misconfigured CORS, headers, and Supabase RLS",
              ].map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <ShieldCheck className="w-5 h-5 text-primary shrink-0 mt-0.5" />
                  <span className="text-sm text-foreground/90">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Right: report mock */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-80px" }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="relative"
          >
            <div
              className="absolute -inset-8 blur-3xl opacity-20 pointer-events-none rounded-full"
              style={{ background: "oklch(0.86 0.11 170)" }}
              aria-hidden="true"
            />

            <div className="relative rounded-2xl border border-border bg-card overflow-hidden shadow-2xl shadow-black/40">
              {/* Window chrome */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-secondary/30">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-muted-foreground/30" />
                  <span className="w-2.5 h-2.5 rounded-full bg-muted-foreground/30" />
                  <span className="w-2.5 h-2.5 rounded-full bg-muted-foreground/30" />
                </div>
                <span className="text-[11px] font-mono text-muted-foreground">
                  vibeshield.app/report/my-saas
                </span>
                <span className="w-12" />
              </div>

              {/* Report body */}
              <div className="p-6">
                <div className="flex items-center justify-between gap-4 pb-5 border-b border-border">
                  <div>
                    <p className="text-xs text-muted-foreground">Security score</p>
                    <p className="mt-1 text-4xl font-semibold tracking-tight">
                      42<span className="text-muted-foreground/60 text-2xl">/100</span>
                    </p>
                    <p className="mt-1 text-xs text-destructive font-medium">Action required</p>
                  </div>

                  {/* Mini score ring */}
                  <div className="relative w-20 h-20 shrink-0">
                    <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                      <circle
                        cx="50"
                        cy="50"
                        r="42"
                        fill="none"
                        stroke="var(--color-border)"
                        strokeWidth="8"
                      />
                      <motion.circle
                        cx="50"
                        cy="50"
                        r="42"
                        fill="none"
                        stroke="var(--color-destructive)"
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={`${2 * Math.PI * 42}`}
                        initial={{ strokeDashoffset: 2 * Math.PI * 42 }}
                        whileInView={{ strokeDashoffset: 2 * Math.PI * 42 * (1 - 0.42) }}
                        viewport={{ once: true }}
                        transition={{ duration: 1.2, ease: "easeOut" }}
                      />
                    </svg>
                  </div>
                </div>

                {/* Severity counters */}
                <div className="grid grid-cols-3 gap-2 mt-5">
                  {[
                    { label: "Critical", count: 2, cls: "text-destructive" },
                    { label: "High", count: 5, cls: "text-warning" },
                    { label: "Medium", count: 11, cls: "text-info" },
                  ].map((s) => (
                    <div
                      key={s.label}
                      className="rounded-lg border border-border bg-secondary/30 p-3"
                    >
                      <p className={`text-xl font-semibold ${s.cls}`}>{s.count}</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">{s.label}</p>
                    </div>
                  ))}
                </div>

                {/* Findings list */}
                <div className="mt-5 space-y-2">
                  {findings.map((f, i) => (
                    <motion.div
                      key={f.title}
                      initial={{ opacity: 0, x: -12 }}
                      whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }}
                      transition={{ duration: 0.4, delay: 0.2 + i * 0.08 }}
                      className="flex items-center gap-3 rounded-lg border border-border bg-secondary/20 hover:bg-secondary/40 px-3 py-2.5 transition-colors"
                    >
                      <span
                        className={`shrink-0 w-7 h-7 rounded-md border flex items-center justify-center ${severityStyles[f.severity]}`}
                      >
                        <f.icon className="w-3.5 h-3.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium truncate">{f.title}</p>
                        <p className="text-[11px] font-mono text-muted-foreground truncate">
                          {f.file}:{f.line}
                        </p>
                      </div>
                      <button className="shrink-0 text-[11px] font-medium text-primary hover:text-primary/80 transition-colors">
                        Auto-fix
                      </button>
                    </motion.div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
