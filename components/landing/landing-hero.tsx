"use client"

import Link from "next/link"
import { motion } from "framer-motion"
import { ArrowRight, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ShieldLogo } from "@/components/shield-logo"

export function LandingHero() {
  return (
    <section className="relative pt-36 pb-20 sm:pt-44 sm:pb-28 overflow-hidden">
      {/* Background grid */}
      <div className="absolute inset-0 grid-pattern pointer-events-none" aria-hidden="true" />
      {/* Soft glow */}
      <div
        className="absolute top-32 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ background: "oklch(0.86 0.11 170)" }}
        aria-hidden="true"
      />

      <div className="relative mx-auto max-w-6xl px-6">
        <div className="flex flex-col items-center text-center">
          {/* Eyebrow badge */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 rounded-full border border-border bg-secondary/40 px-3.5 py-1.5 text-xs"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-primary" />
            <span className="text-muted-foreground">
              Built for vibe coders shipping with AI
            </span>
          </motion.div>

          {/* Heading */}
          <motion.h1
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.05 }}
            className="mt-7 text-balance text-5xl sm:text-6xl md:text-7xl font-semibold tracking-tight leading-[1.05]"
          >
            Scan your AI-built app
            <br />
            <span className="gradient-mint">before you ship.</span>
          </motion.h1>

          {/* Subheading */}
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.12 }}
            className="mt-6 max-w-2xl text-pretty text-base sm:text-lg text-muted-foreground leading-relaxed"
          >
            VibeShield finds the security flaws AI tools quietly introduce —
            exposed keys, broken auth, missing access controls — and shows you
            exactly how to fix them in seconds.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-10 flex flex-col sm:flex-row items-center gap-3"
          >
            <Button size="lg" asChild className="rounded-full h-12 px-7 text-sm font-medium glow-primary">
              <Link href="/scan">
                Start free scan
                <ArrowRight className="w-4 h-4 ml-1.5" />
              </Link>
            </Button>
            <Button
              variant="ghost"
              size="lg"
              asChild
              className="rounded-full h-12 px-6 text-sm font-medium text-muted-foreground hover:text-foreground"
            >
              <Link href="/report">See sample report</Link>
            </Button>
          </motion.div>

          {/* Trust line */}
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="mt-8 text-xs text-muted-foreground/70"
          >
            No credit card. First scan free. Results in under 30 seconds.
          </motion.p>

          {/* Hero shield graphic */}
          <motion.div
            initial={{ opacity: 0, scale: 0.92, y: 30 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.35, ease: "easeOut" }}
            className="mt-16 sm:mt-20 relative"
          >
            <div className="relative">
              <div
                className="absolute -inset-12 rounded-full blur-3xl opacity-30 pointer-events-none"
                style={{ background: "oklch(0.86 0.11 170)" }}
                aria-hidden="true"
              />
              <ShieldLogo size="xl" animate={false} className="relative" />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
