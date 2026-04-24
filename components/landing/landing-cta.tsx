"use client"

import Link from "next/link"
import { motion } from "framer-motion"
import { ArrowRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ShieldLogo } from "@/components/shield-logo"

export function LandingCta() {
  return (
    <section className="relative py-24 sm:py-32 border-t border-border/40">
      <div className="mx-auto max-w-3xl px-6 text-center">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.6 }}
          className="relative"
        >
          <div
            className="absolute -inset-12 blur-3xl opacity-20 pointer-events-none rounded-full"
            style={{ background: "oklch(0.86 0.11 170)" }}
            aria-hidden="true"
          />

          <div className="relative inline-flex">
            <ShieldLogo size="lg" animate={false} />
          </div>

          <h2 className="mt-8 text-4xl sm:text-5xl md:text-6xl font-semibold tracking-tight text-balance leading-[1.05]">
            Don&apos;t ship guesses.
            <br />
            <span className="gradient-mint">Ship something safe.</span>
          </h2>
          <p className="mt-6 text-base sm:text-lg text-muted-foreground leading-relaxed">
            Your first scan is free. Find out what&apos;s hiding in your AI-built app
            in under 30 seconds.
          </p>

          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-3">
            <Button size="lg" asChild className="rounded-full h-12 px-7 glow-primary">
              <Link href="/scan">
                Start free scan
                <ArrowRight className="w-4 h-4 ml-1.5" />
              </Link>
            </Button>
            <Button
              variant="ghost"
              size="lg"
              asChild
              className="rounded-full h-12 px-6 text-muted-foreground hover:text-foreground"
            >
              <Link href="/report">View sample report</Link>
            </Button>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
