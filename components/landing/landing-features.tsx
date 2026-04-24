"use client"

import { motion } from "framer-motion"
import { Eye, Wand2, Zap, Brain } from "lucide-react"

const features = [
  {
    icon: Eye,
    title: "Context-aware analysis",
    desc: "We don't just match patterns. VibeShield reads your code the way an attacker would — across files, routes, and data flow.",
  },
  {
    icon: Wand2,
    title: "One-click auto-fix",
    desc: "Every issue ships with a ready-to-apply patch. Review the diff, hit apply, move on. No StackOverflow needed.",
  },
  {
    icon: Zap,
    title: "Built for AI-generated code",
    desc: "Trained on the exact mistakes Bolt, v0, Cursor, and friends repeat. Catches the gotchas other scanners ignore.",
  },
  {
    icon: Brain,
    title: "Explained in plain English",
    desc: "No CVE codenames. Every finding tells you what's wrong, why it matters, and what an attacker could do with it.",
  },
]

export function LandingFeatures() {
  return (
    <section id="features" className="relative py-20 sm:py-28 border-t border-border/40">
      <div className="mx-auto max-w-6xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5 }}
          className="max-w-2xl"
        >
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground/80 font-medium">
            Why VibeShield
          </p>
          <h2 className="mt-3 text-3xl sm:text-4xl md:text-5xl font-semibold tracking-tight text-balance leading-[1.1]">
            Security that keeps up with the speed of vibes.
          </h2>
        </motion.div>

        <div className="mt-14 grid sm:grid-cols-2 gap-4">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-80px" }}
              transition={{ duration: 0.5, delay: i * 0.08 }}
              className="group relative rounded-2xl border border-border bg-card/40 p-7 hover:border-primary/30 hover:bg-card/70 transition-colors"
            >
              <div className="w-10 h-10 rounded-xl border border-border bg-secondary/40 flex items-center justify-center mb-5 group-hover:border-primary/40 group-hover:bg-primary/10 transition-colors">
                <f.icon className="w-5 h-5 text-primary" />
              </div>
              <h3 className="text-lg font-semibold tracking-tight">{f.title}</h3>
              <p className="mt-2 text-sm text-muted-foreground leading-relaxed">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
