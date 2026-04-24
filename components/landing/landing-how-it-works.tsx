"use client"

import { motion } from "framer-motion"

const steps = [
  {
    n: "01",
    title: "Drop in your repo",
    desc: "Paste a GitHub URL, connect your repo, or upload a zip. We never store your source code.",
  },
  {
    n: "02",
    title: "We scan it like an attacker",
    desc: "VibeShield's engine traces auth, data flow, and config across your whole project — not just one file at a time.",
  },
  {
    n: "03",
    title: "Get your report and ship",
    desc: "A ranked list of real, exploitable issues with one-click patches. Reach a 90+ score before you go live.",
  },
]

export function LandingHowItWorks() {
  return (
    <section id="how" className="relative py-20 sm:py-28 border-t border-border/40">
      <div className="mx-auto max-w-6xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5 }}
          className="max-w-2xl"
        >
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground/80 font-medium">
            How it works
          </p>
          <h2 className="mt-3 text-3xl sm:text-4xl md:text-5xl font-semibold tracking-tight text-balance leading-[1.1]">
            Three steps. Under a minute.
          </h2>
        </motion.div>

        <div className="mt-14 grid md:grid-cols-3 gap-px bg-border/50 border border-border/50 rounded-2xl overflow-hidden">
          {steps.map((s, i) => (
            <motion.div
              key={s.n}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-80px" }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="bg-background p-8 sm:p-10"
            >
              <span className="font-mono text-xs text-primary font-medium">{s.n}</span>
              <h3 className="mt-6 text-xl font-semibold tracking-tight">{s.title}</h3>
              <p className="mt-3 text-sm text-muted-foreground leading-relaxed">{s.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
