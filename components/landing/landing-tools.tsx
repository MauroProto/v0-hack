"use client"

import Image from "next/image"
import { motion } from "framer-motion"

const tools = [
  { name: "Bolt", src: "/logos/bolt.png", invert: true },
  { name: "v0", src: "/logos/v0.png", invert: true },
  { name: "Lovable", src: "/logos/lovable.png", invert: false },
  { name: "Cursor", src: "/logos/cursor.png", invert: false },
  { name: "Replit", src: "/logos/replit.png", invert: false },
  { name: "Windsurf", src: "/logos/windsurf.png", invert: true },
  { name: "Tempo", src: "/logos/tempo.png", invert: true },
  { name: "Claude", src: "/logos/claude.png", invert: true },
]

export function LandingTools() {
  return (
    <section id="tools" className="relative py-20 sm:py-28 border-t border-border/40">
      <div className="mx-auto max-w-6xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5 }}
          className="text-center"
        >
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground/80 font-medium">
            Built with these tools? We&apos;ve got you.
          </p>
          <h2 className="mt-4 text-3xl sm:text-4xl font-semibold tracking-tight text-balance">
            Trained on the code your favorite AI&nbsp;tools generate.
          </h2>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-px bg-border/50 rounded-2xl overflow-hidden border border-border/50"
        >
          {tools.map((tool) => (
            <div
              key={tool.name}
              className="group relative flex flex-col items-center justify-center gap-3 bg-background hover:bg-secondary/40 transition-colors aspect-[5/3] sm:aspect-[5/2] p-6"
            >
              <div className="relative w-10 h-10 sm:w-11 sm:h-11 flex items-center justify-center">
                <Image
                  src={tool.src || "/placeholder.svg"}
                  alt={`${tool.name} logo`}
                  width={44}
                  height={44}
                  className={`object-contain w-full h-full opacity-80 group-hover:opacity-100 transition-opacity ${
                    tool.invert ? "invert" : ""
                  }`}
                />
              </div>
              <span className="text-sm font-medium text-muted-foreground group-hover:text-foreground transition-colors">
                {tool.name}
              </span>
            </div>
          ))}
        </motion.div>

        <p className="mt-6 text-center text-sm text-muted-foreground">
          And any other code editor or generator. If it produces JavaScript, TypeScript, or Python — VibeShield can scan it.
        </p>
      </div>
    </section>
  )
}
