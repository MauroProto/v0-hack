"use client"

import { useEffect, useState } from "react"

const STAGES: { title: string; sub: string; duration: number }[] = [
  { title: "Connect to GitHub repository", sub: "Verifying access · detecting default branch", duration: 3 },
  { title: "Fetch GitHub tree", sub: "Recursive tree walk via REST API · no clone, no code execution", duration: 4 },
  { title: "Fetch supported blobs", sub: "Reading source files server-side · 500 files · 500 KB/file cap", duration: 6 },
  { title: "Fingerprint project", sub: "Frameworks · AI SDK usage · client vs. server boundaries", duration: 3 },
  { title: "Run deterministic security rules", sub: "Secret sweep · env leaks · auth gaps · AI endpoint guards · unsafe code", duration: 8 },
  { title: "AI review", sub: "Validating findings · plain-English explanations & recommendations", duration: 8 },
  { title: "Generate patch previews", sub: "Conservative, review-required suggestions", duration: 3 },
]

const fmt = (s: number) =>
  `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`

type Props = {
  done?: boolean
}

export function ScanProgress({ done = false }: Props) {
  const [step, setStep] = useState(0)
  const [now, setNow] = useState(0)

  const starts: number[] = []
  let acc = 0
  for (const s of STAGES) { starts.push(acc); acc += s.duration }
  const totalSec = acc

  useEffect(() => {
    if (done || step >= STAGES.length - 1) return

    const speed = done ? 8 : 1
    const ms = (STAGES[step].duration / speed) * 1000
    const t = setTimeout(() => setStep((s) => s + 1), ms)
    return () => clearTimeout(t)
  }, [step, done])

  useEffect(() => {
    const t0 = Date.now()
    const i = setInterval(() => setNow(Math.min((Date.now() - t0) / 1000, totalSec)), 250)
    return () => clearInterval(i)
  }, [totalSec])

  const complete = done
  const renderedStep = done ? STAGES.length : step

  return (
    <div className="scan-progress" style={{ marginTop: 18 }}>
      <div className="agent-head">
        <h4>Scan agent</h4>
        <span className="live">
          <span className="dot" />
          {complete ? `complete · ${fmt(totalSec)}` : `live · ${fmt(now)}`}
        </span>
      </div>
      <div className="timeline">
        {STAGES.map((s, i) => {
          const state: "done" | "active" | "pending" =
            i < renderedStep ? "done" : i === renderedStep ? "active" : "pending"
          const startStr = fmt(starts[i])
          const endStr = fmt(starts[i] + s.duration)
          const time =
            state === "done" ? `${startStr} → ${endStr}` :
            state === "active" ? `${startStr} → now` :
            "queued"
          return (
            <div key={i} className="tl-item" data-state={state}>
              <div className="tl-title">{s.title}</div>
              <div className="tl-sub">{s.sub}</div>
              <div className="tl-time">{time}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
