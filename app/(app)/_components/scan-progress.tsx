"use client"

import { useEffect, useMemo, useRef, useState } from "react"

const STAGES: { title: string; sub: string; duration: number }[] = [
  { title: "Connect to GitHub repository", sub: "Verifying access · detecting default branch", duration: 3 },
  { title: "Fetch GitHub tree", sub: "Recursive tree walk via REST API · no clone, no code execution", duration: 4 },
  { title: "Fetch supported blobs", sub: "Reading source files server-side · 500 files · 500 KB/file cap", duration: 6 },
  { title: "Fingerprint project", sub: "Frameworks · AI SDK usage · client vs. server boundaries", duration: 3 },
  { title: "Run deterministic security rules", sub: "Secret sweep · env leaks · auth gaps · AI endpoint guards · unsafe code", duration: 8 },
  { title: "AI review", sub: "Validating findings · plain-English explanations & recommendations", duration: 8 },
  { title: "Generate patch previews", sub: "Conservative, review-required suggestions · Max mode can take several minutes", duration: 3 },
]

const fmt = (s: number) =>
  `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`

const ROSE_CONFIG = {
  particleCount: 54,
  trailSpan: 0.32,
  durationMs: 5400,
  rotationDurationMs: 28000,
  pulseDurationMs: 4600,
  roseA: 9.2,
  roseABoost: 0.6,
  roseBreathBase: 0.72,
  roseBreathBoost: 0.28,
  roseK: 5,
  roseScale: 3.25,
}

type Props = {
  done?: boolean
}

export function ScanProgress({ done = false }: Props) {
  const [step, setStep] = useState(0)
  const [now, setNow] = useState(0)

  const starts: number[] = []
  let acc = 0
  for (const s of STAGES) { starts.push(acc); acc += s.duration }

  useEffect(() => {
    if (done || step >= STAGES.length - 1) return

    const speed = done ? 8 : 1
    const ms = (STAGES[step].duration / speed) * 1000
    const t = setTimeout(() => setStep((s) => s + 1), ms)
    return () => clearTimeout(t)
  }, [step, done])

  useEffect(() => {
    const t0 = Date.now()
    const i = setInterval(() => setNow((Date.now() - t0) / 1000), 250)
    return () => clearInterval(i)
  }, [])

  const complete = done
  const renderedStep = done ? STAGES.length : step
  const totalExpected = starts[starts.length - 1] + STAGES[STAGES.length - 1].duration
  const takingLonger = !done && now > totalExpected + 12

  return (
    <div className="scan-progress" style={{ marginTop: 18 }}>
      <div className="agent-head">
        <h4>Scan agent</h4>
        <span className="live">
          <span className="dot" />
          {complete ? `complete · ${fmt(now)}` : takingLonger ? `working · ${fmt(now)}` : `live · ${fmt(now)}`}
        </span>
      </div>
      {takingLonger && (
        <div className="scan-progress-note">
          Still working on the server. Large repositories and Max mode may wait on GitHub or AI provider responses.
        </div>
      )}
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
              {state === "active" && <RoseCurveLoader />}
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

function RoseCurveLoader() {
  const groupRef = useRef<SVGGElement | null>(null)
  const pathRef = useRef<SVGPathElement | null>(null)
  const particleRefs = useRef<SVGCircleElement[]>([])
  const particles = useMemo(() => Array.from({ length: ROSE_CONFIG.particleCount }, (_, index) => index), [])

  useEffect(() => {
    const group = groupRef.current
    const path = pathRef.current
    if (!group || !path) return

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    const startedAt = performance.now()
    let frame = 0

    const render = (now: number) => {
      const time = now - startedAt
      const progress = (time % ROSE_CONFIG.durationMs) / ROSE_CONFIG.durationMs
      const detailScale = reducedMotion ? 0.78 : roseDetailScale(time)

      group.setAttribute("transform", `rotate(${reducedMotion ? 0 : roseRotation(time)} 50 50)`)
      path.setAttribute("d", buildRosePath(detailScale))

      particleRefs.current.forEach((node, index) => {
        const particle = roseParticle(index, progress, detailScale)
        node.setAttribute("cx", particle.x.toFixed(2))
        node.setAttribute("cy", particle.y.toFixed(2))
        node.setAttribute("r", particle.radius.toFixed(2))
        node.setAttribute("opacity", particle.opacity.toFixed(3))
      })

      if (!reducedMotion) frame = requestAnimationFrame(render)
    }

    frame = requestAnimationFrame(render)
    return () => cancelAnimationFrame(frame)
  }, [])

  return (
    <span className="tl-rose-loader" aria-hidden="true">
      <svg viewBox="0 0 100 100" fill="none">
        <g ref={groupRef}>
          <path ref={pathRef} className="rose-path" stroke="currentColor" strokeWidth="4.5" />
          {particles.map((index) => (
            <circle
              className="rose-particle"
              fill="currentColor"
              key={index}
              ref={(node) => {
                if (node) particleRefs.current[index] = node
              }}
            />
          ))}
        </g>
      </svg>
    </span>
  )
}

function rosePoint(progress: number, detailScale: number) {
  const t = progress * Math.PI * 2
  const a = ROSE_CONFIG.roseA + detailScale * ROSE_CONFIG.roseABoost
  const r =
    a *
    (ROSE_CONFIG.roseBreathBase + detailScale * ROSE_CONFIG.roseBreathBoost) *
    Math.cos(ROSE_CONFIG.roseK * t)

  return {
    x: 50 + Math.cos(t) * r * ROSE_CONFIG.roseScale,
    y: 50 + Math.sin(t) * r * ROSE_CONFIG.roseScale,
  }
}

function roseDetailScale(time: number) {
  const pulseProgress = (time % ROSE_CONFIG.pulseDurationMs) / ROSE_CONFIG.pulseDurationMs
  return 0.52 + ((Math.sin(pulseProgress * Math.PI * 2 + 0.55) + 1) / 2) * 0.48
}

function roseRotation(time: number) {
  return -((time % ROSE_CONFIG.rotationDurationMs) / ROSE_CONFIG.rotationDurationMs) * 360
}

function buildRosePath(detailScale: number, steps = 240) {
  return Array.from({ length: steps + 1 }, (_, index) => {
    const point = rosePoint(index / steps, detailScale)
    return `${index === 0 ? "M" : "L"} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`
  }).join(" ")
}

function roseParticle(index: number, progress: number, detailScale: number) {
  const tailOffset = index / (ROSE_CONFIG.particleCount - 1)
  const point = rosePoint(normalizeProgress(progress - tailOffset * ROSE_CONFIG.trailSpan), detailScale)
  const fade = Math.pow(1 - tailOffset, 0.56)

  return {
    x: point.x,
    y: point.y,
    radius: 0.9 + fade * 2.7,
    opacity: 0.04 + fade * 0.96,
  }
}

function normalizeProgress(progress: number) {
  return ((progress % 1) + 1) % 1
}
