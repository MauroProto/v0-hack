"use client"

import { useState, useEffect, type ReactNode, type SVGProps } from "react"
import Link from "next/link"

type IconProps = SVGProps<SVGSVGElement>

type LogoItem = {
  src: string
  alt: string
  name?: string
  mono?: boolean
}

const LOGO_ITEMS: LogoItem[] = [
  { src: "/logos/v0.png", alt: "v0", mono: true },
  { src: "/logos/cursor.png", alt: "Copilot", name: "Copilot", mono: true },
  { src: "/logos/claude.png", alt: "Claude Code", name: "Claude Code" },
  { src: "/logos/lovable.png", alt: "Lovable", name: "Lovable" },
  { src: "/logos/bolt.png", alt: "Bolt", name: "Bolt", mono: true },
  { src: "/logos/windsurf.png", alt: "Windsurf", name: "Windsurf", mono: true },
  { src: "/logos/replit.png", alt: "Replit", name: "Replit" },
  { src: "/logos/tempo.png", alt: "Cursor", name: "Cursor", mono: true },
]

const LOGO_MARQUEE_COPIES = 6

// ---------- Icons (hairline) ----------
const I = {
  shield: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6l-8-3z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  ),
  arrow: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M5 12h14" />
      <path d="m13 6 6 6-6 6" />
    </svg>
  ),
  github: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="currentColor" {...p}>
      <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.95 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.03a9.5 9.5 0 0 1 5 0c1.91-1.3 2.75-1.03 2.75-1.03.55 1.37.2 2.39.1 2.64.64.7 1.03 1.6 1.03 2.69 0 3.85-2.34 4.7-4.57 4.95.36.31.68.93.68 1.88v2.79c0 .26.18.58.69.48A10 10 0 0 0 12 2Z" />
    </svg>
  ),
  gitbranch: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <circle cx="6" cy="5" r="2" />
      <circle cx="6" cy="19" r="2" />
      <circle cx="18" cy="12" r="2" />
      <path d="M6 7v10" />
      <path d="M6 14a6 6 0 0 0 6-6h4" />
    </svg>
  ),
  zip: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M10 10h2v2h-2z" />
      <path d="M12 12h-2v2h2z" />
      <path d="M10 14h2v2h-2z" />
    </svg>
  ),
  sparkle: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8" />
    </svg>
  ),
  bolt: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M13 2 4 14h7l-1 8 9-12h-7z" />
    </svg>
  ),
  key: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.85 12.15 7.4-7.4" />
      <path d="m18 5 3 3" />
      <path d="m15 8 2 2" />
    </svg>
  ),
  lock: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  ),
  upload: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="m17 8-5-5-5 5" />
      <path d="M12 3v12" />
    </svg>
  ),
  scan: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M3 7V5a2 2 0 0 1 2-2h2" />
      <path d="M17 3h2a2 2 0 0 1 2 2v2" />
      <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
      <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
      <path d="M8 12h8" />
    </svg>
  ),
  info: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v.01" />
      <path d="M11 12h1v4h1" />
    </svg>
  ),
  link: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 1 0-7-7l-1 1" />
      <path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 1 0 7 7l1-1" />
    </svg>
  ),
  agent: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <rect x="3" y="7" width="18" height="13" rx="3" />
      <circle cx="9" cy="13" r="1.2" />
      <circle cx="15" cy="13" r="1.2" />
      <path d="M12 3v4" />
      <path d="M8 20v1" />
      <path d="M16 20v1" />
    </svg>
  ),
  doc: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M9 13h6" />
      <path d="M9 17h4" />
    </svg>
  ),
  share: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <path d="m8.6 13.5 6.8 4" />
      <path d="m15.4 6.5-6.8 4" />
    </svg>
  ),
  wand: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="m14 4 6 6-12 12-6-6z" />
      <path d="m13 5 6 6" />
      <path d="M18 3v2M22 4h-2M19 7h2" />
    </svg>
  ),
  chevron: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  ),
  search: (p: IconProps) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  ),
}

// ---------- Nav ----------
function Nav() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40)
    onScroll()
    window.addEventListener("scroll", onScroll, { passive: true })
    return () => window.removeEventListener("scroll", onScroll)
  }, [])
  return (
    <header className={`nav ${scrolled ? "is-scrolled" : ""}`}>
      <div className="wrap nav-inner">
        <Link href="/" className="brand">
          <span style={{ fontSize: 17 }}>Badger</span>
          <span className="pill" style={{ marginLeft: 10, height: 24, fontSize: 12, padding: "0 9px" }}>Beta</span>
        </Link>
        <nav className="nav-links">
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a href="#report">Report</a>
          <a href="#scan">Scan</a>
        </nav>
        <div className="nav-right">
          <Link href="/scan" className="btn btn-primary nav-cta">
            Start free scan <I.scan style={{ width: 14, height: 14 }} />
          </Link>
        </div>
      </div>
    </header>
  )
}

// ---------- Hero ----------
function Hero() {
  return (
    <section className="hero">
      <div className="hero-grid" />
      <div className="wrap hero-inner">
        <h1 className="display">
          <span className="line">Stop shipping</span>
          <span className="line"><em>AI-built apps</em> blind.</span>
        </h1>
        <p className="lead">
          AI builders can turn an idea into a working app in hours, but the security
          review still lands on you. Badger turns a GitHub repo into an evidence-based
          AppSec report so you can spot exposed secrets, missing auth, risky AI endpoints,
          unsafe tool calls and supply-chain issues before customers or maintainers do.
        </p>
        <div className="hero-cta">
          <Link href="/scan" className="btn btn-accent btn-lg btn-border-spin btn-shine">Start free scan <I.scan style={{ width: 14, height: 14 }} /></Link>
        </div>
        <div className="hero-meta">
          <span><b>No install.</b> Paste a public repo without GitHub login.</span>
          <span className="sep" />
          <span><b>Server-side.</b> GitHub tree and blob APIs, no browser repo reads.</span>
          <span className="sep" />
          <span><b>Hybrid review.</b> Deterministic checks first, AI triage second.</span>
        </div>

        {/* logos marquee */}
        <div className="logos">
          <div className="marquee-track">
            {Array.from({ length: LOGO_MARQUEE_COPIES }, (_, copyIndex) => (
              <div className="marquee-set" key={copyIndex} aria-hidden={copyIndex > 0}>
                {LOGO_ITEMS.map((item) => (
                  <span className="logo" key={`${copyIndex}-${item.alt}`}>
                    {item.mono ? (
                      <span className="logo-mono">
                        <img src={item.src} alt={copyIndex === 0 ? item.alt : ""} />
                      </span>
                    ) : (
                      <img src={item.src} alt={copyIndex === 0 ? item.alt : ""} />
                    )}
                    {item.name && <span className="name">{item.name}</span>}
                  </span>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

// ---------- Dashboard preview ----------
type Finding = {
  sev: "critical" | "high" | "medium" | "low"
  msg: string
  path: string
  line: number
  age: string
  ico: ReactNode
}

const FINDINGS: Finding[] = [
  { sev: "critical", msg: "Secret exposure rule", path: "committed env values", line: 1, age: "scanner", ico: <I.key /> },
  { sev: "critical", msg: "Missing auth rule", path: "sensitive API routes", line: 1, age: "scanner", ico: <I.lock /> },
  { sev: "high", msg: "AI abuse guard rule", path: "model endpoints", line: 1, age: "scanner", ico: <I.bolt /> },
  { sev: "high", msg: "Unsafe tool dispatch rule", path: "agent/tool handlers", line: 1, age: "scanner", ico: <I.sparkle /> },
  { sev: "medium", msg: "Public env misuse rule", path: "NEXT_PUBLIC_* values", line: 1, age: "scanner", ico: <I.key /> },
  { sev: "medium", msg: "Input validation rule", path: "JSON request handlers", line: 1, age: "scanner", ico: <I.lock /> },
  { sev: "low", msg: "Production hardening rule", path: "Next.js/Vercel signals", line: 1, age: "scanner", ico: <I.bolt /> },
]

function ScoreRing({ value }: { value: number }) {
  const r = 24
  const c = 2 * Math.PI * r
  const off = c * (1 - value / 100)
  return (
    <svg width="64" height="64" viewBox="0 0 64 64" aria-hidden="true">
      <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="4" />
      <circle
        cx="32" cy="32" r={r} fill="none"
        stroke="var(--accent)" strokeWidth="4" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={off}
        transform="rotate(-90 32 32)"
      />
    </svg>
  )
}

function TimelineItem({
  state,
  title,
  sub,
  time,
  code,
}: {
  state: "done" | "active" | "pending"
  title: string
  sub?: string
  time?: string
  code?: ReactNode
}) {
  return (
    <div className="tl-item" data-state={state}>
      <div className="tl-title">{title}</div>
      {sub && <div className="tl-sub">{sub}</div>}
      {time && <div className="tl-time">{time}</div>}
      {code && <div className="tl-code">{code}</div>}
    </div>
  )
}

function Dashboard() {
  return (
    <section className="section" id="report">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">The report</span>
          <h2>Know what is risky, what is noise, and what deserves action.</h2>
          <p>
            Badger separates vulnerabilities from hardening and posture debt, then shows
            the evidence behind each call: file and line references, confidence, risk category,
            AI triage, and conservative fix paths that still require human review.
          </p>
        </div>

        <div className="surface dash">
          <div className="dash-chrome">
            <div className="dash-dots"><span /><span /><span /></div>
            <div className="dash-url">
              <I.lock style={{ width: 12, height: 12 }} />
              <span>app.badger.dev/</span>
              <span className="path">report/{'{scanId}'}</span>
            </div>
            <span className="pill" style={{ height: 22, fontSize: 11 }}>
              <span className="dot" /> scan complete
            </span>
          </div>

          <div className="dash-body">
            {/* MAIN */}
            <div className="dash-main">
              <div className="dash-head">
                <div className="title">
                  <div className="crumb">
                    Badger <I.chevron style={{ width: 12, height: 12 }} /> real scan output{" "}
                    <I.chevron style={{ width: 12, height: 12 }} /> report interface
                  </div>
                  <h3>Security report <span className="repo">· GitHub tree + blobs</span></h3>
                </div>
                <div className="actions">
                  <span className="btn btn-outline"><I.share /> Share</span>
                  <span className="btn btn-outline"><I.doc /> Issue body</span>
                  <span className="btn btn-accent"><I.wand /> Fix previews</span>
                </div>
              </div>

              <div className="score-row">
                <div className="score-card score-main">
                  <div className="lbl">Overall posture</div>
                  <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 14 }}>
                    <div>
                      <div className="val" style={{ fontSize: 34 }}>62<small>/ 100</small></div>
                      <div className="sub">Needs attention before deploy</div>
                    </div>
                    <ScoreRing value={62} />
                  </div>
                </div>
                <div className="score-card sev-crit">
                  <div className="lbl">Critical</div>
                  <div className="val">2</div>
                  <div className="sub">Block deploy · exposed secret, open route</div>
                </div>
                <div className="score-card sev-med">
                  <div className="lbl">High · Medium</div>
                  <div className="val">2 <small style={{ color: "var(--fg-4)" }}>/</small> 4</div>
                  <div className="sub">Auth gaps &amp; unsafe env usage</div>
                </div>
                <div className="score-card sev-low">
                  <div className="lbl">Low · Info</div>
                  <div className="val">9</div>
                  <div className="sub">Hygiene &amp; best-practice notes</div>
                </div>
              </div>

              <div className="findings-head">
                <h4>Findings</h4>
                <div className="filter">
                  <span className="chip" data-active="true">All <span className="n">15</span></span>
                  <span className="chip">Critical <span className="n">2</span></span>
                  <span className="chip">AI risks <span className="n">4</span></span>
                  <span className="chip">Secrets <span className="n">3</span></span>
                  <span className="chip">Routes <span className="n">6</span></span>
                </div>
              </div>

              <div className="findings">
                {FINDINGS.map((f, i) => (
                  <div className="finding" key={i}>
                    <div className="ico">{f.ico}</div>
                    <div className={`sev sev-${f.sev}`}><span className="dot" />{f.sev}</div>
                    <div>
                      <div className="msg">{f.msg}</div>
                      <div className="path">{f.path}<b>:{f.line}</b></div>
                    </div>
                    <div className="meta">{f.age}</div>
                    <span className="action" aria-hidden="true"><I.wand style={{ width: 12, height: 12 }} /> Patch</span>
                  </div>
                ))}
              </div>
            </div>

            {/* SIDE: Agent timeline */}
            <aside className="dash-side">
              <div className="agent-head">
                <h4>Scan agent</h4>
                <span className="live"><span className="dot" /> live · 00:42</span>
              </div>

              <div className="timeline">
	                <TimelineItem state="done" title="Read GitHub tree" sub="Server-side REST API · no ZIP upload · no code execution" time="stage 1" />
	                <TimelineItem state="done" title="Detect framework signals" sub="Next.js, React, AI SDK and client component signals" time="stage 2" />
	                <TimelineItem state="done" title="Secret & key sweep" sub="Provider key formats, env files and NEXT_PUBLIC misuse" time="stage 3" />
	                <TimelineItem state="done" title="Route & auth graph" sub="API route, auth, validation and mutation patterns" time="stage 4" />
                <TimelineItem
                  state="active"
                  title="AI endpoint & tool review"
                  sub="Analyzing chat routes, MCP tools and rate limits"
	                  time="stage 5"
                  code={
                    <>
                      <span className="c"># checking</span>{"\n"}
                      <span className="k">→</span> app/api/chat/route.ts{"\n"}
                      <span className="k">→</span> tools/shell.ts{"\n"}
                      <span className="c"># 3 suggestions queued</span>
                    </>
                  }
                />
                <TimelineItem state="pending" title="Generate patch previews" sub="Conservative, review-required suggestions" time="queued" />
              </div>
            </aside>
          </div>
        </div>
      </div>
    </section>
  )
}

// ---------- Features ----------
function Features() {
  return (
    <section className="section" id="features">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">What it reviews</span>
          <h2>Built for teams moving faster than their security review process.</h2>
          <p>
            Badger checks the places where AI-built apps usually break security: auth,
            secrets, agent tools, data access, dependencies and remediation workflow.
          </p>
        </div>

        <div className="features">
          <article className="feature f-third">
            <div className="f-icon"><I.scan /></div>
            <h3>Server-side repo scan</h3>
            <p>
              Reads supported GitHub files through the API without cloning, installing dependencies
              or running untrusted code.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.sparkle /></div>
            <h3>AI and agent risk</h3>
            <p>
              Reviews AI routes, tool calling and MCP surfaces for weak auth, missing limits and
              overly broad execution paths.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.key /></div>
            <h3>Secrets and env vars</h3>
            <p>
              Detects committed credentials, risky env files and dangerous browser-exposed
              <code> NEXT_PUBLIC_*</code> contracts with context-aware filtering.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.lock /></div>
            <h3>Routes and auth</h3>
            <p>
              Maps route handlers, Server Actions, validation calls, auth signals and database
              writes so sensitive code gets reviewed first.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.agent /></div>
            <h3>Tool and MCP review</h3>
            <p>
              Flags shell tools, MCP process spawning, full environment inheritance and tool calls
              without clear boundaries.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.share /></div>
            <h3>Reports and fixes</h3>
            <p>
              Produces evidence-based reports and conservative fix drafts that stay reviewable
              instead of creating noisy public PRs.
            </p>
          </article>
        </div>
      </div>
    </section>
  )
}

// ---------- How it works ----------
function How() {
  const steps = [
    { n: "01", title: "Paste a repo or connect GitHub", body: "Scan public GitHub URLs without logging in. Connect GitHub only when you want account repositories, private repos or PR creation.", ico: <I.github /> },
    { n: "02", title: "Run the harness", body: "The server reads GitHub metadata, tree entries and selected blobs, then runs deterministic analyzers for secrets, routes, dependencies, AI endpoints and repo posture.", ico: <I.scan /> },
    { n: "03", title: "Review evidence", body: "The report ranks findings with file:line references, confidence, risk breakdown and AI triage so you can tell signal from noise.", ico: <I.search /> },
    { n: "04", title: "Fix what is safe", body: "Generate review-required patch previews and PR-ready hygiene changes only when the evidence supports them.", ico: <I.wand /> },
  ]
  return (
    <section className="section" id="how">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">How it works</span>
          <h2>Four steps from <em>prompt</em> to <em>security review</em>.</h2>
        </div>
        <div className="howit">
          {steps.map((s) => (
            <div className="step" key={s.n}>
              <div className="ico">{s.ico}</div>
              <span className="num">{s.n}</span>
              <h4>{s.title}</h4>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ---------- Closing (CTA + stats + footer, unified gradient) ----------
function Closing() {
  return (
    <section className="closing">
      <div className="closing-cta">
        <span className="eyebrow">Free in beta</span>
        <h2>
          Turn an AI-built repo<br />
          into a security decision.
        </h2>
        <p>Scan your first repo without installs, ZIP uploads or running untrusted code.</p>
        <div className="cta-actions">
          <Link href="/scan" className="btn btn-accent btn-lg btn-border-spin btn-shine">
            Start free scan <I.scan style={{ width: 14, height: 14 }} />
          </Link>
        </div>
      </div>

      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Link href="/" className="brand">
              <span>Badger</span>
            </Link>
            <p>An evidence-first security review layer for apps built with AI.</p>
            <span className="status"><span className="dot" /> All systems operational</span>
          </div>
          <div className="cols">
            <div className="col">
              <h5>Product</h5>
              <a href="#features">Features</a>
              <a href="#how">How it works</a>
              <a href="#report">Sample report</a>
              <Link href="/scan">Scanner</Link>
            </div>
            <div className="col">
              <h5>Integrations</h5>
              <Link href="/scan">GitHub</Link>
            </div>
            <div className="col">
              <h5>Resources</h5>
              <Link href="/docs">Docs</Link>
            </div>
            <div className="col">
              <h5>Company</h5>
              <Link href="/scan">Security</Link>
            </div>
          </div>
        </div>

        <div className="wordmark" aria-hidden="true">
          Badger
        </div>

        <div className="footer-bottom">
          <span>© 2026 Badger Labs · Not a guarantee of security.</span>
          <div className="socials">
            <a href="https://github.com/MauroProto/badger" aria-label="GitHub">
              <I.github />
            </a>
            <a href="https://x.com/ProtoMauro" aria-label="X">
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M18.9 3H22l-7.5 8.6L23 21h-6.8l-5.3-6.9L4.7 21H1.5l8-9.2L1 3h6.9l4.8 6.3L18.9 3zm-1.2 16.3h1.9L7 4.6H5L17.7 19.3z" />
              </svg>
            </a>
            <a href="https://www.linkedin.com/in/mauroprotocassina/" aria-label="LinkedIn">
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M4.98 3.5c0 1.4-1.1 2.5-2.5 2.5S0 4.9 0 3.5 1.1 1 2.5 1s2.48 1.1 2.48 2.5zM0 8h5v16H0V8zm7.5 0h4.8v2.2h.1c.7-1.3 2.4-2.7 4.9-2.7 5.2 0 6.2 3.4 6.2 7.9V24h-5v-7.2c0-1.7 0-4-2.4-4s-2.8 1.9-2.8 3.8V24h-5V8z" />
              </svg>
            </a>
          </div>
        </div>
      </footer>
    </section>
  )
}

export default function Page() {
  return (
    <>
      <Nav />
      <Hero />
      <Dashboard />
      <Features />
      <How />
      <Closing />
    </>
  )
}
