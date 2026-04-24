"use client"

import { useState, useEffect, type ReactNode } from "react"
import Image from "next/image"

// ---------- Icons ----------
const I = {
  shield: (p: React.SVGProps<SVGSVGElement>) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}>
      <path d="M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6l-8-3z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>
  ),
  arrow: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg>),
  github: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="currentColor" {...p}><path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.95 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.03a9.5 9.5 0 0 1 5 0c1.91-1.3 2.75-1.03 2.75-1.03.55 1.37.2 2.39.1 2.64.64.7 1.03 1.6 1.03 2.69 0 3.85-2.34 4.7-4.57 4.95.36.31.68.93.68 1.88v2.79c0 .26.18.58.69.48A10 10 0 0 0 12 2Z"/></svg>),
  gitbranch: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10"/><path d="M6 14a6 6 0 0 0 6-6h4"/></svg>),
  zip: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M10 10h2v2h-2z"/><path d="M12 12h-2v2h2z"/><path d="M10 14h2v2h-2z"/></svg>),
  sparkle: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8"/></svg>),
  bolt: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg>),
  key: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="8" cy="15" r="4"/><path d="m10.85 12.15 7.4-7.4"/><path d="m18 5 3 3"/><path d="m15 8 2 2"/></svg>),
  lock: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>),
  upload: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/></svg>),
  scan: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M8 12h8"/></svg>),
  info: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="9"/><path d="M12 8v.01"/><path d="M11 12h1v4h1"/></svg>),
  link: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 1 0-7-7l-1 1"/><path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 1 0 7 7l1-1"/></svg>),
  agent: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><rect x="3" y="7" width="18" height="13" rx="3"/><circle cx="9" cy="13" r="1.2"/><circle cx="15" cy="13" r="1.2"/><path d="M12 3v4"/><path d="M8 20v1"/><path d="M16 20v1"/></svg>),
  doc: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6"/><path d="M9 17h4"/></svg>),
  share: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.6 13.5 6.8 4"/><path d="m15.4 6.5-6.8 4"/></svg>),
  wand: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="m14 4 6 6-12 12-6-6z"/><path d="m13 5 6 6"/><path d="M18 3v2M22 4h-2M19 7h2"/></svg>),
  chevron: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="m9 6 6 6-6 6"/></svg>),
  search: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>),
  api: (p: React.SVGProps<SVGSVGElement>) => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M16 3h3a2 2 0 0 1 2 2v3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/><path d="M9 9h1v6H9z"/><path d="M13 9h1v6h-1z"/></svg>),
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
        <a href="#" className="brand">
          <span className="brand-mark"><I.shield /></span>
          <span>VibeShield</span>
          <span className="pill" style={{ marginLeft: 10, height: 22, fontSize: 10.5, padding: "0 8px" }}>Beta</span>
        </a>
        <nav className="nav-links">
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a href="#report">Report</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
        </nav>
        <div className="nav-right">
          <a href="#" className="btn btn-ghost">Sign in</a>
          <a href="#" className="btn btn-primary">
            Start free scan <I.arrow className="arrow" style={{ width: 14, height: 14 }} />
          </a>
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
          <span className="line">Scan your <em>vibe-coded</em></span>
          <span className="line">app before <span className="muted">you ship.</span></span>
        </h1>
        <p className="lead">
          VibeShield reviews code generated by v0, Cursor, Bolt, Lovable and Claude Code &mdash;
          catching exposed keys, unauthenticated routes, unsafe tool calls and other
          vibe-coding mistakes before they reach production.
        </p>
        <div className="hero-cta">
          <a href="#scan" className="btn btn-accent btn-lg">Start free scan <I.arrow className="arrow" style={{ width: 14, height: 14 }} /></a>
          <a href="#report" className="btn btn-outline btn-lg">View sample report</a>
        </div>
        <div className="hero-meta">
          <span><b>No install.</b> Connect a repo or drop a ZIP.</span>
          <span className="sep" />
          <span><b>Private by default.</b> Code isn&apos;t retained after scan.</span>
          <span className="sep" />
          <span><b>6 scan engines.</b> Secrets, routes, AI risks &amp; more.</span>
        </div>

        {/* logos marquee */}
        <div className="logos">
          <div className="marquee-track">
            {[...Array(2)].map((_, dup) => (
              <div key={dup} style={{ display: "contents" }}>
                <span className="logo"><span className="logo-mono"><Image src="/logos/v0.png" alt="v0" width={44} height={44} /></span><span className="name">v0</span></span>
                <span className="logo"><span className="logo-mono"><Image src="/logos/tempo.png" alt="Cursor" width={44} height={44} /></span><span className="name">Cursor</span></span>
                <span className="logo"><Image src="/logos/claude.png" alt="Claude Code" width={44} height={44} /><span className="name">Claude Code</span></span>
                <span className="logo"><Image src="/logos/lovable.png" alt="Lovable" width={44} height={44} /><span className="name">Lovable</span></span>
                <span className="logo"><span className="logo-mono"><Image src="/logos/bolt.png" alt="Bolt" width={44} height={44} /></span><span className="name">Bolt</span></span>
                <span className="logo"><span className="logo-mono"><Image src="/logos/windsurf.png" alt="Windsurf" width={44} height={44} /></span><span className="name">Windsurf</span></span>
                <span className="logo"><Image src="/logos/replit.png" alt="Replit" width={44} height={44} /><span className="name">Replit</span></span>
                <span className="logo"><span className="logo-mono"><Image src="/logos/cursor.png" alt="Copilot" width={44} height={44} /></span><span className="name">Copilot</span></span>
                <span className="logo"><Image src="/logos/warp.png" alt="Codex" width={44} height={44} /><span className="name">Codex</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

// ---------- Scan input preview ----------
function ScanPreview() {
  const [tab, setTab] = useState("repo")
  return (
    <section className="section" id="scan" style={{ paddingTop: 20, paddingBottom: 48 }}>
      <div className="wrap">
        <div className="surface scan-card">
          <div className="scan-tabs">
            <div className="scan-tab" data-active={tab === "repo"} onClick={() => setTab("repo")}>
              <I.github /> GitHub repository
            </div>
            <div className="scan-tab" data-active={tab === "zip"} onClick={() => setTab("zip")}>
              <I.zip /> Upload ZIP
            </div>
            <div className="scan-tab" data-active={tab === "paste"} onClick={() => setTab("paste")}>
              <I.doc /> Paste snippet
            </div>
            <div style={{ flex: 1 }} />
            <div className="scan-tab" style={{ color: "var(--fg-5)", cursor: "default" }}>
              <I.lock /> End-to-end encrypted
            </div>
          </div>
          <div className="scan-body">
            {tab === "repo" && (
              <>
                <div className="scan-input">
                  <span className="prefix">github.com/</span>
                  <input defaultValue="acme/storefront-ai" />
                  <span className="hint mono">main</span>
                  <button className="btn btn-accent">Scan repository <I.arrow className="arrow" style={{ width: 14, height: 14 }} /></button>
                </div>
                <div className="scan-meta">
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><I.gitbranch /> 3 branches detected</span>
                  <span>&middot;</span>
                  <span><b>184 files</b> &middot; TypeScript, Next.js, Prisma</span>
                  <span>&middot;</span>
                  <span>est. scan time <b>~42s</b></span>
                </div>
              </>
            )}
            {tab === "zip" && (
              <div className="scan-drop">
                <div className="icn"><I.upload /></div>
                <div className="txt">
                  <b>Drop a .zip of your project</b>
                  <span>Up to 200 MB &middot; node_modules auto-excluded &middot; .env files flagged, never logged</span>
                </div>
                <button className="btn btn-outline">Choose file</button>
              </div>
            )}
            {tab === "paste" && (
              <div className="scan-drop" style={{ alignItems: "flex-start" }}>
                <div className="icn"><I.doc /></div>
                <div className="txt">
                  <b>Paste a single file or snippet</b>
                  <span>Useful for checking an AI-generated route handler or tool definition</span>
                </div>
                <button className="btn btn-outline">Open paste editor</button>
              </div>
            )}

            <div className="disclaim">
              <I.info style={{ width: 16, height: 16, color: "var(--fg-3)" }} />
              <div>
                VibeShield is a <b style={{ color: "var(--fg-2)", fontWeight: 500 }}>preflight security check</b>, not a guarantee.
                We surface the most common vibe-coding risks &mdash; pair it with human review, auth, and standard
                production safeguards before going live.
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ---------- Dashboard preview ----------
const FINDINGS = [
  { sev: "critical", msg: "Exposed OpenAI API key committed in code", path: "lib/openai.ts", line: 3, age: "just now", ico: <I.key /> },
  { sev: "critical", msg: "Unauthenticated route exposes user records", path: "app/api/users/route.ts", line: 17, age: "just now", ico: <I.lock /> },
  { sev: "high", msg: "AI chat endpoint has no rate limit or auth guard", path: "app/api/chat/route.ts", line: 24, age: "5s ago", ico: <I.bolt /> },
  { sev: "high", msg: "MCP tool executes shell without allow-list", path: "tools/shell.ts", line: 42, age: "9s ago", ico: <I.sparkle /> },
  { sev: "medium", msg: "Supabase service role key read from NEXT_PUBLIC_*", path: "lib/db.ts", line: 8, age: "12s ago", ico: <I.key /> },
  { sev: "medium", msg: "Missing CSRF protection on mutation route", path: "app/api/checkout/route.ts", line: 31, age: "14s ago", ico: <I.lock /> },
  { sev: "low", msg: "User input passed directly to model context", path: "app/api/chat/route.ts", line: 51, age: "18s ago", ico: <I.api /> },
]

function Dashboard() {
  return (
    <section className="section" id="report">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">The report</span>
          <h2>A clear readout of <em>what&apos;s risky</em>, and how to fix it.</h2>
          <p>
            Findings ranked by severity with file &amp; line references, a plain-English
            explanation, and a ready-to-apply patch. Share a link with your team, export to
            Markdown, or let VibeShield open a pull request.
          </p>
        </div>

        <div className="surface dash">
          <div className="dash-chrome">
            <div className="dash-dots"><span /><span /><span /></div>
            <div className="dash-url">
              <I.lock style={{ width: 12, height: 12 }} />
              <span>app.vibeshield.dev/scans/</span>
              <span className="path">acme/storefront-ai/r_8f2a</span>
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
                  <div className="crumb">acme <I.chevron style={{ width: 12, height: 12 }} /> storefront-ai <I.chevron style={{ width: 12, height: 12 }} /> scan r_8f2a</div>
                  <h3>Security report <span className="repo">&middot; main @ 1f3c2a8</span></h3>
                </div>
                <div className="actions">
                  <button className="btn btn-outline"><I.share /> Share</button>
                  <button className="btn btn-outline"><I.doc /> Export</button>
                  <button className="btn btn-accent"><I.wand /> Apply fixes</button>
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
                  <div className="sub">Block deploy &middot; exposed secret, open route</div>
                </div>
                <div className="score-card sev-med">
                  <div className="lbl">High &middot; Medium</div>
                  <div className="val">2 <small style={{ color: "var(--fg-4)" }}>/</small> 4</div>
                  <div className="sub">Auth gaps &amp; unsafe env usage</div>
                </div>
                <div className="score-card sev-low">
                  <div className="lbl">Low &middot; Info</div>
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
                    <button className="action"><I.wand style={{ width: 12, height: 12 }} /> Patch</button>
                  </div>
                ))}
              </div>
            </div>

            {/* SIDE: Agent timeline */}
            <aside className="dash-side">
              <div className="agent-head">
                <h4>Scan agent</h4>
                <span className="live"><span className="dot" /> live &middot; 00:42</span>
              </div>

              <div className="timeline">
                <TimelineItem state="done" title="Cloned acme/storefront-ai" sub="184 files · 11,842 LOC · TypeScript, Next.js" time="00:00 → 00:03" />
                <TimelineItem state="done" title="Fingerprinted AI-generated code" sub="Detected v0 (72%), Cursor (18%), hand-edited (10%)" time="00:03 → 00:08" />
                <TimelineItem state="done" title="Secret & key sweep" sub="Matched 14 providers · 1 exposed OpenAI key, 1 Supabase service role misplacement" time="00:08 → 00:19" />
                <TimelineItem state="done" title="Route & auth graph" sub="Walked 31 routes · 6 lack an auth guard · 2 allow public writes" time="00:19 → 00:31" />
                <TimelineItem state="active" title="AI endpoint & tool review" sub="Analyzing chat routes, MCP tools and rate limits" time="00:31 → now"
                  code={<><span className="c"># checking</span>{"\n"}<span className="k">→</span> app/api/chat/route.ts{"\n"}<span className="k">→</span> tools/shell.ts{"\n"}<span className="c"># 3 suggestions queued</span></>}
                />
                <TimelineItem state="pending" title="Generate patch PR" sub="Drafts fixes as a branch you can review" time="queued" />
              </div>
            </aside>
          </div>
        </div>
      </div>
    </section>
  )
}

function TimelineItem({ state, title, sub, time, code }: { state: string; title: string; sub: string; time: string; code?: ReactNode }) {
  return (
    <div className="tl-item" data-state={state}>
      <div className="tl-title">{title}</div>
      {sub && <div className="tl-sub">{sub}</div>}
      {time && <div className="tl-time">{time}</div>}
      {code && <div className="tl-code">{code}</div>}
    </div>
  )
}

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

// ---------- Features ----------
function Features() {
  return (
    <section className="section" id="features">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">What it catches</span>
          <h2>Built for the <em>vibe-coding</em> era.</h2>
          <p>
            VibeShield knows the patterns AI code assistants reach for &mdash; and the
            footguns they leave behind. It looks beyond generic linting at the parts of your
            stack most likely to go live insecure.
          </p>
        </div>

        <div className="features">
          <article className="feature f-two-third">
            <div className="f-icon"><I.scan /></div>
            <h3>Repo &amp; snapshot scanning</h3>
            <p>
              Connect a GitHub repo for continuous scans on every push, or drop a ZIP for a
              one-shot review. VibeShield respects monorepos, ignores generated output,
              and scans diffs when you ask for speed.
            </p>
            <div className="f-art">
              <div className="mini-list">
                <div className="row"><span className="dot" style={{ background: "var(--accent)" }} /> github.com/acme/storefront-ai <span style={{ color: "var(--fg-5)", marginLeft: "auto" }}>main &middot; auto</span></div>
                <div className="row"><span className="dot" style={{ background: "var(--accent)" }} /> github.com/acme/lovable-crm <span style={{ color: "var(--fg-5)", marginLeft: "auto" }}>develop &middot; auto</span></div>
                <div className="row"><span className="dot" style={{ background: "var(--warn)" }} /> uploads/landing-v2.zip <span style={{ color: "var(--fg-5)", marginLeft: "auto" }}>snapshot &middot; 2m ago</span></div>
              </div>
            </div>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.sparkle /></div>
            <h3>AI risk detection</h3>
            <p>
              Checks AI endpoints for rate limiting, prompt-injection exposure,
              unchecked tool/MCP calls, and model access that escapes your auth guards.
            </p>
            <div className="f-art">
              <div className="mini-list">
                <div className="row"><span className="dot" style={{ background: "var(--danger)" }} /> <code style={{ color: "var(--fg-2)" }}>POST /api/chat</code> <span style={{ color: "var(--fg-5)", marginLeft: "auto" }}>no rate limit</span></div>
                <div className="row"><span className="dot" style={{ background: "var(--warn)" }} /> <code style={{ color: "var(--fg-2)" }}>tool:shell</code> <span style={{ color: "var(--fg-5)", marginLeft: "auto" }}>no allow-list</span></div>
              </div>
            </div>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.wand /></div>
            <h3>Patch suggestions</h3>
            <p>
              Every finding comes with a readable explanation and a ready-to-apply diff.
              Apply in-app or open a PR straight to your branch.
            </p>
            <div className="f-art">
              <div className="diff">
                <span className="c">app/api/chat/route.ts</span>{"\n"}
                <span className="del">- export async function POST(req) {"{"}</span>
                <span className="add">+ import {"{"} rateLimit {"}"} from &quot;@/lib/limit&quot;;</span>
                <span className="add">+ export const POST = rateLimit(async (req) =&gt; {"{"}</span>
              </div>
            </div>
          </article>

          <article className="feature f-two-third">
            <div className="f-icon"><I.share /></div>
            <h3>Shareable reports</h3>
            <p>
              Send a single link to a teammate, a client, or a compliance reviewer.
              Every report is a stable URL with findings, fixes and a full audit trail &mdash;
              private by default, optionally read-only public.
            </p>
            <div className="f-art" style={{ display: "grid", gap: 8 }}>
              <div className="share-card">
                <div className="avatar" />
                <div className="txt">
                  <span>Maya shared <b style={{ color: "var(--fg)" }}>storefront-ai &middot; r_8f2a</b> with 3 reviewers</span>
                  <small>app.vibeshield.dev/r/8f2ac0 &middot; read-only</small>
                </div>
                <button className="btn btn-outline" style={{ height: 28, fontSize: 12 }}><I.link style={{ width: 12, height: 12 }} /> Copy link</button>
              </div>
              <div className="share-card">
                <div className="avatar" style={{ background: "linear-gradient(135deg,#60a5fa,#7FE7C4)" }} />
                <div className="txt">
                  <span>Opened PR <b style={{ color: "var(--fg)" }}>#217 &middot; VibeShield: auto-patch critical findings</b></span>
                  <small>4 files &middot; +31 −12 &middot; awaiting review</small>
                </div>
                <button className="btn btn-outline" style={{ height: 28, fontSize: 12 }}><I.github style={{ width: 12, height: 12 }} /> View</button>
              </div>
            </div>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.key /></div>
            <h3>Secret &amp; env-var audit</h3>
            <p>
              Catches 40+ key formats and flags secrets misfiled as <code style={{ fontSize: 12 }}>NEXT_PUBLIC_*</code> or committed to the repo. Rotation guides included.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.lock /></div>
            <h3>Route &amp; auth graph</h3>
            <p>
              Walks your route tree to find handlers missing auth, CSRF protection, or
              input validation &mdash; and which ones write to the database.
            </p>
          </article>

          <article className="feature f-third">
            <div className="f-icon"><I.agent /></div>
            <h3>Tool &amp; MCP review</h3>
            <p>
              Inspects agent tool definitions for shell access, unchecked fetches, and
              over-broad permissions. Suggests safe allow-lists.
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
    { n: "01", title: "Connect a repo", body: "Authorize GitHub or drop a ZIP. Monorepos and private repos supported. Your code is processed ephemerally and never used for training.", ico: <I.github /> },
    { n: "02", title: "Run the scan", body: "Six engines run in parallel: secrets, routes, auth, AI endpoints, tool/MCP and dependency risks. Finishes in under a minute on most projects.", ico: <I.scan /> },
    { n: "03", title: "Review findings", body: "A clear, ranked report with plain-English explanations, file:line references, severity and reasoning. No thousand-line logs.", ico: <I.search /> },
    { n: "04", title: "Generate fixes", body: "Apply patches in-app, open a pull request, or hand them to your AI agent. Re-scan anytime — or on every push.", ico: <I.wand /> },
  ]
  return (
    <section className="section" id="how">
      <div className="wrap">
        <div className="section-head">
          <span className="eyebrow">How it works</span>
          <h2>Four steps from <em>prompt</em> to <em>production-ready</em>.</h2>
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

// ---------- Closing ----------
function Closing() {
  return (
    <section className="closing">
      <div className="closing-cta">
        <span className="eyebrow">Free in beta</span>
        <h2>
          Ship AI-built apps<br />
          with <em>fewer surprises.</em>
        </h2>
        <p>Scan your first repo in under a minute. No install.</p>
        <div className="cta-actions">
          <a href="#" className="btn btn-accent btn-lg">Start free scan <I.arrow className="arrow" style={{ width: 14, height: 14 }} /></a>
          <a href="#" className="btn btn-outline btn-lg"><I.github /> Install GitHub App</a>
        </div>
      </div>

      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <a href="#" className="brand">
              <span className="brand-mark"><I.shield /></span>
              <span>VibeShield</span>
            </a>
            <p>A preflight security check for apps you built with AI.</p>
            <span className="status"><span className="dot" /> All systems operational</span>
          </div>
          <div className="cols">
            <div className="col">
              <h5>Product</h5>
              <a href="#features">Features</a>
              <a href="#how">How it works</a>
              <a href="#report">Sample report</a>
              <a href="#">Pricing</a>
            </div>
            <div className="col">
              <h5>Integrations</h5>
              <a href="#">GitHub</a>
              <a href="#">GitLab</a>
              <a href="#">Slack</a>
              <a href="#">Webhooks</a>
            </div>
            <div className="col">
              <h5>Resources</h5>
              <a href="#">Docs</a>
              <a href="#">Threat library</a>
              <a href="#">Changelog</a>
              <a href="#">Status</a>
            </div>
            <div className="col">
              <h5>Company</h5>
              <a href="#">About</a>
              <a href="#">Security</a>
              <a href="#">Privacy</a>
              <a href="#">Contact</a>
            </div>
          </div>
        </div>

        <div className="wordmark" aria-hidden="true">
          Vibe<em>Shield</em>
        </div>

        <div className="footer-bottom">
          <span>&copy; 2026 VibeShield Labs &middot; Not a guarantee of security.</span>
          <div className="socials">
            <a href="#" aria-label="GitHub"><I.github /></a>
            <a href="#" aria-label="X"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.9 3H22l-7.5 8.6L23 21h-6.8l-5.3-6.9L4.7 21H1.5l8-9.2L1 3h6.9l4.8 6.3L18.9 3zm-1.2 16.3h1.9L7 4.6H5L17.7 19.3z"/></svg></a>
            <a href="#" aria-label="LinkedIn"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4.98 3.5c0 1.4-1.1 2.5-2.5 2.5S0 4.9 0 3.5 1.1 1 2.5 1s2.48 1.1 2.48 2.5zM0 8h5v16H0V8zm7.5 0h4.8v2.2h.1c.7-1.3 2.4-2.7 4.9-2.7 5.2 0 6.2 3.4 6.2 7.9V24h-5v-7.2c0-1.7 0-4-2.4-4s-2.8 1.9-2.8 3.8V24h-5V8z"/></svg></a>
          </div>
        </div>
      </footer>
    </section>
  )
}

// ---------- App ----------
export default function Page() {
  return (
    <>
      <Nav />
      <Hero />
      <ScanPreview />
      <Dashboard />
      <Features />
      <How />
      <Closing />
    </>
  )
}
