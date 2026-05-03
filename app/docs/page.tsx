import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "Docs — VibeShield",
  description:
    "Learn how VibeShield works: static GitHub scanning, deterministic analyzers, AI triage, Supabase storage, SARIF exports, baseline tracking and safe remediation PRs.",
}

const capabilities = [
  "GitHub repository extraction through server-side tree and blob APIs",
  "Repository inventory for routes, Server Actions, client components, env reads, imports, AI calls, database calls and workflows",
  "Deterministic analyzers for secrets, auth gaps, AI/tool risks, Supabase posture, GitHub Actions posture and dependency intelligence",
  "OSV dependency checks through the API, without installing project dependencies",
  "Bounded source-to-sink traces for selected high-risk patterns",
  "AI triage over redacted evidence for prioritization, explanations and PR safety review",
  "SARIF, GitHub issue bodies, baseline tracking, suppressions and selected-scope remediation PRs",
]

const safetyPrinciples = [
  "No scanned repository code execution",
  "No npm install, package scripts, tests or build steps inside scanned repositories",
  "No ZIP uploads or browser-side repository reads",
  "Secrets are redacted from reports, prompts, SARIF and issue bodies",
  "Private repository snippets are not sent to AI providers unless explicitly enabled",
  "Public PR generation is intentionally conservative and blocks report-only or speculative changes",
]

const routes = [
  ["/scan", "Start a public URL or GitHub-authenticated scan"],
  ["/pulse", "Live security activity across recent reports"],
  ["/scans", "Scan history for the current browser or authenticated identity"],
  ["/report/[scanId]", "Detailed report with grouped findings, evidence and fix guidance"],
  ["/api/scan", "Create or run a scan"],
  ["/api/scan/[scanId]/sarif", "Export SARIF 2.1.0"],
  ["/api/system/health", "Secret-free production health status"],
]

const envGroups = [
  {
    title: "Required for production",
    values: [
      "SUPABASE_URL",
      "SUPABASE_SERVICE_ROLE_KEY",
      "VIBESHIELD_IDENTITY_SALT",
      "VIBESHIELD_REQUIRE_PERSISTENT_STORAGE=true",
      "VIBESHIELD_REQUIRE_PERSISTENT_QUOTA=true",
      "VIBESHIELD_GITHUB_SESSION_SECRET",
      "GITHUB_CLIENT_ID",
      "GITHUB_CLIENT_SECRET",
      "GITHUB_REDIRECT_URI",
    ],
  },
  {
    title: "Optional AI review",
    values: [
      "VIBESHIELD_AI_PROVIDER=anthropic",
      "ANTHROPIC_API_KEY",
      "VIBESHIELD_ANTHROPIC_MODEL",
      "AI_GATEWAY_API_KEY",
      "DEEPSEEK_API_KEY",
    ],
  },
]

export default function DocsPage() {
  return (
    <main className="docs-page">
      <section className="docs-hero">
        <div className="wrap docs-hero-inner">
          <Link href="/" className="docs-back">← Back to VibeShield</Link>
          <span className="eyebrow">Open source documentation</span>
          <h1>
            How VibeShield turns an AI-built repo into a security decision.
          </h1>
          <p>
            VibeShield is a GitHub-native AppSec copilot for teams building with AI. It reads
            repositories safely, builds evidence, separates real vulnerabilities from posture debt,
            and uses AI only after deterministic analysis has produced redacted artifacts.
          </p>
          <div className="docs-actions">
            <Link href="/scan" className="btn btn-accent btn-lg btn-border-spin">Start free scan</Link>
            <a href="https://github.com/MauroProto/v0-hack" className="btn btn-outline btn-lg">View source</a>
          </div>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap docs-grid">
          <article className="docs-card docs-card-large">
            <span className="eyebrow">Why it exists</span>
            <h2>AI makes shipping faster. It does not make security review disappear.</h2>
            <p>
              Builders can now generate full apps with v0, Cursor, Copilot, Claude Code, Bolt,
              Lovable and similar tools. The problem is that generated code often reaches production
              before anyone has reviewed the dangerous parts: public env contracts, missing auth,
              unsafe Server Actions, unbounded AI routes, broad tool permissions, weak Supabase RLS,
              dependency exposure and CI supply-chain drift.
            </p>
            <p>
              VibeShield exists to make that review visible. It is not a guarantee of security and it
              does not pretend every pattern match is a vulnerability. Its job is to gather evidence,
              classify risk conservatively and help a human decide what deserves action.
            </p>
          </article>

          <article className="docs-card">
            <span className="eyebrow">Project origin</span>
            <h3>Built for Zero to Action</h3>
            <p>
              VibeShield was built for the Zero to Action Hackathon by Berset as a practical security
              layer for the new AI-builder workflow.
            </p>
          </article>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap">
          <div className="docs-section-head">
            <span className="eyebrow">What it does</span>
            <h2>Static analysis, evidence, triage and safe remediation.</h2>
          </div>
          <div className="docs-list-grid">
            {capabilities.map((item) => (
              <div className="docs-list-item" key={item}>
                <span />
                <p>{item}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap docs-architecture">
          <div className="docs-section-head">
            <span className="eyebrow">Architecture</span>
            <h2>The scan pipeline is intentionally bounded.</h2>
            <p>
              VibeShield is designed for serverless deployment on Vercel with Supabase persistence.
              It favors controlled static analysis over executing unknown code.
            </p>
          </div>
          <div className="docs-flow">
            {[
              "GitHub API extraction",
              "Repo inventory",
              "Deterministic analyzers",
              "OSV dependency intelligence",
              "Taint and evidence traces",
              "Suppressions and baseline",
              "AI triage",
              "Report, SARIF and PR workflow",
            ].map((step, index) => (
              <div className="docs-flow-step" key={step}>
                <small>{String(index + 1).padStart(2, "0")}</small>
                <span>{step}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap docs-grid">
          <article className="docs-card">
            <span className="eyebrow">Security model</span>
            <h2>Safe by default for public and private repositories.</h2>
            <div className="docs-checks">
              {safetyPrinciples.map((item) => (
                <p key={item}><span>✓</span>{item}</p>
              ))}
            </div>
          </article>

          <article className="docs-card">
            <span className="eyebrow">Scan modes</span>
            <div className="docs-mode">
              <b>Rules</b>
              <p>Fast deterministic pass with no AI review.</p>
            </div>
            <div className="docs-mode">
              <b>Normal</b>
              <p>Recommended default: deterministic analysis plus targeted AI triage.</p>
            </div>
            <div className="docs-mode">
              <b>Max</b>
              <p>Deeper review with broader context, taskflow planning and stricter triage.</p>
            </div>
          </article>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap docs-grid">
          <article className="docs-card docs-card-large">
            <span className="eyebrow">Routes</span>
            <h2>Main product and API surfaces.</h2>
            <div className="docs-routes">
              {routes.map(([route, description]) => (
                <div key={route}>
                  <code>{route}</code>
                  <span>{description}</span>
                </div>
              ))}
            </div>
          </article>

          <article className="docs-card">
            <span className="eyebrow">Production setup</span>
            <h2>Environment variables</h2>
            {envGroups.map((group) => (
              <div className="docs-env" key={group.title}>
                <h3>{group.title}</h3>
                {group.values.map((value) => <code key={value}>{value}</code>)}
              </div>
            ))}
          </article>
        </div>
      </section>

      <section className="docs-section">
        <div className="wrap docs-terminal">
          <div>
            <span className="eyebrow">Local development</span>
            <h2>Run it locally, then verify before deploying.</h2>
            <p>
              Local development can use a git-ignored file store. Production should use Supabase
              for reports, quota, jobs, baselines and scan events.
            </p>
          </div>
          <pre><code>{`pnpm install
pnpm run dev

# before production
pnpm run release:verify`}</code></pre>
        </div>
      </section>

      <section className="docs-section docs-final">
        <div className="wrap">
          <span className="eyebrow">Open source</span>
          <h2>Read the code, run the scanner, improve the analyzer.</h2>
          <p>
            VibeShield is built as a practical open source foundation for evidence-first AppSec
            review of AI-built applications. The roadmap is to keep improving precision, reduce
            false positives, and make remediation safer rather than noisier.
          </p>
          <div className="docs-actions">
            <a href="https://github.com/MauroProto/v0-hack" className="btn btn-accent btn-lg">Open GitHub</a>
            <Link href="/scan" className="btn btn-outline btn-lg">Scan a repo</Link>
          </div>
        </div>
      </section>
    </main>
  )
}
