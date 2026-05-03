import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "Docs — VibeShield",
  description:
    "Plain documentation for VibeShield: what it does, how scans work, configuration, limits and safe usage.",
}

const envVars = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "VIBESHIELD_IDENTITY_SALT",
  "VIBESHIELD_REQUIRE_PERSISTENT_STORAGE=true",
  "VIBESHIELD_REQUIRE_PERSISTENT_QUOTA=true",
  "VIBESHIELD_GITHUB_SESSION_SECRET",
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
  "GITHUB_REDIRECT_URI",
  "ANTHROPIC_API_KEY",
]

export default function DocsPage() {
  return (
    <main className="docs-page">
      <div className="docs-shell">
        <aside className="docs-sidebar" aria-label="Documentation navigation">
          <Link href="/" className="docs-logo">VibeShield</Link>
          <nav>
            <a href="#overview">Overview</a>
            <a href="#quick-start">Quick start</a>
            <a href="#how-it-works">How it works</a>
            <a href="#scan-modes">Scan modes</a>
            <a href="#security">Security model</a>
            <a href="#configuration">Configuration</a>
            <a href="#limits">Limits</a>
            <a href="#local-development">Local development</a>
          </nav>
        </aside>

        <article className="docs-content">
          <header id="overview">
            <Link href="/" className="docs-back">Back to home</Link>
            <h1>VibeShield documentation</h1>
            <p>
              VibeShield is an open source security review layer for AI-built web apps. It scans
              GitHub repositories from the server, builds a static security inventory, runs focused
              AppSec rules, and uses AI to triage evidence instead of blindly trusting pattern
              matches.
            </p>
            <p>
              The project is built for builders who ship with tools like v0, Cursor, Copilot and
              Claude Code, then need a practical way to catch risky code before it becomes a public
              pull request or production issue.
            </p>
          </header>

          <section id="quick-start">
            <h2>Quick start</h2>
            <ol>
              <li>Sign in with GitHub.</li>
              <li>Paste a public repository URL or select a repository from your account.</li>
              <li>Choose Normal or Max mode.</li>
              <li>Review the grouped findings and the evidence behind each one.</li>
              <li>Generate fixes only when the selected findings are safe to remediate.</li>
            </ol>
          </section>

          <section id="how-it-works">
            <h2>How it works</h2>
            <p>VibeShield does not execute the scanned repository. The scan pipeline is static:</p>
            <ol>
              <li>Fetch the GitHub tree and supported text blobs server-side.</li>
              <li>Fingerprint the framework, routes, Server Actions, client components and configs.</li>
              <li>Run deterministic rules for secrets, auth, client exposure, AI risks, Supabase and CI posture.</li>
              <li>Run OSV dependency checks from manifests and lockfiles.</li>
              <li>Apply suppressions for tests, fixtures, examples and scanner detector code.</li>
              <li>Use AI review on selected evidence to reduce false positives and explain impact.</li>
              <li>Store the report, baseline state and exportable artifacts.</li>
            </ol>
          </section>

          <section id="scan-modes">
            <h2>Scan modes</h2>
            <table>
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Use it for</th>
                  <th>Credits</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Normal</td>
                  <td>Default review with rules plus targeted AI triage.</td>
                  <td>1</td>
                </tr>
                <tr>
                  <td>Max</td>
                  <td>Deeper review with broader context and stricter AI reasoning.</td>
                  <td>2</td>
                </tr>
                <tr>
                  <td>Generate fixes</td>
                  <td>Creates a remediation text draft for selected findings.</td>
                  <td>1</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section id="security">
            <h2>Security model</h2>
            <ul>
              <li>Repository code is never executed during a scan.</li>
              <li>VibeShield does not run npm install, package scripts, tests or builds for scanned repos.</li>
              <li>Secrets and token-looking values are redacted before reports and AI review.</li>
              <li>Public pull requests should contain real code fixes, not noisy generated reports.</li>
              <li>Reports, scan history and generated artifacts are tied to the logged-in account.</li>
              <li>Private repository data should only be reviewed by AI when that behavior is explicitly enabled.</li>
            </ul>
          </section>

          <section id="configuration">
            <h2>Configuration</h2>
            <p>Production deployments should use Supabase for persistence and GitHub OAuth for login.</p>
            <pre><code>{envVars.join("\n")}</code></pre>
          </section>

          <section id="limits">
            <h2>Limits</h2>
            <ul>
              <li>Only supported text files are scanned.</li>
              <li>Large repositories are capped to keep scans predictable and affordable.</li>
              <li>Static analysis can miss runtime-only behavior.</li>
              <li>AI triage improves prioritization, but final security decisions still require human review.</li>
              <li>VibeShield is not a guarantee of security or a replacement for a full audit.</li>
            </ul>
          </section>

          <section id="local-development">
            <h2>Local development</h2>
            <pre><code>{`pnpm install
pnpm run dev

# verify before deploy
pnpm exec tsc --noEmit --incremental false
pnpm run lint
pnpm run build
pnpm run scanner:smoke`}</code></pre>
          </section>

          <section>
            <h2>Links</h2>
            <ul>
              <li><Link href="/scan">Start a scan</Link></li>
              <li><a href="https://github.com/MauroProto/v0-hack">GitHub repository</a></li>
            </ul>
          </section>
        </article>
      </div>
    </main>
  )
}
