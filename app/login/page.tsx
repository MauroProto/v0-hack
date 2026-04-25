import Link from "next/link"
import { Icon } from "../(app)/_components/icons"

export default function LoginPage() {
  return (
    <div className="auth-page">
      <div className="auth-grid" />

      <header className="auth-header">
        <Link href="/" className="brand">
          <span className="brand-mark"><Icon.shield /></span>
          <span>VibeShield</span>
          <span className="pill" style={{ marginLeft: 10, height: 22, fontSize: 10.5, padding: "0 8px" }}>Beta</span>
        </Link>
        <Link href="/" className="auth-back">
          ← Back to homepage
        </Link>
      </header>

      <div className="auth-wrap">
        <div className="auth-card">
          <h1 className="auth-title">
            Sign in to <em>VibeShield</em>
          </h1>
          <p className="auth-sub">
            Catch security mistakes in AI-built apps before they reach production.
          </p>

          <Link href="/scan" className="auth-btn auth-btn-github">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.95 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.03a9.5 9.5 0 0 1 5 0c1.91-1.3 2.75-1.03 2.75-1.03.55 1.37.2 2.39.1 2.64.64.7 1.03 1.6 1.03 2.69 0 3.85-2.34 4.7-4.57 4.95.36.31.68.93.68 1.88v2.79c0 .26.18.58.69.48A10 10 0 0 0 12 2Z" />
            </svg>
            <span>Open GitHub login</span>
          </Link>

          <p className="auth-fine">
            We only read repos you explicitly authorize. Your code is never used for training.
          </p>

          <div className="auth-divider"><span>or</span></div>

          <div className="auth-noaccount">
            <div className="auth-noaccount-head">
              <span className="auth-noaccount-pill">
                <Icon.bolt style={{ width: 11, height: 11 }} />
                No account needed
              </span>
              <h3>Don&rsquo;t want to log in?</h3>
            </div>
            <p className="auth-noaccount-desc">
              You can use VibeShield without a GitHub account. Paste a public GitHub repo URL and the server
              reads supported files through GitHub APIs for the current session.
            </p>
            <Link href="/scan" className="auth-btn auth-btn-secondary">
              <span>Continue without account</span>
              <Icon.chevRight style={{ width: 14, height: 14 }} />
            </Link>
            <ul className="auth-noaccount-list">
              <li><span className="x">×</span> Saved scan history</li>
              <li><span className="x">×</span> Auto-scan on every push</li>
              <li><span className="x">×</span> Patch PRs opened on your behalf</li>
            </ul>
            <p className="auth-noaccount-note">
              These features need GitHub. You can come back and sign in any time without losing your scan.
            </p>
          </div>
        </div>

        <div className="auth-foot">
          <span>Free in beta · no credit card · scan in under a minute.</span>
        </div>
      </div>
    </div>
  )
}
