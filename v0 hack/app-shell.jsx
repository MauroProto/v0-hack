// app-shell.jsx — sidebar + topbar shared across artboards

const Icon = {
  shield: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 3 4 6v6c0 4.5 3.4 8.4 8 9 4.6-.6 8-4.5 8-9V6l-8-3Z"/></svg>,
  home: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/></svg>,
  scan: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M3 12h18"/></svg>,
  agent: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/></svg>,
  repo: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M4 4a2 2 0 0 1 2-2h12v18H6a2 2 0 0 1-2-2Z"/><path d="M4 16h14M8 2v14"/></svg>,
  patch: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M14 4 10 20M6 6l-4 6 4 6M18 6l4 6-4 6"/></svg>,
  chart: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 20V4M3 20h18M8 15v-6M13 15V7M18 15v-4"/></svg>,
  team: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="9" cy="8" r="3.2"/><path d="M2.5 20c.5-3.5 3.3-5.5 6.5-5.5S15 16.5 15.5 20"/><circle cx="17" cy="8" r="2.5"/><path d="M17 13c3 0 4.5 1.8 5 5"/></svg>,
  bell: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M6 9a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6ZM10 20a2 2 0 0 0 4 0"/></svg>,
  gear: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.65 1.65 0 0 0-1.8-.3 1.65 1.65 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.65 1.65 0 0 0-1-1.5 1.65 1.65 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.65 1.65 0 0 0 .3-1.8 1.65 1.65 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.65 1.65 0 0 0 1.5-1 1.65 1.65 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.65 1.65 0 0 0 1.8.3 1.65 1.65 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.65 1.65 0 0 0 1 1.5 1.65 1.65 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.65 1.65 0 0 0-.3 1.8 1.65 1.65 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.65 1.65 0 0 0-1.5 1Z"/></svg>,
  search: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>,
  plus: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 5v14M5 12h14"/></svg>,
  arrow: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M5 12h14M13 6l6 6-6 6"/></svg>,
  check: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M4 12l5 5 11-12"/></svg>,
  key: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="8" cy="15" r="4"/><path d="m11 12 10-10M17 6l3 3M14 9l3 3"/></svg>,
  lock: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/></svg>,
  bolt: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/></svg>,
  route: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="5" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M7 5h5a5 5 0 0 1 5 5v0a5 5 0 0 1-5 5H7a5 5 0 0 0-5 5"/></svg>,
  terminal: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="m5 8 4 4-4 4M12 16h6"/><rect x="2" y="4" width="20" height="16" rx="2"/></svg>,
  file: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg>,
  chevron: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="m9 18 6-6-6-6"/></svg>,
  chevDown: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="m6 9 6 6 6-6"/></svg>,
  dots: (p) => <svg {...p} viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/></svg>,
  link: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>,
  copy: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V4a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>,
  download: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 3v13M6 11l6 6 6-6M5 21h14"/></svg>,
  export: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 16V4M6 9l6-6 6 6M5 20h14"/></svg>,
  share: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="m8 11 8-4M8 13l8 4"/></svg>,
  branch: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 6v12M6 14a6 6 0 0 0 6-6h4"/></svg>,
  commit: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="3.5"/><path d="M3 12h5.5M15.5 12H21"/></svg>,
  external: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M14 4h6v6M20 4 10 14M9 5H5a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1v-4"/></svg>,
  play: (p) => <svg {...p} viewBox="0 0 24 24" fill="currentColor"><path d="M6 4v16l14-8Z"/></svg>,
  filter: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 5h18l-7 8v6l-4 2v-8Z"/></svg>,
};

function Sidebar({ active = 'scan' }) {
  return (
    <aside className="sb">
      <div className="sb-top">
        <div className="sb-brand">
          <div className="sb-brand-mark">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 3 4 6v6c0 4.5 3.4 8.4 8 9 4.6-.6 8-4.5 8-9V6l-8-3Z"/>
            </svg>
          </div>
          VibeShield
        </div>
        <Icon.chevDown style={{ width: 14, height: 14, color: 'var(--fg-5)' }} />
      </div>

      <div className="sb-org">
        <div className="av">A</div>
        <div className="name">acme</div>
        <div className="plan">Pro</div>
        <Icon.chevDown style={{ width: 12, height: 12, color: 'var(--fg-5)' }} />
      </div>

      <div className="sb-search">
        <Icon.search style={{ width: 13, height: 13 }} />
        <span>Jump to…</span>
        <span className="kbd">⌘K</span>
      </div>

      <div className="sb-nav">
        <div className="sb-link" data-active={active === 'home'}>
          <Icon.home /> Home
        </div>
        <div className="sb-link" data-active={active === 'scans'}>
          <Icon.scan /> Scans <span className="count">142</span>
        </div>
        <div className="sb-link" data-active={active === 'scan'}>
          <Icon.scan /> Current scan <span className="dot"/>
        </div>
        <div className="sb-link" data-active={active === 'agent'}>
          <Icon.agent /> Agent runs
        </div>
        <div className="sb-link" data-active={active === 'patches'}>
          <Icon.patch /> Patches <span className="count">9</span>
        </div>
        <div className="sb-link" data-active={active === 'repos'}>
          <Icon.repo /> Repositories <span className="count">14</span>
        </div>
      </div>

      <div>
        <div className="sb-nav-label">Repositories</div>
        <div className="sb-repos">
          <div className="sb-repo" data-active={active === 'scan'}>
            <span className="rdot rdot-crit"/>
            <span className="rpath">storefront-ai</span>
          </div>
          <div className="sb-repo">
            <span className="rdot rdot-warn"/>
            <span className="rpath">dashboard-web</span>
          </div>
          <div className="sb-repo">
            <span className="rdot rdot-ok"/>
            <span className="rpath">api-gateway</span>
          </div>
          <div className="sb-repo">
            <span className="rdot rdot-ok"/>
            <span className="rpath">marketing-site</span>
          </div>
          <div className="sb-repo">
            <span className="rdot rdot-warn"/>
            <span className="rpath">embeddings-worker</span>
          </div>
          <div className="sb-repo">
            <span className="rdot rdot-ok"/>
            <span className="rpath">internal-tools</span>
          </div>
        </div>
      </div>

      <div className="sb-nav">
        <div className="sb-link" data-active={active === 'billing'}>
          <Icon.chart /> Billing & usage
        </div>
        <div className="sb-link"><Icon.team /> Team</div>
        <div className="sb-link"><Icon.gear /> Settings</div>
      </div>

      <div className="sb-bottom">
        <div className="sb-usage">
          <div className="sb-usage-row"><span>Scans this cycle</span><b>412 / 1,000</b></div>
          <div className="sb-usage-bar"><i style={{ width: '41%' }}/></div>
        </div>
        <div className="sb-user">
          <div className="av">FC</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="name">Fede C.</div>
            <div className="mail">fede@acme.co</div>
          </div>
          <Icon.dots style={{ width: 14, height: 14, color: 'var(--fg-5)' }}/>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ crumbs, actions, showApply = false, scanStatus = null }) {
  return (
    <div className="topbar">
      <div className="crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span className="sep">/</span>}
            <span className={`c ${c.mono ? 'mono' : ''}`} style={c.mono ? { fontFamily: 'var(--font-mono)' } : undefined}>
              {c.text}
            </span>
          </React.Fragment>
        ))}
        {scanStatus && (
          <span style={{
            marginLeft: 12,
            display: 'inline-flex', alignItems: 'center', gap: 6,
            fontSize: 11, color: 'var(--fg-4)',
            padding: '2px 8px',
            border: '1px solid var(--line)',
            borderRadius: 999,
            fontFamily: 'var(--font-mono)',
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)' }}/>
            {scanStatus}
          </span>
        )}
      </div>
      <div className="spacer"/>
      <div className="tb-actions">
        {actions}
      </div>
    </div>
  );
}

// Progress ring component
function Ring({ value = 62, size = 64, stroke = 5 }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, value));
  const dash = c * (pct / 100);
  return (
    <div className="ring-wrap" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle className="ring-bg" cx={size/2} cy={size/2} r={r} strokeWidth={stroke}/>
        <circle className="ring-fg" cx={size/2} cy={size/2} r={r} strokeWidth={stroke}
          strokeDasharray={`${dash} ${c}`}/>
      </svg>
      <div className="ring-txt">{value}</div>
    </div>
  );
}

Object.assign(window, { Icon, Sidebar, Topbar, Ring });
