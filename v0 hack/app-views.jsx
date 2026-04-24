// app-views.jsx — individual views for each artboard
// Uses Icon, Sidebar, Topbar, Ring from app-shell.jsx

// ==================================================================
// Sample data (shared)
// ==================================================================
const FINDINGS = [
  { id: 1, sev: 'critical', icon: 'key',   msg: 'Exposed OpenAI API key committed in code',             path: 'lib/openai.ts', line: 3,   meta: 'just now', cat: 'secret' },
  { id: 2, sev: 'critical', icon: 'lock',  msg: 'Unauthenticated route exposes user records',           path: 'app/api/users/route.ts', line: 17, meta: 'just now', cat: 'route' },
  { id: 3, sev: 'high',     icon: 'bolt',  msg: 'AI chat endpoint has no rate limit or auth guard',    path: 'app/api/chat/route.ts', line: 24, meta: '5s ago', cat: 'ai' },
  { id: 4, sev: 'high',     icon: 'terminal', msg: 'MCP tool executes shell without allow-list',       path: 'tools/shell.ts', line: 42, meta: '9s ago', cat: 'ai' },
  { id: 5, sev: 'medium',   icon: 'key',   msg: 'Supabase service role key read from NEXT_PUBLIC_*',   path: 'lib/db.ts', line: 8, meta: '12s ago', cat: 'secret' },
  { id: 6, sev: 'medium',   icon: 'lock',  msg: 'Missing CSRF protection on mutation route',           path: 'app/api/checkout/route.ts', line: 31, meta: '14s ago', cat: 'route' },
  { id: 7, sev: 'low',      icon: 'bolt',  msg: 'User input passed directly to model context',         path: 'app/api/chat/route.ts', line: 51, meta: '18s ago', cat: 'ai' },
  { id: 8, sev: 'low',      icon: 'route', msg: 'Allow-any CORS header on public endpoint',            path: 'middleware.ts', line: 12, meta: '22s ago', cat: 'route' },
  { id: 9, sev: 'low',      icon: 'file',  msg: '.env.local referenced in repo history',               path: '.gitignore', line: 2, meta: '25s ago', cat: 'secret' },
  { id: 10, sev: 'low',     icon: 'lock',  msg: 'Session cookie missing SameSite attribute',           path: 'lib/auth.ts', line: 19, meta: '28s ago', cat: 'route' },
  { id: 11, sev: 'low',     icon: 'bolt',  msg: 'Streaming response not cancelled on client abort',    path: 'app/api/chat/route.ts', line: 64, meta: '31s ago', cat: 'ai' },
  { id: 12, sev: 'low',     icon: 'route', msg: 'Redirect target not validated against allow-list',    path: 'app/auth/callback/route.ts', line: 22, meta: '34s ago', cat: 'route' },
  { id: 13, sev: 'low',     icon: 'file',  msg: 'Console.log leaks PII in production build',           path: 'lib/logger.ts', line: 7, meta: '38s ago', cat: 'hygiene' },
  { id: 14, sev: 'low',     icon: 'file',  msg: 'Dependency react-markdown pinned to vulnerable 8.0.x', path: 'package.json', line: 24, meta: '40s ago', cat: 'hygiene' },
  { id: 15, sev: 'low',     icon: 'route', msg: 'Missing Content-Security-Policy header',              path: 'next.config.js', line: 11, meta: '42s ago', cat: 'hygiene' },
];

const iconOf = (k) => {
  const m = { key: Icon.key, lock: Icon.lock, bolt: Icon.bolt, route: Icon.route, terminal: Icon.terminal, file: Icon.file };
  return m[k] || Icon.file;
};

function FindingRow({ f, selected, compact = false, onClick }) {
  const I = iconOf(f.icon);
  return (
    <div className="f-row" data-selected={selected} onClick={onClick}>
      <div className="f-ico"><I/></div>
      <span className={`sev sev-${f.sev}`}><span className="d"/>{f.sev}</span>
      <div className="f-main">
        <div className="f-msg">{f.msg}</div>
        <div className="f-path"><b>{f.path}</b>:{f.line}</div>
      </div>
      {!compact && <span className="f-meta">{f.meta}</span>}
      {!compact && <button className="f-action"><Icon.patch style={{ width: 11, height: 11 }}/>Patch</button>}
    </div>
  );
}

// ==================================================================
// VIEW 1 — Scan report (the hero view, expanded from the screenshot)
// ==================================================================
function ViewReport() {
  const [tab, setTab] = React.useState('all');
  const counts = {
    all: FINDINGS.length,
    critical: FINDINGS.filter(f => f.sev === 'critical').length,
    ai: FINDINGS.filter(f => f.cat === 'ai').length,
    secret: FINDINGS.filter(f => f.cat === 'secret').length,
    route: FINDINGS.filter(f => f.cat === 'route').length,
  };
  const shown = tab === 'all' ? FINDINGS
    : tab === 'critical' ? FINDINGS.filter(f => f.sev === 'critical')
    : FINDINGS.filter(f => f.cat === tab);

  return (
    <div className="app">
      <Sidebar active="scan"/>
      <div className="main">
        <Topbar
          crumbs={[
            { text: 'acme' },
            { text: 'storefront-ai' },
            { text: 'scan r_8f2a', mono: true },
          ]}
          actions={<>
            <button className="tb-btn"><Icon.share style={{ width: 12, height: 12 }}/>Share</button>
            <button className="tb-btn"><Icon.export style={{ width: 12, height: 12 }}/>Export</button>
            <button className="tb-btn primary"><Icon.patch style={{ width: 12, height: 12 }}/>Apply fixes</button>
          </>}
        />
        <div className="content">
          <div className="report">
            <div className="report-main">
              <div className="report-head">
                <div className="report-title">
                  <h1>Security report<em>main @ 1f3c2a8</em></h1>
                  <div className="sub">
                    <span className="branch">main</span>
                    <span className="dot"/>
                    <span>scanned 00:42 ago</span>
                    <span className="dot"/>
                    <span className="sha">1f3c2a8</span>
                    <span className="dot"/>
                    <span>by agent v3.2</span>
                  </div>
                </div>
              </div>

              <div className="score-grid">
                <div className="sc sc-main">
                  <div className="sc-lbl">Overall posture</div>
                  <div className="sc-val">62 <small>/ 100</small></div>
                  <div className="sc-sub">Needs attention<br/>before deploy</div>
                  <div className="ring"><Ring value={62}/></div>
                </div>
                <div className="sc sc-crit">
                  <div className="sc-lbl">Critical</div>
                  <div className="sc-val">2</div>
                  <div className="sc-sub">Block deploy · exposed secret, open route</div>
                </div>
                <div className="sc sc-high">
                  <div className="sc-lbl">High · Medium</div>
                  <div className="sev-split"><b>2</b>/<span>4</span></div>
                  <div className="sc-sub">Auth gaps & unsafe env usage</div>
                </div>
                <div className="sc sc-low">
                  <div className="sc-lbl">Low · Info</div>
                  <div className="sc-val">9</div>
                  <div className="sc-sub">Hygiene & best-practice notes</div>
                </div>
              </div>

              <div className="findings-block">
                <div className="findings-top">
                  <h2>Findings</h2>
                  <div className="findings-tabs">
                    <button className="f-tab" data-active={tab === 'all'} onClick={() => setTab('all')}>All <span className="n">{counts.all}</span></button>
                    <button className="f-tab" data-sev="crit" data-active={tab === 'critical'} onClick={() => setTab('critical')}>Critical <span className="n">{counts.critical}</span></button>
                    <button className="f-tab" data-active={tab === 'ai'} onClick={() => setTab('ai')}>AI risks <span className="n">{counts.ai}</span></button>
                    <button className="f-tab" data-active={tab === 'secret'} onClick={() => setTab('secret')}>Secrets <span className="n">{counts.secret}</span></button>
                    <button className="f-tab" data-active={tab === 'route'} onClick={() => setTab('route')}>Routes <span className="n">{counts.route}</span></button>
                  </div>
                </div>
                <div className="findings-list">
                  {shown.map(f => <FindingRow key={f.id} f={f}/>)}
                </div>
              </div>
            </div>

            <aside className="report-side">
              <div className="report-side-head">
                <h3>Scan agent</h3>
                <span className="live"><span className="dot"/>live 00:42</span>
              </div>
              <div className="tl" style={{ '--tl-progress': '78%' }}>
                <div className="tl-it" data-state="done">
                  <div className="tl-t">Cloned acme/storefront-ai</div>
                  <div className="tl-s">184 files · 11,842 LOC · TypeScript, Next.js</div>
                  <div className="tl-tm">00:00 → 00:03</div>
                </div>
                <div className="tl-it" data-state="done">
                  <div className="tl-t">Fingerprinted AI-generated code</div>
                  <div className="tl-s">Detected v0 (72%), Cursor (18%), hand-edited (10%)</div>
                  <div className="tl-tm">00:03 → 00:08</div>
                </div>
                <div className="tl-it" data-state="done">
                  <div className="tl-t">Secret & key sweep</div>
                  <div className="tl-s">Matched 14 providers · 1 exposed OpenAI key, 1 Supabase service role misplacement</div>
                  <div className="tl-tm">00:08 → 00:19</div>
                </div>
                <div className="tl-it" data-state="done">
                  <div className="tl-t">Route & auth graph</div>
                  <div className="tl-s">Walked 31 routes · 6 lack an auth guard · 2 allow public writes</div>
                  <div className="tl-tm">00:19 → 00:31</div>
                </div>
                <div className="tl-it" data-state="active">
                  <div className="tl-t">AI endpoint & tool review</div>
                  <div className="tl-s">Analyzing chat routes, MCP tools and rate limits</div>
                  <div className="tl-tm">00:31 → now</div>
                  <div className="tl-code">
                    <span className="c"># checking</span>{'\n'}
                    <span className="k">→</span> app/api/chat/route.ts{'\n'}
                    <span className="k">→</span> tools/shell.ts{'\n'}
                    <span className="c"># 3 suggestions queued</span>
                  </div>
                </div>
                <div className="tl-it">
                  <div className="tl-t">Generate patch PR</div>
                  <div className="tl-s">Drafts fixes as a branch you can review</div>
                  <div className="tl-tm">queued</div>
                </div>
              </div>
            </aside>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// VIEW 2 — Finding detail (split view)
// ==================================================================
function ViewFindingDetail() {
  const selected = FINDINGS[0]; // exposed OpenAI key
  return (
    <div className="app">
      <Sidebar active="scan"/>
      <div className="main">
        <Topbar
          crumbs={[
            { text: 'acme' },
            { text: 'storefront-ai' },
            { text: 'scan r_8f2a', mono: true },
            { text: 'F-001', mono: true },
          ]}
          actions={<>
            <button className="tb-btn"><Icon.external style={{ width: 12, height: 12 }}/>Open in editor</button>
            <button className="tb-btn primary"><Icon.patch style={{ width: 12, height: 12 }}/>Generate patch</button>
          </>}
        />
        <div className="split">
          <div className="split-list">
            <div className="split-list-head">
              <h2><Icon.filter style={{ width: 12, height: 12 }}/>Findings <span className="cnt">{FINDINGS.length}</span></h2>
              <button className="tb-btn" style={{ height: 24, padding: '0 8px', fontSize: 11 }}>Critical</button>
            </div>
            <div className="split-list-body">
              {FINDINGS.map(f => (
                <FindingRow key={f.id} f={f} selected={f.id === selected.id} compact/>
              ))}
            </div>
          </div>

          <div className="split-detail">
            <div className="detail-head">
              <div className="breadcrumb">
                <span>F-001</span>
                <span style={{ color: 'var(--fg-5)' }}>·</span>
                <b>lib/openai.ts</b>
                <span style={{ color: 'var(--fg-5)' }}>:3</span>
              </div>
              <h2>Exposed OpenAI API key committed <em>in source code</em></h2>
              <div className="tags">
                <span className="tag crit"><span className="d"/>critical</span>
                <span className="tag">CWE-798</span>
                <span className="tag">Secret</span>
                <span className="tag">AI provider</span>
                <span className="tag">Blocks deploy</span>
              </div>
              <div className="actions">
                <button className="tb-btn primary"><Icon.patch style={{ width: 12, height: 12 }}/>Apply patch</button>
                <button className="tb-btn"><Icon.copy style={{ width: 12, height: 12 }}/>Copy key to revoke</button>
                <button className="tb-btn"><Icon.share style={{ width: 12, height: 12 }}/>Share</button>
              </div>
            </div>

            <div className="detail-body">
              <div className="detail-section">
                <h3>What we found</h3>
                <div className="prose">
                  A plain-text OpenAI API key (<code>sk-proj-****Lk9Q</code>) is hard-coded in <code>lib/openai.ts</code> and was committed to <code>main</code> at <code>1f3c2a8</code>. The string matches the <code>sk-proj-*</code> provider format with 98% confidence. Any contributor with read access to the repo can exfiltrate it, and it is included in every build artifact shipped to Vercel.
                </div>
              </div>

              <div className="detail-section">
                <h3>Where it is</h3>
                <div className="code-block">
                  <div className="code-head">
                    <Icon.file style={{ width: 12, height: 12 }}/>
                    <span className="path"><b>lib/openai.ts</b></span>
                    <span className="spacer"/>
                    <button className="copy"><Icon.copy style={{ width: 11, height: 11 }}/>Copy</button>
                  </div>
                  <div className="code-body">
                    <div className="lnums">
                      <div>1</div><div>2</div><div className="ln-hit">3</div><div>4</div><div>5</div><div>6</div><div>7</div>
                    </div>
                    <pre>
<span className="k">import</span> <span className="v">{'{'} OpenAI {'}'}</span> <span className="k">from</span> <span className="s">"openai"</span>;{'\n'}
{'\n'}
<div className="ln-hit" style={{ margin: '0 -14px', padding: '0 14px' }}>
<span className="k">export const</span> <span className="v">openai</span> = <span className="k">new</span> <span className="f">OpenAI</span>({'{'} apiKey: <span className="s">"sk-proj-8zXq2...Lk9Q"</span> {'}'});
</div>
{'\n'}
<span className="k">export async function</span> <span className="f">ask</span>(<span className="v">prompt</span>: <span className="t">string</span>) {'{'}{'\n'}
  <span className="k">return</span> openai.responses.create({'{'} model: <span className="s">"gpt-4.1"</span>, input: prompt {'}'});{'\n'}
{'}'}
                    </pre>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>Why it matters</h3>
                <div className="prose">
                  Client-side bundles on Vercel inline this module, so the key leaks to every visitor's browser devtools in a production build. An attacker can siphon tokens, generate arbitrary completions billed to your org, or poison chat responses. OpenAI auto-revokes leaked keys within ~30 minutes — but anything issued in the meantime counts against your quota.
                </div>
              </div>

              <div className="detail-section">
                <h3>Recommended patch</h3>
                <div className="diff-block">
                  <div className="diff-head">
                    <Icon.branch style={{ width: 12, height: 12 }}/>
                    <span><b style={{ color: 'var(--fg)' }}>lib/openai.ts</b></span>
                    <span style={{ color: 'var(--fg-5)' }}>+ .env.local</span>
                    <span className="spacer"/>
                    <span className="badge"><Icon.bolt style={{ width: 10, height: 10 }}/>Auto-fix ready</span>
                  </div>
                  <div className="diff-rows">
                    <div className="diff-row"><div className="ln">1</div><div className="ln">1</div><div className="sign"> </div><pre>{`import { OpenAI } from "openai";`}</pre></div>
                    <div className="diff-row"><div className="ln">2</div><div className="ln">2</div><div className="sign"> </div><pre> </pre></div>
                    <div className="diff-row del"><div className="ln">3</div><div className="ln"></div><div className="sign">-</div><pre>{`export const openai = new OpenAI({ apiKey: "sk-proj-8zXq2...Lk9Q" });`}</pre></div>
                    <div className="diff-row add"><div className="ln"></div><div className="ln">3</div><div className="sign">+</div><pre>{`const key = process.env.OPENAI_API_KEY;`}</pre></div>
                    <div className="diff-row add"><div className="ln"></div><div className="ln">4</div><div className="sign">+</div><pre>{`if (!key) throw new Error("OPENAI_API_KEY is required");`}</pre></div>
                    <div className="diff-row add"><div className="ln"></div><div className="ln">5</div><div className="sign">+</div><pre>{`export const openai = new OpenAI({ apiKey: key });`}</pre></div>
                    <div className="diff-row"><div className="ln">4</div><div className="ln">6</div><div className="sign"> </div><pre> </pre></div>
                    <div className="diff-row"><div className="ln">5</div><div className="ln">7</div><div className="sign"> </div><pre>{`export async function ask(prompt: string) {`}</pre></div>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>Next steps</h3>
                <div className="reco-grid">
                  <div className="reco">
                    <span className="lbl">1 · Revoke</span>
                    <span className="val mono">sk-proj-****Lk9Q</span>
                    <span style={{ fontSize: 12, color: 'var(--fg-4)' }}>Opens OpenAI dashboard with the exact key pre-selected.</span>
                  </div>
                  <div className="reco">
                    <span className="lbl">2 · Rotate</span>
                    <span className="val">Issue new key → Vercel env</span>
                    <span style={{ fontSize: 12, color: 'var(--fg-4)' }}>Writes OPENAI_API_KEY to Preview + Production via the Vercel integration.</span>
                  </div>
                  <div className="reco">
                    <span className="lbl">3 · Purge history</span>
                    <span className="val mono">git filter-repo --path lib/openai.ts</span>
                    <span style={{ fontSize: 12, color: 'var(--fg-4)' }}>Scripted; we open a PR that rewrites history on a protected branch.</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// VIEW 3 — Agent run (timeline full width)
// ==================================================================
function ViewAgent() {
  return (
    <div className="app">
      <Sidebar active="agent"/>
      <div className="main">
        <Topbar
          crumbs={[
            { text: 'acme' },
            { text: 'storefront-ai' },
            { text: 'scan r_8f2a', mono: true },
            { text: 'agent run', mono: false },
          ]}
          scanStatus="running · 00:42"
          actions={<>
            <button className="tb-btn"><Icon.download style={{ width: 12, height: 12 }}/>Download log</button>
            <button className="tb-btn"><Icon.copy style={{ width: 12, height: 12 }}/>Copy run ID</button>
            <button className="tb-btn primary"><Icon.play style={{ width: 11, height: 11 }}/>Re-run</button>
          </>}
        />
        <div className="content">
          <div className="agent-page">
            <div className="agent-head2">
              <div>
                <h1>Agent run <em>r_8f2a</em></h1>
                <div className="sub">
                  <span>storefront-ai</span>
                  <span style={{ width: 3, height: 3, borderRadius: '50%', background: 'var(--fg-5)' }}/>
                  <span>main @ 1f3c2a8</span>
                  <span style={{ width: 3, height: 3, borderRadius: '50%', background: 'var(--fg-5)' }}/>
                  <span style={{ color: 'var(--accent)' }}>live · elapsed 00:42</span>
                </div>
              </div>
            </div>

            <div className="agent-stats">
              <div className="sc"><div className="sc-lbl">Steps</div><div className="sc-val">5 <small>/ 6</small></div><div className="sc-sub">1 in progress</div></div>
              <div className="sc"><div className="sc-lbl">Files walked</div><div className="sc-val">184</div><div className="sc-sub">11,842 LOC · TS + TSX</div></div>
              <div className="sc"><div className="sc-lbl">Tokens</div><div className="sc-val">312k <small>in · 47k out</small></div><div className="sc-sub">Claude Sonnet 4.5</div></div>
              <div className="sc"><div className="sc-lbl">Findings so far</div><div className="sc-val">15</div><div className="sc-sub">2 critical · 2 high · 2 medium</div></div>
            </div>

            <div className="agent-track">
              <div className="at-side">
                <div className="at-step">Step 01 · 00:00 → 00:03</div>
                <div className="at-title">Clone & index</div>
                <div className="at-sub">Shallow clone, build file graph.</div>
                <div className="at-state done"><span className="d"/>completed</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">00:00.12</span><span className="msg"><b>git clone</b> <span className="code">acme/storefront-ai</span> <span className="a">--depth 1</span></span><span className="tag">io</span></div>
                <div className="at-row"><span className="tm">00:01.84</span><span className="msg">Indexed 184 files · 11,842 LOC</span><span className="tag">parse</span></div>
                <div className="at-row"><span className="tm">00:02.41</span><span className="msg">Detected stack: <b>Next.js 14 (app router)</b>, TypeScript 5.4, Supabase, Vercel AI SDK</span><span className="tag">detect</span></div>
                <div className="at-row"><span className="tm">00:02.98</span><span className="msg"><span className="a">→</span> 31 API routes, 14 server actions, 9 middleware edges mapped</span><span className="tag">graph</span></div>
              </div>
            </div>

            <div className="agent-track">
              <div className="at-side">
                <div className="at-step">Step 02 · 00:03 → 00:08</div>
                <div className="at-title">AI-code fingerprint</div>
                <div className="at-sub">Classify authorship by heuristics.</div>
                <div className="at-state done"><span className="d"/>completed</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">00:03.22</span><span className="msg">Sampling token entropy, identifier cadence, comment density across 184 files</span><span className="tag">heur</span></div>
                <div className="at-row"><span className="tm">00:05.10</span><span className="msg"><b>v0.dev</b>: 132 files <span className="a">(72%)</span> · very consistent naming, classname ballast</span><span className="tag">class</span></div>
                <div className="at-row"><span className="tm">00:06.44</span><span className="msg"><b>Cursor agent</b>: 33 files <span className="a">(18%)</span> · frequent TODO: stubs, `any` casts in generated helpers</span><span className="tag">class</span></div>
                <div className="at-row"><span className="tm">00:07.71</span><span className="msg">Hand-edited: 19 files <span className="a">(10%)</span> · concentrated in <span className="code">lib/auth</span></span><span className="tag">class</span></div>
              </div>
            </div>

            <div className="agent-track">
              <div className="at-side">
                <div className="at-step">Step 03 · 00:08 → 00:19</div>
                <div className="at-title">Secret sweep</div>
                <div className="at-sub">14 provider formats, entropy + format match.</div>
                <div className="at-state done"><span className="d"/>completed</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">00:08.40</span><span className="msg">Running 14 provider matchers against 184 files and git history</span><span className="tag">scan</span></div>
                <div className="at-row"><span className="tm">00:12.09</span><span className="msg"><span className="d">✗</span> <b>OpenAI key</b> in <span className="code">lib/openai.ts:3</span> — committed at <span className="code">1f3c2a8</span></span><span className="tag">hit</span></div>
                <div className="at-row"><span className="tm">00:14.71</span><span className="msg"><span className="w">⚠</span> <b>Supabase service role</b> read from <span className="code">NEXT_PUBLIC_SUPABASE_SERVICE_ROLE</span> — leaks to client bundle</span><span className="tag">hit</span></div>
                <div className="at-row"><span className="tm">00:16.22</span><span className="msg"><span className="a">→</span> Verified via format match (98%) + live API probe (not attempted)</span><span className="tag">verify</span></div>
                <div className="at-row"><span className="tm">00:18.93</span><span className="msg">2 findings queued for patch generation</span><span className="tag">queue</span></div>
              </div>
            </div>

            <div className="agent-track">
              <div className="at-side">
                <div className="at-step">Step 04 · 00:19 → 00:31</div>
                <div className="at-title">Route & auth graph</div>
                <div className="at-sub">Trace every HTTP entrypoint to a guard.</div>
                <div className="at-state done"><span className="d"/>completed</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">00:19.88</span><span className="msg">Built call graph for 31 routes + 14 server actions</span><span className="tag">graph</span></div>
                <div className="at-row"><span className="tm">00:23.40</span><span className="msg"><span className="d">✗</span> <b>/api/users</b> — no <span className="code">auth()</span> guard, returns <span className="code">select * from users</span></span><span className="tag">hit</span></div>
                <div className="at-row"><span className="tm">00:26.12</span><span className="msg"><span className="w">⚠</span> <b>/api/checkout</b> — mutation without CSRF token verification</span><span className="tag">hit</span></div>
                <div className="at-row"><span className="tm">00:29.55</span><span className="msg"><span className="w">⚠</span> <b>/api/chat</b> — no per-user rate limit, unbounded token spend</span><span className="tag">hit</span></div>
              </div>
            </div>

            <div className="agent-track" style={{ borderColor: 'rgba(127,231,196,0.25)' }}>
              <div className="at-side">
                <div className="at-step" style={{ color: 'var(--accent)' }}>Step 05 · 00:31 → now</div>
                <div className="at-title">AI endpoint & tool review</div>
                <div className="at-sub">Chat routes, MCP tools, rate limits, prompt injection.</div>
                <div className="at-state active"><span className="d"/>running</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">00:31.15</span><span className="msg">Enumerating AI surfaces: 2 chat routes, 4 MCP tools, 1 streaming endpoint</span><span className="tag">scan</span></div>
                <div className="at-row"><span className="tm">00:34.02</span><span className="msg"><span className="d">✗</span> <span className="code">tools/shell.ts</span> — exec with arbitrary argv, no allow-list</span><span className="tag">hit</span></div>
                <div className="at-row"><span className="tm">00:37.71</span><span className="msg"><span className="a">→</span> Drafting patch: narrow exec to <span className="code">{`{ "git": ["log","status"] }`}</span></span><span className="tag">patch</span></div>
                <div className="at-row"><span className="tm">00:40.88</span><span className="msg">Analyzing <span className="code">app/api/chat/route.ts</span> for prompt-injection surface…</span><span className="tag">scan</span></div>
                <div className="at-row"><span className="tm">00:42.00</span><span className="msg" style={{ color: 'var(--fg-5)' }}>_ waiting for model</span><span className="tag">…</span></div>
              </div>
            </div>

            <div className="agent-track" style={{ opacity: 0.6 }}>
              <div className="at-side">
                <div className="at-step">Step 06 · queued</div>
                <div className="at-title">Patch PR</div>
                <div className="at-sub">Draft a reviewable fix branch.</div>
                <div className="at-state"><span className="d" style={{ background: 'var(--fg-5)' }}/>queued</div>
              </div>
              <div className="at-body">
                <div className="at-row"><span className="tm">—</span><span className="msg" style={{ color: 'var(--fg-5)' }}>Waits for step 05. Will draft <span className="code">vibeshield/scan-r_8f2a</span> with 9 file changes.</span><span className="tag">plan</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// VIEW 4 — Patches & PR
// ==================================================================
function ViewPatches() {
  return (
    <div className="app">
      <Sidebar active="patches"/>
      <div className="main">
        <Topbar
          crumbs={[
            { text: 'acme' },
            { text: 'storefront-ai' },
            { text: 'patches' },
            { text: 'PR #142', mono: true },
          ]}
          actions={<>
            <button className="tb-btn"><Icon.external style={{ width: 12, height: 12 }}/>Open on GitHub</button>
            <button className="tb-btn"><Icon.copy style={{ width: 12, height: 12 }}/>Copy branch</button>
            <button className="tb-btn accent"><Icon.check style={{ width: 12, height: 12 }}/>Merge patch PR</button>
          </>}
        />
        <div className="content">
          <div className="patches-page">
            <div className="pr-card">
              <div className="pr-head">
                <div className="pr-left">
                  <span className="pr-status"><Icon.check style={{ width: 10, height: 10 }}/>Ready to review</span>
                  <div className="pr-title">VibeShield fixes · <em>storefront-ai</em></div>
                  <div className="pr-meta">
                    <Icon.commit style={{ width: 12, height: 12 }}/>
                    <b>9 commits</b>
                    <span style={{ color: 'var(--fg-5)' }}>·</span>
                    <span>opened 00:41 ago</span>
                    <span style={{ color: 'var(--fg-5)' }}>·</span>
                    <span>by <b>VibeShield agent</b></span>
                  </div>
                </div>
                <div className="pr-actions">
                  <button className="tb-btn"><Icon.download style={{ width: 12, height: 12 }}/>Export diff</button>
                </div>
              </div>

              <div className="pr-branch">
                <span className="b"><Icon.branch style={{ width: 11, height: 11, verticalAlign: -1, marginRight: 4 }}/>main</span>
                <span className="arrow">←</span>
                <span className="b" style={{ color: 'var(--accent)', borderColor: 'rgba(127,231,196,0.3)' }}>
                  <Icon.branch style={{ width: 11, height: 11, verticalAlign: -1, marginRight: 4 }}/>vibeshield/scan-r_8f2a
                </span>
                <span className="spacer"/>
                <span className="stat">
                  <span>7 files changed</span>
                  <span className="add-n">+48</span>
                  <span className="del-n">−19</span>
                </span>
              </div>

              <div className="pr-body">
                <div style={{ fontSize: 10.5, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fg-5)', fontWeight: 500, marginTop: 4 }}>
                  Findings fixed in this PR
                </div>
                <div className="pr-checklist">
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Moved OpenAI key to <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)' }}>OPENAI_API_KEY</code> env var
                    <span className="sev sev-critical"><span className="d"/>critical</span>
                    <span className="path">lib/openai.ts</span>
                  </div>
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Wrapped <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)' }}>/api/users</code> in <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)' }}>requireAuth()</code> guard
                    <span className="sev sev-critical"><span className="d"/>critical</span>
                    <span className="path">app/api/users/route.ts</span>
                  </div>
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Added per-IP rate limit to <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)' }}>/api/chat</code> (30 req/min)
                    <span className="sev sev-high"><span className="d"/>high</span>
                    <span className="path">app/api/chat/route.ts</span>
                  </div>
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Narrowed MCP shell tool to an allow-list
                    <span className="sev sev-high"><span className="d"/>high</span>
                    <span className="path">tools/shell.ts</span>
                  </div>
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Moved Supabase service role to server-only env
                    <span className="sev sev-medium"><span className="d"/>medium</span>
                    <span className="path">lib/db.ts</span>
                  </div>
                  <div className="pr-check">
                    <div className="cb"><Icon.check/></div>
                    Added CSRF token verification on mutation routes
                    <span className="sev sev-medium"><span className="d"/>medium</span>
                    <span className="path">app/api/checkout/route.ts</span>
                  </div>
                </div>

                <div style={{ fontSize: 10.5, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fg-5)', fontWeight: 500, marginTop: 8 }}>
                  Representative diff
                </div>

                <div className="pr-file">
                  <div className="pr-file-head">
                    <Icon.file style={{ width: 12, height: 12 }}/>
                    <span><b>app/api/users/route.ts</b></span>
                    <span style={{ color: 'var(--fg-5)' }}>·</span>
                    <span className="sm">+8 −3</span>
                    <span className="spacer"/>
                    <span className="sm">fixes F-002</span>
                  </div>
                  <div className="diff-block" style={{ border: 0, borderRadius: 0 }}>
                    <div className="diff-rows">
                      <div className="diff-row"><div className="ln">1</div><div className="ln">1</div><div className="sign"> </div><pre>{`import { NextResponse } from "next/server";`}</pre></div>
                      <div className="diff-row"><div className="ln">2</div><div className="ln">2</div><div className="sign"> </div><pre>{`import { db } from "@/lib/db";`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">3</div><div className="sign">+</div><pre>{`import { requireAuth } from "@/lib/auth";`}</pre></div>
                      <div className="diff-row"><div className="ln">3</div><div className="ln">4</div><div className="sign"> </div><pre> </pre></div>
                      <div className="diff-row del"><div className="ln">4</div><div className="ln"></div><div className="sign">−</div><pre>{`export async function GET() {`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">5</div><div className="sign">+</div><pre>{`export async function GET(req: Request) {`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">6</div><div className="sign">+</div><pre>{`  const session = await requireAuth(req);`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">7</div><div className="sign">+</div><pre>{`  if (!session.user.isAdmin) return new Response("forbidden", { status: 403 });`}</pre></div>
                      <div className="diff-row"><div className="ln">5</div><div className="ln">8</div><div className="sign"> </div><pre>{`  const users = await db.from("users").select("id,email,created_at");`}</pre></div>
                      <div className="diff-row del"><div className="ln">6</div><div className="ln"></div><div className="sign">−</div><pre>{`  return NextResponse.json(users);`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">9</div><div className="sign">+</div><pre>{`  return NextResponse.json(users.data);`}</pre></div>
                      <div className="diff-row"><div className="ln">7</div><div className="ln">10</div><div className="sign"> </div><pre>{`}`}</pre></div>
                    </div>
                  </div>
                </div>

                <div className="pr-file">
                  <div className="pr-file-head">
                    <Icon.file style={{ width: 12, height: 12 }}/>
                    <span><b>tools/shell.ts</b></span>
                    <span style={{ color: 'var(--fg-5)' }}>·</span>
                    <span className="sm">+11 −5</span>
                    <span className="spacer"/>
                    <span className="sm">fixes F-004</span>
                  </div>
                  <div className="diff-block" style={{ border: 0, borderRadius: 0 }}>
                    <div className="diff-rows">
                      <div className="diff-row"><div className="ln">40</div><div className="ln">40</div><div className="sign"> </div><pre>{`export const shell: Tool = {`}</pre></div>
                      <div className="diff-row"><div className="ln">41</div><div className="ln">41</div><div className="sign"> </div><pre>{`  name: "shell",`}</pre></div>
                      <div className="diff-row del"><div className="ln">42</div><div className="ln"></div><div className="sign">−</div><pre>{`  run: async ({ cmd, args }) => exec(cmd, args),`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">42</div><div className="sign">+</div><pre>{`  run: async ({ cmd, args }) => {`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">43</div><div className="sign">+</div><pre>{`    const allow = ALLOWLIST[cmd];`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">44</div><div className="sign">+</div><pre>{`    if (!allow) throw new Error(\`shell: \${cmd} not permitted\`);`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">45</div><div className="sign">+</div><pre>{`    if (!args.every(a => allow.args.includes(a))) throw new Error("shell: arg denied");`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">46</div><div className="sign">+</div><pre>{`    return exec(cmd, args, { timeout: 5_000 });`}</pre></div>
                      <div className="diff-row add"><div className="ln"></div><div className="ln">47</div><div className="sign">+</div><pre>{`  },`}</pre></div>
                      <div className="diff-row"><div className="ln">43</div><div className="ln">48</div><div className="sign"> </div><pre>{`};`}</pre></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// VIEW 5 — Billing / Usage
// ==================================================================
function ViewBilling() {
  // Generate activity bars
  const bars = React.useMemo(() => {
    return Array.from({ length: 30 }, (_, i) => {
      const base = 30 + Math.sin(i * 0.6) * 20 + Math.cos(i * 0.4) * 15;
      const s = Math.max(12, Math.round(base + Math.random() * 35));
      const p = Math.max(4, Math.round((s * 0.25) + Math.random() * 10));
      return { s, p };
    });
  }, []);
  const maxH = 170;
  const maxVal = Math.max(...bars.map(b => b.s + b.p));

  return (
    <div className="app">
      <Sidebar active="billing"/>
      <div className="main">
        <Topbar
          crumbs={[
            { text: 'acme' },
            { text: 'Billing & usage' },
          ]}
          actions={<>
            <button className="tb-btn"><Icon.download style={{ width: 12, height: 12 }}/>Download invoice</button>
            <button className="tb-btn primary">Manage plan</button>
          </>}
        />
        <div className="subnav">
          <div className="s-tab" data-active={true}><Icon.chart/>Overview</div>
          <div className="s-tab"><Icon.scan/>Usage <span className="n">412</span></div>
          <div className="s-tab"><Icon.file/>Invoices <span className="n">6</span></div>
          <div className="s-tab"><Icon.key/>Payment method</div>
          <div className="s-tab"><Icon.team/>Seats <span className="n">7/10</span></div>
        </div>
        <div className="content">
          <div className="billing">
            <div className="billing-head">
              <h1>Billing <em>& usage</em></h1>
              <div className="sub">Cycle resets <span style={{ color: 'var(--fg-2)', fontFamily: 'var(--font-mono)' }}>Dec 1, 2024</span> · next invoice <span style={{ color: 'var(--fg-2)', fontFamily: 'var(--font-mono)' }}>$480.00</span></div>
            </div>

            <div className="plan-card">
              <div>
                <div className="plan-name">Pro plan</div>
                <h2>$480 <em>/ month</em></h2>
                <div className="price">1,000 scans · unlimited repos · up to 10 seats · <b>PR auto-patch</b> · SSO + SAML</div>
              </div>
              <div className="plan-actions">
                <button className="tb-btn">View plans</button>
                <button className="tb-btn primary">Upgrade to Team</button>
              </div>
            </div>

            <div className="usage-grid">
              <div className="u-card">
                <div className="u-title"><span>Scans this cycle</span><span style={{ color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>41%</span></div>
                <div className="u-val">412 <small>/ 1,000</small></div>
                <div className="u-bar"><i style={{ width: '41%' }}/></div>
                <div className="u-sub">On pace for 892 by Dec 1 · below plan limit.</div>
              </div>
              <div className="u-card">
                <div className="u-title"><span>Agent tokens</span><span style={{ color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>62%</span></div>
                <div className="u-val">124M <small>/ 200M</small></div>
                <div className="u-bar"><i style={{ width: '62%' }}/></div>
                <div className="u-sub">Claude Sonnet 4.5 · billed as part of Pro.</div>
              </div>
              <div className="u-card">
                <div className="u-title"><span>Seats</span><span style={{ color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>70%</span></div>
                <div className="u-val">7 <small>/ 10</small></div>
                <div className="u-bar"><i style={{ width: '70%' }}/></div>
                <div className="u-sub">3 pending invites · 1 admin, 6 members.</div>
              </div>
            </div>

            <div className="chart-card">
              <div className="chart-head">
                <div>
                  <h3>Scan activity · last 30 days</h3>
                  <div style={{ fontSize: 12, color: 'var(--fg-4)', marginTop: 4 }}>412 scans · 37 patch PRs opened · avg 11.3s per scan</div>
                </div>
                <div className="leg">
                  <span className="l-scan"><i/>scans</span>
                  <span className="l-patch"><i/>patch PRs</span>
                </div>
              </div>
              <div className="chart">
                {bars.map((b, i) => {
                  const h = maxH * ((b.s + b.p) / maxVal);
                  const sH = maxH * (b.s / maxVal);
                  const pH = maxH * (b.p / maxVal);
                  return (
                    <div className="bar" key={i} style={{ height: h }}>
                      <div className="p" style={{ height: pH }}/>
                      <div className="s" style={{ height: sH }}/>
                    </div>
                  );
                })}
              </div>
              <div className="chart-axis">
                <span>Nov 1</span><span>Nov 7</span><span>Nov 14</span><span>Nov 21</span><span>Nov 28</span>
              </div>
            </div>

            <div>
              <div style={{ fontSize: 11, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--fg-5)', fontWeight: 500, marginBottom: 10 }}>
                Recent invoices
              </div>
              <div className="tbl">
                <div className="tbl-head">
                  <div>Date</div>
                  <div>Description</div>
                  <div>Amount</div>
                  <div>Status</div>
                  <div></div>
                </div>
                <div className="tbl-row">
                  <div>Nov 1, 2024</div>
                  <div style={{ color: 'var(--fg)' }}>Pro · monthly · acme</div>
                  <div className="amt">$480.00</div>
                  <div><span className="status-pill paid">Paid</span></div>
                  <div><button className="dl"><Icon.download style={{ width: 11, height: 11 }}/>PDF</button></div>
                </div>
                <div className="tbl-row">
                  <div>Oct 1, 2024</div>
                  <div style={{ color: 'var(--fg)' }}>Pro · monthly · acme</div>
                  <div className="amt">$480.00</div>
                  <div><span className="status-pill paid">Paid</span></div>
                  <div><button className="dl"><Icon.download style={{ width: 11, height: 11 }}/>PDF</button></div>
                </div>
                <div className="tbl-row">
                  <div>Sep 1, 2024</div>
                  <div style={{ color: 'var(--fg)' }}>Pro · monthly · acme</div>
                  <div className="amt">$480.00</div>
                  <div><span className="status-pill paid">Paid</span></div>
                  <div><button className="dl"><Icon.download style={{ width: 11, height: 11 }}/>PDF</button></div>
                </div>
                <div className="tbl-row">
                  <div>Aug 1, 2024</div>
                  <div style={{ color: 'var(--fg)' }}>Starter → Pro upgrade · prorated</div>
                  <div className="amt">$312.58</div>
                  <div><span className="status-pill paid">Paid</span></div>
                  <div><button className="dl"><Icon.download style={{ width: 11, height: 11 }}/>PDF</button></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { ViewReport, ViewFindingDetail, ViewAgent, ViewPatches, ViewBilling });
