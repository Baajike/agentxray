// AgentXray for GitHub: shows a grade next to the repo name on every repository page.
// Reads files over HTTPS with the shared engine. Never clones, never executes anything.
(() => {
  const SITE = 'https://baajike.github.io/agentxray/';
  const TTL = 6 * 60 * 60 * 1000; // cache results for 6 hours
  const RESERVED = new Set(['settings', 'orgs', 'organizations', 'marketplace', 'explore', 'topics', 'trending', 'collections', 'sponsors', 'notifications', 'issues', 'pulls', 'search', 'login', 'join', 'new', 'codespaces', 'features', 'enterprise', 'pricing', 'about', 'apps', 'site', 'security', 'customer-stories', 'readme', 'stars', 'dashboard', 'copilot', 'account', 'users']);
  const COLORS = { A: ['#0b2418', '#39ff9c'], B: ['#11240f', '#9cff6a'], C: ['#26210b', '#ffd24a'], D: ['#2a170b', '#ff8a3d'], F: ['#2a0b12', '#ff3b5c'] };

  let mods = null;
  let currentKey = null;
  let host = null;

  const load = async () => mods || (mods = await Promise.all([
    import(chrome.runtime.getURL('lib/engine.js')),
    import(chrome.runtime.getURL('lib/github.js')),
  ]));

  function repoFromPath() {
    const [owner, repo] = location.pathname.split('/').filter(Boolean);
    if (!owner || !repo || RESERVED.has(owner.toLowerCase())) return null;
    if (!document.querySelector('meta[name="octolytics-dimension-repository_nwo"], meta[name="go-import"]') && !document.querySelector('#repository-container-header')) return null;
    return { owner, repo, key: `${owner}/${repo}`.toLowerCase() };
  }

  function mountPoint() {
    return document.querySelector('#repository-container-header strong[itemprop="name"]')?.parentElement
      || document.querySelector('[itemprop="name"]')?.parentElement
      || document.querySelector('#repo-title-component')
      || null;
  }

  function ensureHost() {
    if (host && document.contains(host)) return host;
    host = document.createElement('span');
    host.id = 'agentxray-badge';
    host.attachShadow({ mode: 'open' });
    const mp = mountPoint();
    if (mp) { host.style.marginLeft = '10px'; host.style.display = 'inline-flex'; host.style.verticalAlign = 'middle'; mp.appendChild(host); }
    else { Object.assign(host.style, { position: 'fixed', right: '18px', bottom: '18px', zIndex: 2147483646 }); document.body.appendChild(host); }
    return host;
  }

  const css = `
    :host{all:initial}
    a,div{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;box-sizing:border-box}
    .pill{display:inline-flex;align-items:center;gap:7px;padding:3px 10px 3px 4px;border-radius:999px;font-size:12px;font-weight:700;text-decoration:none;border:1px solid;cursor:pointer;line-height:18px;position:relative;white-space:nowrap}
    .g{display:inline-grid;place-items:center;width:20px;height:20px;border-radius:6px;font-weight:800;font-size:13px}
    .muted{color:#8b98a6;border-color:#30363d;background:#0d1117}
    .tip{display:none;position:absolute;top:calc(100% + 8px);left:0;width:360px;background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:12px 14px;color:#d8e1ea;font-weight:400;white-space:normal;box-shadow:0 12px 32px rgba(0,0,0,.5);z-index:10;cursor:default}
    .wrap:hover .tip,.wrap:focus-within .tip{display:block}
    .wrap{position:relative;display:inline-block}
    .v{font-size:12.5px;line-height:1.45;margin-bottom:8px}
    .c{font-size:11px;color:#8b98a6;margin-bottom:8px}
    .f{font-size:11.5px;line-height:1.4;padding:5px 0;border-top:1px solid #21262d}
    .s{font-weight:800;font-size:10px;padding:1px 5px;border-radius:4px;margin-right:6px}
    .critical{background:#ff3b5c;color:#fff}.high{background:#ff8a3d;color:#1a0c00}.medium{background:#ffd24a;color:#1a1400}.low,.info{background:#1e3557;color:#cfe2ff}
    .more{display:block;margin-top:8px;font-size:11.5px;color:#5ad8ff;text-decoration:none}
    .spin{width:10px;height:10px;border:2px solid #30363d;border-top-color:#39ff9c;border-radius:50%;animation:r .8s linear infinite;margin-left:6px}
    @keyframes r{to{transform:rotate(360deg)}}
  `;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function draw(html) { const h = ensureHost(); h.shadowRoot.innerHTML = `<style>${css}</style>${html}`; }

  function drawLoading() { draw(`<span class="pill muted"><span class="spin"></span>AgentXray scanning</span>`); }

  function drawError(msg) {
    draw(`<span class="wrap"><a class="pill muted" href="${SITE}" target="_blank" rel="noopener">AgentXray ?</a><div class="tip"><div class="v">${esc(msg)}</div><a class="more" href="#" id="opt">Add a GitHub token in AgentXray options</a></div></span>`);
    host.shadowRoot.getElementById('opt')?.addEventListener('click', e => { e.preventDefault(); chrome.runtime.sendMessage?.({ open: 'options' }); window.open(chrome.runtime.getURL('options.html')); });
  }

  function drawResult(r, slug) {
    const [bg, fg] = COLORS[r.grade];
    // group repeats: "AI agent in CI..." x2 becomes one line
    const grouped = [];
    for (const f of r.findings.filter(f => f.severity !== 'info')) {
      const g = grouped.find(x => x.title === f.title);
      if (g) g.n++; else grouped.push({ ...f, n: 1 });
    }
    const top = grouped.slice(0, 4);
    const counts = ['critical', 'high', 'medium', 'low'].filter(s => r.counts[s]).map(s => `${r.counts[s]} ${s}`).join(' · ') || 'no findings';
    const url = `${SITE}#gh=${slug}`;
    draw(`<span class="wrap"><a class="pill" style="background:${bg};color:${fg};border-color:${fg}55" href="${url}" target="_blank" rel="noopener" title="Open the full AgentXray report">
      <span class="g" style="background:${fg};color:${bg}">${r.grade}</span>AgentXray ${r.score}</a>
      <div class="tip"><div class="v">${esc(r.verdict)}</div><div class="c">${counts}${r.stats.hidden ? ` · ${r.stats.hidden} hidden message${r.stats.hidden > 1 ? 's' : ''}` : ''} · ${r.stats.files} files read</div>
      ${top.map(f => `<div class="f"><span class="s ${f.severity}">${f.severity.toUpperCase()}</span>${esc(f.title)}${f.n > 1 ? ` <span style="color:#8b98a6">x${f.n}</span>` : ''}</div>`).join('')}
      <a class="more" href="${url}" target="_blank" rel="noopener">Full report, timeline and fixes</a></div></span>`);
  }

  async function run() {
    const r = repoFromPath();
    if (!r) { currentKey = null; return; }
    if (r.key === currentKey && host && document.contains(host)) return;
    currentKey = r.key;
    const cacheKey = `ax:${r.key}`;
    const store = await chrome.storage.local.get([cacheKey, 'token']);
    const cached = store[cacheKey];
    if (cached && Date.now() - cached.at < TTL) return drawResult(cached.r, cached.slug);
    drawLoading();
    try {
      const [{ scan }, { fetchRepo }] = await load();
      const { files, meta } = await fetchRepo(`${r.owner}/${r.repo}`, { token: store.token || undefined, concurrency: 6 });
      const res = scan(files);
      // keep only what the badge needs, so storage stays small
      const slim = { grade: res.grade, score: res.score, verdict: res.verdict, counts: res.counts, stats: res.stats, findings: res.findings.slice(0, 12).map(f => ({ severity: f.severity, title: f.title })) };
      await chrome.storage.local.set({ [cacheKey]: { at: Date.now(), r: slim, slug: meta.name } });
      if (currentKey === r.key) drawResult(slim, meta.name);
    } catch (e) {
      if (currentKey === r.key) drawError(e.message || 'Scan failed');
    }
  }

  // GitHub navigates without full page loads, so watch for URL changes.
  let lastPath = '';
  const tick = () => { if (location.pathname !== lastPath) { lastPath = location.pathname; run(); } else if (currentKey && host && !document.contains(host)) { currentKey = null; run(); } };
  document.addEventListener('turbo:load', tick);
  setInterval(tick, 1000);
  tick();
})();
