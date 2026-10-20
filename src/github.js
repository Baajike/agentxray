// Fetch a public GitHub repo's risky surfaces WITHOUT cloning it.
// Cloning can fire hooks; reading raw files over HTTPS cannot.
import { isInteresting } from './engine.js';

export function parseRepo(input) {
  const s = String(input).trim().replace(/\.git$/, '').replace(/\/+$/, '');
  const m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)(?:\/tree\/([^?#]+))?/i) || s.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2], ref: m[3] ? decodeURIComponent(m[3]) : null };
}

export async function fetchRepo(input, { token, onProgress = () => {}, maxFiles = 400, concurrency = 10 } = {}) {
  const r = typeof input === 'string' ? parseRepo(input) : input;
  if (!r) throw new Error('Not a GitHub repo. Try owner/repo or https://github.com/owner/repo');
  const h = { Accept: 'application/vnd.github+json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const api = async (u) => {
    const res = await fetch(`https://api.github.com${u}`, { headers: h });
    if (res.status === 403 || res.status === 429) throw new Error('GitHub API rate limit reached (60 requests/hour without a token). Try again later, or use the CLI with GITHUB_TOKEN.');
    if (res.status === 404) throw new Error(`Repository ${r.owner}/${r.repo} not found (or it's private).`);
    if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
    return res.json();
  };
  onProgress({ step: 'meta', msg: `Looking up ${r.owner}/${r.repo}…` });
  const meta = await api(`/repos/${r.owner}/${r.repo}`);
  const ref = r.ref || meta.default_branch;
  onProgress({ step: 'tree', msg: `Mapping the file tree on ${ref}…` });
  const tree = await api(`/repos/${r.owner}/${r.repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`);
  const blobs = tree.tree.filter(e => e.type === 'blob');
  const wanted = blobs.filter(e => e.mode === '120000' || isInteresting(e.path, e.size))
    .sort((a, b) => depth(a.path) - depth(b.path)).slice(0, maxFiles);
  const files = [];
  let done = 0;
  const queue = [...wanted];
  const worker = async () => {
    while (queue.length) {
      const e = queue.shift();
      try {
        const res = await fetch(`https://raw.githubusercontent.com/${r.owner}/${r.repo}/${encodeURIComponent(ref)}/${e.path.split('/').map(encodeURIComponent).join('/')}`);
        const text = res.ok ? await res.text() : '';
        if (e.mode === '120000') files.push({ path: e.path, isSymlink: true, linkTarget: text.trim(), text: '' });
        else files.push({ path: e.path, text, size: e.size });
      } catch { /* skip unreadable file */ }
      done++;
      onProgress({ step: 'files', done, total: wanted.length, msg: e.path });
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return { files, meta: { name: meta.full_name, ref, stars: meta.stargazers_count, totalFiles: blobs.length, scannedFiles: files.length, truncated: !!tree.truncated, url: meta.html_url } };
}

const depth = p => p.split('/').length;
