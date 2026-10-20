#!/usr/bin/env node
// AgentXray CLI — see what a repo can make your AI coding agent do, before you open it.
import { readdirSync, lstatSync, readFileSync, readlinkSync, existsSync, writeFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { scan, isInteresting, badge, VERSION, PHASES, SEVERITIES } from '../src/engine.js';
import { fetchRepo, parseRepo } from '../src/github.js';
import { toSarif } from '../src/sarif.js';
import { DEMO_FILES, DEMO_NAME } from '../src/demo.js';

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : d; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !['--fail-on', '--ignore-file', '--out', '--format'].includes(argv[i - 1]));

if (flag('--help') || flag('-h')) {
  console.log(`
  agentxray ${VERSION} — X-ray a repo before your AI coding agent touches it

  Usage
    agentxray [path | owner/repo | github-url]     scan a folder (default: .) or a GitHub repo without cloning
    agentxray --demo                               scan a built-in booby-trapped repo

  Output
    --json                 machine-readable result
    --sarif                SARIF 2.1.0 (GitHub code scanning)
    --out <file>           write output to a file
    --badge                print a README badge for this repo's grade
    --verbose              show why + fix for every finding (default: critical/high only)
    --no-color

  CI
    --fail-on <severity>   exit 1 if any finding is at/above: critical | high | medium | low
    --ignore-file <path>   your own ignore list (globs or rule ids, one per line).
                           A scanned repo's own .agentxrayignore is NEVER trusted — a repo can't silence itself.

  Env
    GITHUB_TOKEN           raises the GitHub API limit for remote scans
`);
  process.exit(0);
}
if (flag('--version')) { console.log(VERSION); process.exit(0); }

const machine = flag('--json') || flag('--sarif');
const useColor = !flag('--no-color') && !machine && process.stdout.isTTY !== false && !process.env.NO_COLOR;
const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const C = { red: c('31'), green: c('32'), yellow: c('33'), blue: c('34'), mag: c('35'), cyan: c('36'), dim: c('2'), bold: c('1'), inv: c('7'), bred: c('1;31'), bgreen: c('1;32') };
const SEVC = { critical: s => C.bred(s), high: C.red, medium: C.yellow, low: C.blue, info: C.dim };
const GRADEC = { A: C.bgreen, B: C.green, C: C.yellow, D: c('38;5;208'), F: C.bred };
const err = (...a) => { if (!machine) console.error(...a); };

// ── collect files ─────────────────────────────────────────────
const SKIP_DIRS = new Set(['node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'target', '.turbo', '.cache', 'coverage', '.pnpm-store', 'vendor']);

function walk(root) {
  const out = [];
  const stack = [root];
  let seen = 0;
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const abs = join(dir, e.name);
      const rel = relative(root, abs).split('\\').join('/');
      if (++seen > 200_000) return out;
      let st; try { st = lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) { let t = ''; try { t = readlinkSync(abs); } catch {} out.push({ path: rel, isSymlink: true, linkTarget: t, text: '' }); continue; }
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (rel === '.git') { for (const sub of ['config', 'hooks', 'modules']) if (existsSync(join(abs, sub))) collectGit(root, join(abs, sub), out); continue; }
        stack.push(abs); continue;
      }
      if (!st.isFile() || !isInteresting(rel, st.size)) continue;
      try { out.push({ path: rel, text: readFileSync(abs, 'utf8'), size: st.size }); } catch {}
    }
  }
  return out;
}
function collectGit(root, abs, out) {
  const st = lstatSync(abs);
  if (st.isFile()) { out.push({ path: relative(root, abs).split('\\').join('/'), text: readFileSync(abs, 'utf8'), size: st.size }); return; }
  for (const n of readdirSync(abs)) {
    const p = join(abs, n); const s = lstatSync(p);
    if (s.isDirectory()) collectGit(root, p, out);
    else if (/\/(hooks\/[^/]+|config)$/.test(p.split('\\').join('/')) && s.size < 500_000) out.push({ path: relative(root, p).split('\\').join('/'), text: readFileSync(p, 'utf8'), size: s.size });
  }
}

// ── main ──────────────────────────────────────────────────────
const target = positional[0] || '.';
let files, label, meta = null;
const t0 = Date.now();

try {
  if (flag('--demo')) { files = DEMO_FILES; label = `${DEMO_NAME} (built-in demo)`; }
  else if (!existsSync(target) && parseRepo(target)) {
    label = target;
    err(C.dim(`  ⟳ fetching ${target} from GitHub (no clone, nothing executes)…`));
    const res = await fetchRepo(target, { token: process.env.GITHUB_TOKEN || process.env.GH_TOKEN });
    files = res.files; meta = res.meta; label = `github.com/${meta.name}@${meta.ref}`;
  } else {
    if (!existsSync(target) || !statSync(target).isDirectory()) { console.error(`agentxray: "${target}" is not a folder or a GitHub repo`); process.exit(2); }
    files = walk(resolve(target)); label = resolve(target);
  }
} catch (e) { console.error(C.red(`agentxray: ${e.message}`)); process.exit(2); }

const ignoreFile = opt('--ignore-file');
const ignore = ignoreFile && existsSync(ignoreFile) ? readFileSync(ignoreFile, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')) : [];
const result = scan(files, { ignore });
result.target = label;
if (meta) result.github = meta;
const ms = Date.now() - t0;

// ── output ────────────────────────────────────────────────────
const out = opt('--out');
const emit = (s) => (out ? writeFileSync(out, s) : process.stdout.write(s + '\n'));

if (flag('--sarif')) emit(JSON.stringify(toSarif(result), null, 2));
else if (flag('--json')) emit(JSON.stringify(result, null, 2));
else if (flag('--badge')) emit(`[![AgentXray ${result.grade}](${badge(result)})](https://github.com/topics/agentxray)`);
else printPretty(result);

const failOn = opt('--fail-on');
if (failOn) {
  const rank = SEVERITIES.length - SEVERITIES.indexOf(failOn);
  if (result.findings.some(f => SEVERITIES.length - SEVERITIES.indexOf(f.severity) >= rank)) process.exit(1);
}

function printPretty(r) {
  const W = Math.min(process.stdout.columns || 100, 110);
  const line = C.dim('─'.repeat(W));
  console.log();
  console.log(C.cyan(C.bold('  ▌▌ AgentXray')) + C.dim(`  v${VERSION}  ·  what can this repo make your AI agent do?`));
  console.log(C.dim(`  ${r.target}  ·  ${r.stats.files} files read in ${ms}ms  ·  nothing was executed`));
  console.log(line);

  // grade block
  const g = GRADEC[r.grade];
  console.log(`  ${g(C.inv(`  ${r.grade}  `))}  ${C.bold(`${r.score}/100`)}   ${r.verdict}`);
  const counts = SEVERITIES.filter(s => r.counts[s]).map(s => SEVC[s](`${r.counts[s]} ${s}`)).join(C.dim('  ·  '));
  console.log(`         ${counts || C.green('no findings')}${r.stats.hidden ? C.mag(`   ·  ${r.stats.hidden} hidden message${r.stats.hidden > 1 ? 's' : ''} decoded`) : ''}`);
  console.log(line);

  // timeline
  console.log(C.dim('  WHEN IT FIRES'));
  const cells = r.phases.map(p => {
    const col = p.worst ? SEVC[p.worst] : C.dim;
    return col(`${p.count ? '●' : '○'} ${p.short}${p.count ? ` ${p.count}` : ''}`);
  });
  console.log('  ' + cells.join(C.dim(' ─ ')));
  console.log(line);

  if (!r.findings.length) { console.log(C.green('  ✓ Nothing found that runs code or steers an agent on its own.')); console.log(); return; }

  const verbose = flag('--verbose');
  for (const ph of PHASES) {
    const fs = r.findings.filter(f => f.phase === ph.id);
    if (!fs.length) continue;
    console.log(`  ${C.bold(`${ph.n}. ${ph.label.toUpperCase()}`)}  ${C.dim(ph.desc)}`);
    for (const f of fs) {
      const tag = SEVC[f.severity](f.severity.toUpperCase().padEnd(8));
      console.log(`   ${tag} ${C.bold(f.title)}`);
      console.log(`            ${C.cyan(`${f.file}${f.line > 1 ? ':' + f.line : ''}`)}  ${C.dim(f.rule)}${f.tags?.length ? '  ' + C.mag(f.tags.filter(t => t !== 'network' || f.tags.length === 1).join(' ')) : ''}`);
      if (f.decoded) console.log(`            ${C.mag('◉ decoded:')} ${C.mag(trunc(f.decoded, W - 24))}`);
      else if (f.evidence && f.evidence !== f.file) console.log(`            ${C.dim('›')} ${trunc(f.evidence, W - 16)}`);
      if (verbose || f.severity === 'critical') {
        console.log(`            ${C.dim('why:')} ${C.dim(wrap(f.why, W - 18, 17))}`);
        console.log(`            ${C.green('fix:')} ${wrap(f.fix, W - 18, 17)}`);
      }
    }
    console.log();
  }
  if (r.surfaces.length) console.log(C.dim('  Agents this repo configures: ') + r.surfaces.map(s => `${s.name}${s.findings ? C.red(` (${s.findings})`) : ''}`).join(C.dim(', ')));
  console.log(C.dim(`  Run with --verbose for every explanation, --sarif for GitHub code scanning, --badge for your README.`));
  console.log();
}
function trunc(s, n) { s = String(s).replace(/\s+/g, ' '); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
function wrap(s, w, indent) {
  const words = String(s).split(' '); const lines = []; let cur = '';
  for (const wd of words) { if ((cur + ' ' + wd).trim().length > w) { lines.push(cur.trim()); cur = wd; } else cur += ' ' + wd; }
  if (cur.trim()) lines.push(cur.trim());
  return lines.join('\n' + ' '.repeat(indent + 4));
}
