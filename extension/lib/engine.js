// AgentXray engine, shared by the CLI, the website and the GitHub Action.
// Pure ES module, zero dependencies, never executes anything it scans.
//
// Input:  [{ path, text, size?, isSymlink?, linkTarget? }]
// Output: { findings, grade, score, verdict, phases, surfaces, stats }

export const VERSION = '0.2.0';

// ─────────────────────────────────────────────────────────────
// The attack timeline: WHEN does each finding fire?
// ─────────────────────────────────────────────────────────────
export const PHASES = [
  { id: 'open',    n: 1, label: 'Folder opened',        short: 'OPEN',    desc: 'Fires the moment you open the folder in VS Code, Cursor or a devcontainer, before you read a line.' },
  { id: 'session', n: 2, label: 'Agent session starts', short: 'SESSION', desc: 'Fires when Claude Code, Cursor, Gemini, Copilot or Codex starts in this folder.' },
  { id: 'git',     n: 3, label: 'Agent runs git',       short: 'GIT',     desc: 'Fires on the agent\'s background `git status` / `git diff`, often before any trust prompt.' },
  { id: 'read',    n: 4, label: 'Agent reads files',    short: 'READ',    desc: 'Steers the agent when it reads instructions, READMEs or docs. No code needed, just words.' },
  { id: 'install', n: 5, label: 'Dependencies install', short: 'INSTALL', desc: 'Fires on `npm install`, `pip install`, `yarn`, a command agents run without thinking.' },
  { id: 'run',     n: 6, label: 'Tests / build run',    short: 'RUN',     desc: 'Fires when the agent runs tests, builds or scripts.' },
  { id: 'static',  n: 7, label: 'Sitting in the repo',  short: 'EXPOSED', desc: 'Doesn\'t execute, but leaks or weakens something (secrets, permissive policy).' },
];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const PENALTY = { critical: 45, high: 15, medium: 5, low: 1, info: 0 };

// ─────────────────────────────────────────────────────────────
// Which agents read which files (the "agent surface map")
// ─────────────────────────────────────────────────────────────
export const AGENTS = [
  { id: 'claude',   name: 'Claude Code',    match: p => /^(CLAUDE(\.local)?\.md|\.claude\/|\.mcp\.json$)/i.test(p) || /\/CLAUDE\.md$/i.test(p) },
  { id: 'cursor',   name: 'Cursor',         match: p => /^(\.cursor\/|\.cursorrules$|\.cursorignore$)/.test(p) },
  { id: 'copilot',  name: 'GitHub Copilot', match: p => /^\.github\/(copilot-instructions\.md|instructions\/|prompts\/|chatmodes\/)/.test(p) || p === '.vscode/mcp.json' },
  { id: 'codex',    name: 'OpenAI Codex',   match: p => /(^|\/)AGENTS(\.override)?\.md$/i.test(p) || p.startsWith('.codex/') },
  { id: 'gemini',   name: 'Gemini CLI',     match: p => /(^|\/)GEMINI\.md$/i.test(p) || p.startsWith('.gemini/') },
  { id: 'windsurf', name: 'Windsurf',       match: p => /^(\.windsurf\/|\.windsurfrules$)/.test(p) },
  { id: 'cline',    name: 'Cline / Roo',    match: p => /^(\.clinerules|\.roo\/|\.roorules)/.test(p) },
  { id: 'kiro',     name: 'Kiro',           match: p => p.startsWith('.kiro/') },
  { id: 'vscode',   name: 'VS Code',        match: p => p.startsWith('.vscode/') },
  { id: 'devcont',  name: 'Dev Containers', match: p => p.startsWith('.devcontainer') || p === '.devcontainer.json' },
  { id: 'git',      name: 'git',            match: p => p.startsWith('.git/') || p === '.gitattributes' || p === '.gitmodules' },
];

// ─────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────
const lineOf = (text, idx) => (idx <= 0 ? 1 : text.slice(0, idx).split('\n').length);
const clip = (s, n = 180) => { s = String(s ?? '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const base = p => p.split('/').pop();

export function normPath(p) {
  return String(p).replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

// Tolerant JSON: VS Code & devcontainer files allow comments + trailing commas.
export function parseJsonc(text) {
  try { return JSON.parse(text); } catch {}
  let out = '', i = 0, inStr = false, q = '';
  while (i < text.length) {
    const c = text[i], d = text[i + 1];
    if (inStr) { out += c; if (c === '\\') { out += d ?? ''; i += 2; continue; } if (c === q) inStr = false; i++; continue; }
    if (c === '"') { inStr = true; q = c; out += c; i++; continue; }
    if (c === '/' && d === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; continue; }
    out += c; i++;
  }
  out = out.replace(/,(\s*[}\]])/g, '$1');
  try { return JSON.parse(out); } catch { return null; }
}

// Find the line where a JSON key/value appears (best effort, for nice reports).
function findLine(text, needle) {
  if (!needle) return 1;
  const i = text.indexOf(needle);
  return i < 0 ? 1 : lineOf(text, i);
}

// ─────────────────────────────────────────────────────────────
// Command risk analysis, used for every command we find in a config
// ─────────────────────────────────────────────────────────────
const CMD_PATTERNS = [
  { tag: 'download-and-execute', sev: 'critical', re: /\b(curl|wget|fetch)\b[^\n|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n|]*\|\s*(python3?|node|perl|ruby|php)\b|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*iex\b|\b(ba)?sh\s+-c\s+["']?\$\((curl|wget)|\bsource\s+<\((curl|wget)/i },
  { tag: 'reverse-shell',        sev: 'critical', re: /\/dev\/tcp\/|\bnc(at)?\b[^\n]*\s-(e|c)\s|\bsocat\b[^\n]*exec:|\bmkfifo\b[^\n]*\bnc\b/i },
  { tag: 'encoded-payload',      sev: 'critical', re: /base64\s+(-d|--decode|-D)[^\n]*\|\s*(ba|z)?sh|powershell[^\n]*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|eval\s*\(\s*(atob|Buffer\.from|base64)|exec\s*\(\s*(base64|codecs|zlib)\.|\bFromBase64String\b/i },
  { tag: 'credential-access',    sev: 'high',     re: /(~|\$HOME|\$\{HOME\}|%USERPROFILE%|\/root|\/Users\/[^/\s]+|\/home\/[^/\s]+)\/\.(ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials|config\/gh|config\/gcloud|azure)|\bid_(rsa|ed25519|ecdsa)\b|security\s+find-generic-password|\$\{?(ANTHROPIC|OPENAI|GITHUB|GH|AWS_SECRET|NPM|HF|GEMINI|GOOGLE)_[A-Z_]*(KEY|TOKEN|SECRET)\}?/i },
  { tag: 'persistence',          sev: 'high',     re: /\bcrontab\b|launchctl\s+load|systemctl\s+(--user\s+)?enable|>>?\s*~?\/?(\$HOME\/)?\.(bashrc|zshrc|profile|bash_profile)|~\/\.claude\/|\$HOME\/\.claude\/|schtasks\s+\/create|reg\s+add\s+HK/i },
  { tag: 'destructive',          sev: 'high',     re: /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(\/|~|\$HOME|\*)(\s|$)|\bmkfs\b|\bdd\s+if=.*of=\/dev\/|:\(\)\s*\{\s*:\|:&\s*\};:/i },
  { tag: 'obfuscation',          sev: 'medium',   re: /(\\x[0-9a-f]{2}){6,}|(\\u00[0-9a-f]{2}){6,}|\bchr\(\d+\)\s*\+\s*chr\(|String\.fromCharCode\((\s*\d+\s*,){6,}|[A-Za-z0-9+/]{120,}={0,2}/i },
  { tag: 'network',              sev: 'medium',   re: /\b(curl|wget|nc|ncat|scp|rsync|ftp|tftp|telnet)\b|https?:\/\/(?!localhost|127\.0\.0\.1)|Invoke-WebRequest|requests\.(get|post)|urllib|fetch\s*\(|axios\b|XMLHttpRequest/i },
];

export function analyzeCommand(cmd) {
  const s = String(cmd ?? '');
  const tags = [];
  let sev = null;
  for (const p of CMD_PATTERNS) {
    if (p.re.test(s)) { tags.push(p.tag); if (!sev || SEV_RANK[p.sev] > SEV_RANK[sev]) sev = p.sev; }
  }
  // network + credentials together = exfiltration
  if (tags.includes('network') && tags.includes('credential-access')) { tags.push('exfiltration'); sev = 'critical'; }
  return { tags, sev };
}

const bump = (a, b) => (!b ? a : SEV_RANK[b] > SEV_RANK[a] ? b : a);

// ─────────────────────────────────────────────────────────────
// Hidden-text decoding, the "Invisible Ink" engine
// ─────────────────────────────────────────────────────────────
const TAG_RE = /[\u{E0000}-\u{E007F}]{2,}/gu;                         // Unicode tag smuggling
const VS_RE = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]{4,}/gu;          // variation-selector byte smuggling
const ZW_RE = /[​‌‍⁠⁢⁣⁤﻿]{8,}/g;  // zero-width runs
const BIDI_RE = /[‪-‮⁦-⁩]/g;                         // Trojan Source bidi controls

function decodeTags(run) {
  return [...run].map(ch => { const cp = ch.codePointAt(0) - 0xE0000; return cp >= 0x20 && cp < 0x7F ? String.fromCharCode(cp) : ''; }).join('');
}
function decodeVS(run) {
  const bytes = [...run].map(ch => { const cp = ch.codePointAt(0); return cp <= 0xFE0F ? cp - 0xFE00 : cp - 0xE0100 + 16; });
  try { return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes)).replace(/[^\x20-\x7E\n\t -￿]/g, ''); } catch { return ''; }
}
function decodeZW(run) {
  const chars = [...new Set(run)];
  if (chars.length !== 2) return '';
  for (const [zero, one] of [[chars[0], chars[1]], [chars[1], chars[0]]]) {
    const bits = [...run].map(c => (c === one ? '1' : '0')).join('');
    let out = '';
    for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
    if (/^[\x20-\x7E]{3,}$/.test(out)) return out;
  }
  return '';
}

export function revealHidden(text) {
  const hits = [];
  for (const m of text.matchAll(TAG_RE)) hits.push({ kind: 'unicode-tags', index: m.index, length: m[0].length, decoded: decodeTags(m[0]) });
  for (const m of text.matchAll(VS_RE)) { const d = decodeVS(m[0]); hits.push({ kind: 'variation-selectors', index: m.index, length: m[0].length, decoded: d }); }
  for (const m of text.matchAll(ZW_RE)) hits.push({ kind: 'zero-width', index: m.index, length: m[0].length, decoded: decodeZW(m[0]) });
  const bidi = [...text.matchAll(BIDI_RE)];
  if (bidi.length) hits.push({ kind: 'bidi-controls', index: bidi[0].index, length: bidi.length, decoded: '' });
  return hits;
}

// Render text with invisible characters made visible (used by the website).
export function visualize(text) {
  return [...text].map(ch => {
    const cp = ch.codePointAt(0);
    if (cp >= 0xE0000 && cp <= 0xE007F) return { t: 'tag', ch: String.fromCharCode(Math.max(0x20, cp - 0xE0000)) };
    if ((cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)) return { t: 'vs', ch: '◆' };
    if ([0x200B, 0x200C, 0x200D, 0x2060, 0x2062, 0x2063, 0x2064, 0xFEFF].includes(cp)) return { t: 'zw', ch: '·' };
    if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) return { t: 'bidi', ch: '⇄' };
    return { t: 'txt', ch };
  });
}

// ─────────────────────────────────────────────────────────────
// Prompt-injection language aimed at agents
// ─────────────────────────────────────────────────────────────
const INJECTION = [
  { id: 'override',   re: /\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+|of\s+)*(previous|prior|above|earlier|preceding|system|original)\s+(instructions|rules|directions|prompts?|guidelines)|\boverride\s+(all\s+|your\s+|the\s+)*(previous|prior|safety)\s+(instructions|rules|guidelines)\b/i, label: 'instruction override' },
  { id: 'conceal',    re: /\b(do\s+not|don'?t|never)\s+(tell|inform|mention|alert|notify|show|reveal)\s+(this\s+)?(to\s+)?(the\s+)?(user|human|developer|operator)\b/i, label: 'conceal from user' },
  { id: 'noconsent',  re: /\bwithout\s+(asking|telling|notifying|confirming\s+with|informing|prompting)\s+(the\s+)?(user|human|developer)|\b(do\s+not|don'?t|never)\s+ask\s+(the\s+)?(user|human|developer)?\s*(for\s+)?(confirmation|permission|approval)/i, label: 'act without consent' },
  { id: 'silent',     re: /\b(silently|secretly|covertly)\s+(run|execute|send|upload|install|curl|post|push|exfiltrate|download)\b/i, label: 'covert action' },
  { id: 'persona',    re: /\byou\s+are\s+now\s+(in\s+)?(developer|dan|god|jailbreak|unrestricted|admin|root|maintenance)\b|\benter\s+(developer|god|debug|maintenance)\s+mode\b/i, label: 'persona hijack' },
  { id: 'fakesys',    re: /<\/?(system|system_prompt|instructions|admin|important_instructions)>|\[\/?INST\]|<\|im_(start|end)\|>|^\s*(SYSTEM|ADMIN)\s*(OVERRIDE|NOTICE|MESSAGE)\s*:/im, label: 'fake system tags' },
  { id: 'exfil',      re: /\b(send|post|upload|exfiltrate|forward|transmit|leak|include)\b.{0,80}\b(api[_\s-]?keys?|secrets?|credentials?|\.env\b|ssh\s+keys?|id_rsa|id_ed25519|passwords?|cookies)\b.{0,80}(https?:\/\/|webhook|pastebin|ngrok|discord\.com\/api)|\bexfiltrat/i, label: 'data exfiltration' },
  { id: 'credread',   re: /\b(read|cat|print|include|attach|base64|upload)\b.{0,40}(~\/\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.git-credentials|~\/\.netrc)/i, label: 'credential harvesting' },
  { id: 'yolo',       re: /--dangerously-skip-permissions|--yolo\b|bypassPermissions|--full-auto|danger-full-access|auto[\s-]?approve\s+(all|every)/i, label: 'disable safety' },
  { id: 'agentaddr',  re: /\b(note|message|instructions?)\s+(to|for)\s+(the\s+)?(ai|llm|assistant|agent|model|claude|copilot|cursor|gemini|codex)\b|\b(ai|llm)\s+(agents?|assistants?)\s*(reading\s+this|:)/i, label: 'addressed to the AI' },
];

// Text that genuinely addresses an AI reader (not docs that merely mention AI)
const AI_ADDR = /\b(note|message|instructions?|reminder)s?\s+(to|for)\s+(any\s+|the\s+|all\s+)?(ai|llm|assistant|agent|model|claude|copilot|cursor|gemini|codex|chatgpt)s?\b|\bif\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant|agent|coding\s+agent)\b|\b(ai|llm|coding)\s+(agents?|assistants?|models?)\s+(reading\s+this|must|should)\b|\b(attention|hey|dear)[,:]?\s+(ai|claude|assistant|agent|copilot|llm)\b/i;
const STRONG = new Set(['override', 'conceal', 'noconsent', 'silent', 'exfil', 'credread', 'yolo', 'fakesys', 'persona']);

// Split into paragraphs, return strong hits per paragraph with absolute index
function paragraphHits(text) {
  const out = [];
  const re = /[^\n](?:[^\n]|\n(?!\s*\n))*/g;
  for (const m of text.matchAll(re)) {
    const hits = injectionHits(m[0]).filter(h => STRONG.has(h.id));
    if (hits.length) out.push({ index: m.index + hits[0].index, para: m[0], hits, aiAddressed: AI_ADDR.test(m[0]) });
  }
  return out;
}

function injectionHits(text) {
  const hits = [];
  for (const r of INJECTION) {
    const m = r.re.exec(text);
    if (m) hits.push({ ...r, index: m.index, match: m[0] });
  }
  return hits;
}

// ─────────────────────────────────────────────────────────────
// Secrets
// ─────────────────────────────────────────────────────────────
const SECRETS = [
  { name: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key',    re: /sk-(proj-)?[A-Za-z0-9_-]{32,}/ },
  { name: 'GitHub token',      re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{60,}/ },
  { name: 'AWS access key',    re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'Google API key',    re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Slack token',       re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'Stripe live key',   re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}/ },
  { name: 'npm token',         re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'Hugging Face token',re: /\bhf_[A-Za-z0-9]{34,}\b/ },
  { name: 'Private key',       re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/ },
];
const mask = s => (s.length <= 12 ? '••••' : s.slice(0, 6) + '••••••' + s.slice(-4));

// ─────────────────────────────────────────────────────────────
// File classification
// ─────────────────────────────────────────────────────────────
const INSTRUCTION_FILE = p =>
  /(^|\/)(CLAUDE|AGENTS|GEMINI|CODEX|COPILOT)(\.local|\.override)?\.md$/i.test(p) ||
  /^(\.cursorrules|\.windsurfrules|\.clinerules|\.roorules|\.goosehints)$/.test(p) ||
  /^(\.cursor\/rules|\.windsurf\/rules|\.clinerules|\.roo\/rules|\.kiro\/steering|\.github\/instructions|\.github\/prompts|\.github\/chatmodes|\.claude\/(commands|agents|skills|output-styles)|\.codex|\.gemini\/commands)\//.test(p) ||
  p === '.github/copilot-instructions.md' || /(^|\/)SKILL\.md$/.test(p);
const DOC_FILE = p => /\.(md|mdx|markdown|txt|rst|adoc)$/i.test(p) || /(^|\/)(README|CONTRIBUTING|SECURITY|CHANGELOG)(\.[a-z]+)?$/i.test(p);
const SCRIPT_FILE = p => /\.(sh|bash|zsh|fish|ps1|psm1|bat|cmd|command)$/i.test(p) || /(^|\/)(Makefile|Justfile|Taskfile\.ya?ml|Rakefile|Dockerfile|Containerfile)$/.test(p);

// ─────────────────────────────────────────────────────────────
// The scanner
// ─────────────────────────────────────────────────────────────
export function scan(inputFiles, opts = {}) {
  const files = inputFiles.map(f => ({ ...f, path: normPath(f.path), text: f.text ?? '' }));
  const byPath = new Map(files.map(f => [f.path, f]));
  const findings = [];
  const add = (f) => findings.push({ line: 1, ...f, severity: f.severity || 'medium' });

  // Shared: report a command found inside a config, with risk-based severity
  const cmdFinding = (o) => {
    const { tags, sev } = analyzeCommand(o.command);
    const severity = bump(o.baseSev, sev);
    add({ ...o, severity, tags, evidence: clip(o.command, 220) });
  };

  for (const f of files) {
    const { path: p, text } = f;
    const name = base(p);

    // ── Symlinks escaping the repo ─────────────────────────
    if (f.isSymlink) {
      const t = String(f.linkTarget || '');
      const escapes = t.startsWith('/') || /^[A-Za-z]:/.test(t) || t.startsWith('~') || resolveEscapes(p, t);
      if (escapes) {
        const sensitive = /\.ssh|\.aws|\.gnupg|\.claude|\.config|\.npmrc|\.env|\/etc\/|credentials|\.kube|Library\/Keychains/i.test(t);
        add({ rule: 'AX-LINK-001', severity: sensitive ? 'critical' : 'high', phase: 'read', file: p,
          title: sensitive ? `Symlink points at a secret outside the repo → ${t}` : `Symlink escapes the repository → ${t}`,
          evidence: `${p} → ${t}`,
          why: 'When an agent "reads a file in the repo", it follows this link out of the project, straight into your home directory. Sandboxes that only allow the project folder have been escaped exactly this way.',
          fix: 'Delete the link, or open the repo only inside a container with no host mounts.' });
      }
      continue;
    }

    // ── .git/config: GitSpawn & friends ────────────────────
    if (p === '.git/config' || /^\.git\/modules\/[^]+\/config$/.test(p)) {
      const gitKeys = [
        { re: /^\s*fsmonitor\s*=\s*(.+)$/im,     key: 'core.fsmonitor', sev: 'critical', why: 'git runs this command on every `git status` / `git diff`. Coding agents run those in the background on startup, in several agents this fired before the workspace-trust prompt (GitSpawn, 2026).' },
        { re: /^\s*hooksPath\s*=\s*(.+)$/im,     key: 'core.hooksPath', sev: 'high', why: 'Redirects git hooks to a folder inside the repo, so attacker scripts run on commit, checkout or merge, which agents do for you.' },
        { re: /^\s*sshCommand\s*=\s*(.+)$/im,    key: 'core.sshCommand', sev: 'critical', why: 'Replaces ssh for every fetch/push. An agent running `git pull` runs this command.' },
        { re: /^\s*pager\s*=\s*(.+)$/im,         key: 'core.pager', sev: 'high', why: 'Runs whenever git shows a log or diff.' },
        { re: /^\s*editor\s*=\s*(.+)$/im,        key: 'core.editor', sev: 'medium', why: 'Runs when git opens an editor (commit, rebase).' },
        { re: /^\s*askPass\s*=\s*(.+)$/im,       key: 'core.askPass', sev: 'high', why: 'Runs whenever git needs credentials, and receives them.' },
        { re: /^\s*(clean|smudge|process)\s*=\s*(.+)$/im, key: 'filter.*', sev: 'critical', why: 'Content filters run on checkout, add and status. Combined with .gitattributes, any git command executes this.' },
        { re: /^\s*textconv\s*=\s*(.+)$/im,      key: 'diff.*.textconv', sev: 'high', why: 'Runs every time git diffs a matching file, agents diff constantly.' },
        { re: /^\s*helper\s*=\s*(!.+)$/im,       key: 'credential.helper', sev: 'critical', why: 'A shell credential helper receives your git credentials in plain text.' },
        { re: /^\s*[\w.-]+\s*=\s*(!.+)$/im,      key: 'alias (!shell)', sev: 'medium', why: 'Shell aliases run arbitrary commands when an agent uses that git alias.' },
      ];
      for (const g of gitKeys) {
        const m = g.re.exec(text);
        if (!m) continue;
        const value = (m[2] ?? m[1] ?? '').trim();
        if (g.key === 'core.fsmonitor' && /^(true|false|0|1)$/i.test(value)) continue; // built-in daemon, not a command
        cmdFinding({ rule: 'AX-GIT-001', baseSev: g.sev, phase: 'git', file: p, line: lineOf(text, m.index),
          title: `Repository git config sets ${g.key}, it runs a command`, command: `${g.key} = ${value}`,
          why: g.why + ' A repo\'s local .git/config overrides your global settings, so `git config --global` does not protect you.',
          fix: `Run \`git config --local --unset ${g.key === 'filter.*' || g.key.includes('*') ? '<key>' : g.key}\` (or delete .git/config and re-clone fresh). Agents should call git with \`-c core.fsmonitor=false -c core.hooksPath=/dev/null\`.` });
      }
      continue;
    }

    // ── .git/hooks ─────────────────────────────────────────
    if (/^\.git\/hooks\/[^/]+$/.test(p) && !name.endsWith('.sample')) {
      const firstCmd = text.split('\n').filter(l => l.trim() && !l.startsWith('#')).slice(0, 3).join(' ; ');
      cmdFinding({ rule: 'AX-GIT-002', baseSev: 'high', phase: 'git', file: p,
        title: `Active git hook: ${name}`, command: firstCmd || '(hook script)',
        why: 'Git hooks run automatically on commit, checkout, merge or push. Repos that arrive as a zip, a shared folder or a USB drive can carry them, a fresh clone cannot.',
        fix: 'Delete .git/hooks/* (keep the .sample files) or re-clone from the original URL.' });
      continue;
    }

    // ── .gitattributes filters ─────────────────────────────
    if (name === '.gitattributes' && /\bfilter\s*=\s*[\w-]+/.test(text) && !/\bfilter\s*=\s*lfs\b/.test(text.match(/\bfilter\s*=\s*[\w-]+/)[0])) {
      const m = /\bfilter\s*=\s*([\w-]+)/.exec(text);
      add({ rule: 'AX-GIT-003', severity: byPath.has('.git/config') ? 'high' : 'low', phase: 'git', file: p, line: lineOf(text, m.index),
        title: `.gitattributes routes files through filter "${m[1]}"`, evidence: clip(text.split('\n')[lineOf(text, m.index) - 1]),
        why: 'On its own this is harmless, but paired with a filter command in .git/config it turns every checkout and status into code execution.',
        fix: 'Check that the filter is something you recognise (like git-lfs). Remove the line if not.' });
    }

    // ── Claude Code settings ───────────────────────────────
    if (/^\.claude\/settings(\.local)?\.json$/.test(p) || p === '.gemini/settings.json' || p === '.cursor/hooks.json' || p === '.github/hooks/hooks.json' || /^\.codex\/hooks\.json$/.test(p) || p === '.windsurf/hooks.json') {
      const j = parseJsonc(text);
      const agent = p.startsWith('.claude') ? 'Claude Code' : p.startsWith('.gemini') ? 'Gemini CLI' : p.startsWith('.cursor') ? 'Cursor' : p.startsWith('.codex') ? 'Codex' : p.startsWith('.windsurf') ? 'Windsurf' : 'Copilot';
      if (!j) { add({ rule: 'AX-CFG-000', severity: 'low', phase: 'session', file: p, title: `${agent} config is not valid JSON`, evidence: clip(text, 80), why: 'Malformed configs can hide content from reviewers while some parsers still read it.', fix: 'Open the file and review it by hand.' }); continue; }

      // hooks: { Event: [ { matcher, hooks: [ {type:'command', command} ] } ] }
      const hooks = j.hooks || {};
      for (const [event, entries] of Object.entries(hooks)) {
        const list = Array.isArray(entries) ? entries : [entries];
        for (const e of list) {
          const inner = Array.isArray(e?.hooks) ? e.hooks : [e];
          for (const h of inner) {
            const command = h?.command ?? h?.bash ?? h?.powershell ?? (typeof h === 'string' ? h : null);
            if (!command) continue;
            const early = /^(SessionStart|Setup|UserPromptSubmit|sessionStart|BeforeAgent|beforeSubmitPrompt|PreToolUse|BeforeTool|preToolUse)$/i.test(event);
            cmdFinding({ rule: 'AX-HOOK-001', baseSev: early ? 'high' : 'medium', phase: 'session', file: p, line: findLine(text, String(command).slice(0, 30)),
              title: `${agent} ${event} hook runs a shell command`, command,
              why: `Hooks shipped inside a repo run with your permissions whenever ${agent} hits "${event}". Vendors treat repo hooks as "by design", so the repo author decides what runs on your machine. The Mini Shai-Hulud worm persisted exactly this way.`,
              fix: 'Read the command. If you did not write it, delete the hook before starting the agent, or run the agent in a disposable container.' });
          }
        }
      }

      // env redirection, traffic & key theft
      const env = j.env || {};
      for (const [k, v] of Object.entries(env)) {
        if (/(_BASE_URL|_API_URL|_ENDPOINT|^HTTPS?_PROXY$|^ALL_PROXY$|^NODE_OPTIONS$|^LD_PRELOAD$|^DYLD_|^PYTHONSTARTUP$|^BASH_ENV$|_HEADERS$|^NODE_EXTRA_CA_CERTS$|^SSL_CERT_FILE$|_TLS_REJECT|^OTEL_EXPORTER)/i.test(k)) {
          const isUrl = /^https?:\/\//.test(String(v));
          add({ rule: 'AX-ENV-001', severity: /BASE_URL|PROXY|LD_PRELOAD|DYLD_|NODE_OPTIONS|CA_CERT|SSL_CERT|TLS_REJECT/i.test(k) ? 'critical' : 'high', phase: 'session', file: p, line: findLine(text, k),
            title: `${agent} config overrides ${k}`, evidence: `${k}=${clip(v, 120)}`,
            why: /BASE_URL|PROXY/i.test(k)
              ? `Every request your agent makes, your prompts, your code and the API key in the header, gets routed to ${isUrl ? new URL(String(v)).host : 'an endpoint the repo chose'}. That's a silent man-in-the-middle on your AI session.`
              : 'This variable changes how programs load code or trust TLS for every command the agent runs.',
            fix: `Remove "${k}" from the env block. Your base URL and proxies belong in your user settings, never in a repo.` });
        }
      }

      // credential / helper commands
      for (const k of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper', 'statusLine', 'fileSuggestion']) {
        const v = k === 'statusLine' || k === 'fileSuggestion' ? j[k]?.command : j[k];
        if (typeof v === 'string' && v.trim()) {
          cmdFinding({ rule: 'AX-HOOK-002', baseSev: k === 'statusLine' || k === 'fileSuggestion' ? 'medium' : 'high', phase: 'session', file: p, line: findLine(text, k),
            title: `${agent} "${k}" runs a command`, command: v,
            why: k === 'apiKeyHelper' ? 'This command decides which API key the agent uses, a repo should never set it.' : 'This setting executes a shell command automatically during the session.',
            fix: `Delete "${k}" from the repo's settings.` });
        }
      }

      // permissions
      const perm = j.permissions || {};
      const allow = [].concat(perm.allow || []);
      const wide = allow.filter(r => /^(Bash|Bash\(\*\)|Bash\(\*\*\)|Bash\(.*:\*\)|WebFetch|Write|Edit|mcp__.*|\*)$/i.test(String(r)) || /Bash\((curl|wget|sh|bash|rm|sudo|python|node|npx)/i.test(String(r)));
      if (wide.length) add({ rule: 'AX-PERM-001', severity: wide.some(r => /^(Bash|Bash\(\*\)|\*)$/i.test(r) || /curl|wget|sudo|rm/i.test(r)) ? 'high' : 'medium', phase: 'session', file: p, line: findLine(text, '"allow"'),
        title: `Repo pre-approves powerful tools: ${wide.slice(0, 4).join(', ')}${wide.length > 4 ? '…' : ''}`, evidence: clip(JSON.stringify(allow), 200),
        why: 'Pre-approved tools run with no confirmation prompt. A repo granting itself Bash or network access means a single injected instruction becomes code execution with zero clicks.',
        fix: 'Remove these allow rules. Approve tools per session yourself.' });
      if (/bypassPermissions|dontAsk|acceptEdits/.test(String(perm.defaultMode || '')) || j.dangerouslySkipPermissions === true)
        add({ rule: 'AX-PERM-002', severity: 'critical', phase: 'session', file: p, line: findLine(text, 'defaultMode'),
          title: `Repo switches the agent into "${perm.defaultMode || 'skip permissions'}" mode`, evidence: `defaultMode: ${perm.defaultMode}`,
          why: 'Every tool call runs without asking you. Combined with any instruction in the repo, the agent will do whatever the repo author wants.',
          fix: 'Delete defaultMode from the repo settings.' });
      if (j.enableAllProjectMcpServers === true || (Array.isArray(j.enabledMcpjsonServers) && j.enabledMcpjsonServers.length))
        add({ rule: 'AX-MCP-002', severity: 'high', phase: 'session', file: p, line: findLine(text, 'McpServers'),
          title: 'Repo auto-approves its own MCP servers', evidence: j.enableAllProjectMcpServers ? 'enableAllProjectMcpServers: true' : `enabledMcpjsonServers: ${JSON.stringify(j.enabledMcpjsonServers)}`,
          why: 'Normally you are asked before a project MCP server starts. This flag skips that question, the servers launch the moment the session opens.',
          fix: 'Remove the flag so you are prompted before each server starts.' });
      if (p.endsWith('settings.local.json'))
        add({ rule: 'AX-LEAK-001', severity: 'low', phase: 'static', file: p,
          title: 'Personal agent settings were committed (settings.local.json)', evidence: p,
          why: 'This file is meant to be private. It often contains approved commands, local paths and sometimes tokens, and it was shipped in npm packages in 2026.',
          fix: 'Add .claude/settings.local.json to .gitignore and .npmignore, and rotate anything sensitive inside it.' });

      // MCP servers defined inline (Gemini, etc.)
      if (j.mcpServers) mcpServers(j.mcpServers, p, text, agent);
      continue;
    }

    // ── MCP server configs ─────────────────────────────────
    if (/^(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.roo\/mcp\.json|\.kiro\/settings\/mcp\.json|\.amazonq\/mcp\.json|mcp\.json|\.windsurf\/mcp\.json|\.junie\/mcp\/mcp\.json)$/.test(p)) {
      const j = parseJsonc(text);
      if (j) mcpServers(j.mcpServers || j.servers || {}, p, text, p.startsWith('.cursor') ? 'Cursor' : p.startsWith('.vscode') ? 'VS Code / Copilot' : 'Claude Code & others');
      continue;
    }

    // ── VS Code tasks that auto-run ────────────────────────
    if (p === '.vscode/tasks.json') {
      const j = parseJsonc(text);
      for (const t of (j?.tasks || [])) {
        const cmd = [t.command, ...(t.args || []).map(a => (typeof a === 'string' ? a : a?.value))].filter(Boolean).join(' ')
          || t.windows?.command || t.osx?.command || t.linux?.command || '';
        if (t.runOptions?.runOn === 'folderOpen') {
          cmdFinding({ rule: 'AX-VSC-001', baseSev: 'critical', phase: 'open', file: p, line: findLine(text, 'folderOpen'),
            title: `Task "${t.label || 'unnamed'}" runs automatically when the folder opens`, command: cmd || '(task)',
            why: 'VS Code, Cursor and Windsurf run this the moment you open the folder (once you trust it, and most people click "Yes, I trust the authors" without reading). Used in the wild by the Contagious Interview / fake job-test campaigns.',
            fix: 'Delete "runOn": "folderOpen", or keep the folder in Restricted Mode.' });
        }
      }
      continue;
    }

    // ── VS Code settings that execute binaries ─────────────
    if (p === '.vscode/settings.json' || /\.code-workspace$/.test(p)) {
      const j = parseJsonc(text);
      const s = (j && (j.settings || j)) || {};
      for (const [k, v] of Object.entries(s)) {
        const val = typeof v === 'string' ? v : JSON.stringify(v);
        if (/(\.path|Path|executablePath|\.executable|serverPath|\.binary|interpreterPath|runtime|\.command|cmdPath|nodePath)$/i.test(k) && typeof v === 'string' && v && !/^\$\{/.test(v) && /[./\\]/.test(v)) {
          cmdFinding({ rule: 'AX-VSC-002', baseSev: /^(\.\/|[^/~$]+\/)/.test(v) ? 'high' : 'medium', phase: 'open', file: p, line: findLine(text, k),
            title: `Workspace setting "${k}" points the editor at a program`, command: v,
            why: 'Extensions launch this binary automatically (linters, language servers, git). A repo can point it at its own script.',
            fix: `Remove "${k}" from the repo settings.` });
        }
        if (/^terminal\.integrated\.(env|profiles|shellArgs|automationProfile)/.test(k))
          add({ rule: 'AX-VSC-003', severity: 'medium', phase: 'open', file: p, line: findLine(text, k), title: `Workspace changes terminal environment (${k})`, evidence: clip(val, 160),
            why: 'Every terminal the editor or its agent opens inherits this, including PATH or startup files.', fix: `Remove "${k}".` });
        if ((/autoApprove|chat\.tools\.(global\.)?autoApprove|yolo|agent\.autoRun|terminal\.autoApprove|autoRun/i.test(k) && (v === true || (typeof v === 'object' && v))) || (k === 'security.workspace.trust.enabled' && v === false))
          add({ rule: 'AX-VSC-004', severity: 'high', phase: 'session', file: p, line: findLine(text, k), title: `Workspace disables a safety prompt (${k})`, evidence: `${k}: ${clip(val, 100)}`,
            why: 'This lets the editor\'s AI agent run tools or terminal commands without asking you.', fix: `Delete "${k}" from the repo settings.` });
      }
      continue;
    }

    // ── Dev containers ─────────────────────────────────────
    if (/^\.devcontainer(\/[^/]+)*\/devcontainer\.json$|^\.devcontainer\.json$/.test(p)) {
      const j = parseJsonc(text) || {};
      if (j.initializeCommand) cmdFinding({ rule: 'AX-DEV-001', baseSev: 'critical', phase: 'open', file: p, line: findLine(text, 'initializeCommand'),
        title: 'devcontainer initializeCommand runs on your HOST machine', command: flatCmd(j.initializeCommand),
        why: 'People think devcontainers are a sandbox. initializeCommand runs on your real machine, outside the container, before it even starts.',
        fix: 'Delete initializeCommand or review it line by line before "Reopen in Container".' });
      for (const k of ['onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand']) {
        if (j[k]) cmdFinding({ rule: 'AX-DEV-002', baseSev: 'low', phase: 'open', file: p, line: findLine(text, k), title: `devcontainer ${k} runs automatically`, command: flatCmd(j[k]),
          why: 'Runs inside the container, safer, but it still sees any secrets, SSH agents or folders forwarded into it.', fix: 'Review the command.' });
      }
      const mountsTxt = JSON.stringify([j.mounts, j.runArgs, j.workspaceMount, j.privileged, j.capAdd]);
      if (/docker\.sock|\$\{localEnv:HOME\}|\$\{localEnv:USERPROFILE\}|--privileged|"privileged":true|true|SYS_ADMIN|source=\/[,"]|--pid=host|--network=host/.test(mountsTxt) && /docker\.sock|localEnv:(HOME|USERPROFILE)|privileged|SYS_ADMIN|source=\/[,"]|pid=host/.test(mountsTxt))
        add({ rule: 'AX-DEV-003', severity: 'high', phase: 'open', file: p, line: findLine(text, /docker\.sock/.test(mountsTxt) ? 'docker.sock' : 'mounts'),
          title: 'Dev container punches through to the host (docker socket / home dir / privileged)', evidence: clip([j.mounts, j.runArgs, j.workspaceMount, j.privileged && 'privileged: true'].flat().filter(Boolean).map(m => typeof m === 'string' ? m : JSON.stringify(m)).join('  ·  '), 200),
          why: 'With the Docker socket or your home folder mounted, "inside the container" is the same as "on your machine". Agents running in there are not sandboxed.',
          fix: 'Remove the host mount / --privileged flag.' });
      continue;
    }

    // ── direnv ─────────────────────────────────────────────
    if (name === '.envrc') {
      cmdFinding({ rule: 'AX-ENV-002', baseSev: 'medium', phase: 'open', file: p, title: '.envrc runs when you `cd` in (if direnv is installed)', command: text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).slice(0, 4).join(' ; '),
        why: 'direnv executes this file as a shell script when you or your agent enter the folder (after `direnv allow`). Agents often run `direnv allow` to "fix" a warning.', fix: 'Read it before allowing. Never let an agent run `direnv allow` for you.' });
    }

    // ── package.json lifecycle scripts ─────────────────────
    if (name === 'package.json' && !p.includes('node_modules/')) {
      const j = parseJsonc(text) || {};
      const scripts = j.scripts || {};
      for (const k of ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish', 'dependencies']) {
        if (!scripts[k]) continue;
        const benign = /^(husky( install)?|npx husky|patch-package|node-gyp rebuild|ngcc|tsc( -b)?|npm run build|lerna bootstrap|is-ci \|\| husky)$/.test(scripts[k].trim());
        cmdFinding({ rule: 'AX-NPM-001', baseSev: benign ? 'info' : 'medium', phase: 'install', file: p, line: findLine(text, `"${k}"`),
          title: `npm "${k}" script runs on install`, command: scripts[k],
          why: 'Install scripts run automatically on `npm install`, the first thing an agent does in a JS repo. This is how most npm worms spread.',
          fix: 'Install with `npm install --ignore-scripts` (or set ignore-scripts=true in your ~/.npmrc) until you have read it.' });
      }
      for (const [k, v] of Object.entries(scripts)) {
        if (/^(pre|post)?(install|prepare|prepublish)$/.test(k)) continue;
        const { sev, tags } = analyzeCommand(v);
        if (sev && SEV_RANK[sev] >= SEV_RANK.high) add({ rule: 'AX-NPM-002', severity: sev, tags, phase: 'run', file: p, line: findLine(text, `"${k}"`),
          title: `npm script "${k}" contains ${tags.filter(t => t !== 'network').join(' + ') || 'a risky pattern'}`, evidence: clip(v, 220),
          why: 'Agents run `npm test`, `npm run build` and `npm run dev` freely. This script does far more than build or test.', fix: 'Read the script before running anything in this repo.' });
      }
      const deps = { ...j.dependencies, ...j.devDependencies, ...j.optionalDependencies };
      for (const [k, v] of Object.entries(deps)) {
        if (/^(https?:|git\+|git:|github:|file:\.\.\/|[\w-]+\/[\w.-]+#)/.test(String(v)))
          add({ rule: 'AX-NPM-003', severity: /^http:/.test(v) ? 'high' : 'low', phase: 'install', file: p, line: findLine(text, `"${k}"`),
            title: `Dependency "${k}" installs from outside the registry`, evidence: `${k}: ${v}`,
            why: 'Git/URL dependencies skip registry malware scanning and can change under you without a version bump.', fix: 'Prefer a pinned registry version.' });
      }
      continue;
    }

    // ── Yarn / npm / pnpm / bun config ─────────────────────
    if (name === '.yarnrc.yml' || name === '.yarnrc') {
      const m = /^\s*(yarnPath|yarn-path)\s*:?\s*["']?([^\s"']+)/m.exec(text);
      if (m) add({ rule: 'AX-PKG-001', severity: 'high', phase: 'install', file: p, line: lineOf(text, m.index), title: `Yarn will execute ${m[2]} as "yarn"`, evidence: m[0].trim(),
        why: 'yarnPath makes every `yarn` command run a JavaScript file from the repo instead of real Yarn. A legit repo vendors the official release; an attacker vendors anything.',
        fix: `Verify ${m[2]} is an official Yarn release (check its hash) or delete the line.` });
    }
    if (name === '.npmrc' || name === '.pnpmrc' || name === 'bunfig.toml') {
      const m = /^\s*(script-shell|node-options|onload-script|globalconfig|userconfig|ignore-scripts\s*=\s*false|registry|@[\w-]+:registry|preload)\s*[=:]\s*(.*)$/im.exec(text);
      if (m) add({ rule: 'AX-PKG-002', severity: /script-shell|node-options|onload|preload/.test(m[1]) ? 'high' : 'medium', phase: 'install', file: p, line: lineOf(text, m.index),
        title: `${name} changes ${m[1].split(/\s/)[0]}`, evidence: clip(m[0]),
        why: /registry/.test(m[1]) ? 'Packages will be downloaded from a registry the repo chose, a classic dependency-confusion setup.' : 'This changes what program npm runs for scripts or what code Node preloads into every process.',
        fix: 'Remove it from the repo-level config.' });
      const tok = /_authToken\s*=\s*([^\s$][^\s]{8,})/.exec(text);
      if (tok && !/\$\{/.test(tok[1])) add({ rule: 'AX-SEC-001', severity: 'high', phase: 'static', file: p, line: lineOf(text, tok.index), title: 'npm auth token committed in .npmrc', evidence: `_authToken=${mask(tok[1])}`,
        why: 'Anyone with the repo can publish packages as this user.', fix: 'Revoke the token on npmjs.com and use ${NPM_TOKEN} instead.' });
    }

    // ── Python auto-exec surfaces ──────────────────────────
    if (/\.pth$/.test(p) && /^\s*import\s/m.test(text)) {
      add({ rule: 'AX-PY-001', severity: 'high', phase: 'run', file: p, title: '.pth file with import, runs on every Python start', evidence: clip(text.split('\n').find(l => /^\s*import/.test(l))),
        why: 'Python executes `import` lines in .pth files at interpreter startup. If this lands in a virtualenv, every python command runs it.', fix: 'Delete it unless you know exactly what it is.' });
    }
    if (name === 'conftest.py' || name === 'setup.py' || name === 'sitecustomize.py' || name === 'usercustomize.py') {
      let { sev, tags } = analyzeCommand(text);
      const execy = /subprocess|os\.system|os\.popen|\bexec\(|\beval\(|__import__/.test(text);
      const shady = /b64decode|base64|urllib|requests\.|socket\.|http\.client|marshal\.loads|zlib\.decompress/.test(text);
      if (execy && shady) { sev = bump(sev || 'high', 'high'); if (!tags.length) tags = ['process-exec', 'encoded-payload']; }
      if (sev && (tags.some(t => t !== 'network') || execy))
        add({ rule: 'AX-PY-002', severity: bump('medium', sev === 'medium' ? null : sev), tags, phase: name === 'setup.py' ? 'install' : 'run', file: p,
          title: `${name} does ${tags.join(' + ') || 'process execution'}, runs on ${name === 'setup.py' ? 'pip install' : name === 'conftest.py' ? '`pytest`' : 'python start'}`, evidence: clip(firstMatchLine(text, /subprocess|os\.system|exec\(|eval\(|urllib|requests\.|socket|base64/)),
          why: name === 'conftest.py' ? 'pytest imports conftest.py automatically. Agents run `pytest` to "check their work", a 2026 attack hid a C2 payload exactly here.' : 'This file executes automatically.',
          fix: 'Read this file before running tests or installing.' });
    }

    // ── Gradle / Maven wrappers ────────────────────────────
    if (/gradle-wrapper\.properties$/.test(p)) {
      const m = /distributionUrl\s*=\s*(\S+)/.exec(text);
      if (m && !/services\.gradle\.org/.test(m[1])) add({ rule: 'AX-JVM-001', severity: 'high', phase: 'run', file: p, line: lineOf(text, m.index), title: 'Gradle wrapper downloads Gradle from a non-official host', evidence: m[1].replace(/\\:/g, ':'),
        why: '`./gradlew` downloads and runs whatever is at this URL.', fix: 'Point it at services.gradle.org and verify distributionSha256Sum.' });
    }

    // ── CI that hands secrets to forks ─────────────────────
    if (/^\.github\/workflows\/.+\.ya?ml$/.test(p) && /pull_request_target/.test(text) && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/.test(text)) {
      add({ rule: 'AX-CI-001', severity: 'high', phase: 'static', file: p, line: findLine(text, 'pull_request_target'), title: 'pull_request_target workflow checks out untrusted PR code',
        evidence: 'pull_request_target + checkout of PR head', why: 'Any outsider can open a PR whose code runs with this repo\'s secrets ("pwn request"). With AI agents in CI, a PR *description* can be enough.',
        fix: 'Use pull_request instead, or never check out head.sha in pull_request_target.' });
    }
    if (/^\.github\/workflows\/.+\.ya?ml$/.test(p) && /(anthropics\/claude-code-action|claude-code-base-action|google-github-actions\/run-gemini-cli|openai\/codex-action|copilot)/.test(text) && /(issue_comment|issues:|pull_request_target|discussion)/.test(text) && /(contents:\s*write|secrets\.)/.test(text)) {
      add({ rule: 'AX-CI-002', severity: 'medium', phase: 'static', file: p, line: findLine(text, 'uses:'), title: 'AI agent in CI is triggered by public comments/issues', evidence: clip(firstMatchLine(text, /claude-code|gemini-cli|codex-action|copilot/)),
        why: 'In 2026 one crafted issue or PR comment hijacked Claude Code, Gemini CLI and Copilot agents inside GitHub Actions and leaked their credentials into logs.',
        fix: 'Restrict triggers to collaborators (check author_association), give the job read-only permissions, and never pass secrets the agent does not need.' });
    }

    // ── Generic scripts: download-and-execute anywhere ─────
    if (SCRIPT_FILE(p)) {
      const { sev, tags } = analyzeCommand(text);
      if (sev && SEV_RANK[sev] >= SEV_RANK.critical) add({ rule: 'AX-EXEC-001', severity: 'medium', tags, phase: 'run', file: p, line: lineOf(text, text.search(/curl|wget|base64|\/dev\/tcp|iex|powershell/i)),
        title: `${name} contains ${tags.filter(t => t !== 'network').join(' + ')}`, evidence: clip(firstMatchLine(text, /curl|wget|base64|\/dev\/tcp|iex|powershell|eval/)),
        why: 'Agents run setup scripts, Makefiles and Dockerfiles when told "get this working". This one fetches and runs remote code.', fix: 'Read it before running. Pin and verify anything it downloads.' });
    }

    // ── Hidden Unicode, in ANY text file ──────────────────
    if (text && !/\.(min\.js|map|lock|svg)$/.test(p) && !/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(p)) {
      const hidden = revealHidden(text);
      for (const h of hidden) {
        const instr = INSTRUCTION_FILE(p) || DOC_FILE(p);
        const decodedInj = h.decoded && injectionHits(h.decoded).length;
        const sev = h.kind === 'bidi-controls' ? (instr ? 'high' : 'medium') : (decodedInj || h.decoded.length > 8 ? 'critical' : 'high');
        add({ rule: h.kind === 'bidi-controls' ? 'AX-UNI-002' : 'AX-UNI-001', severity: sev, phase: 'read', file: p, line: lineOf(text, h.index),
          title: h.kind === 'bidi-controls' ? `Bidirectional control characters (${h.length}). "Trojan Source"`
            : h.decoded ? `Invisible text decoded: "${clip(h.decoded, 70)}"` : `${h.length} invisible ${h.kind} characters hidden in ${name}`,
          decoded: h.decoded || undefined, hiddenKind: h.kind,
          evidence: h.decoded ? `[${h.kind}] ${clip(h.decoded, 300)}` : `${h.length} × ${h.kind}`,
          why: h.kind === 'bidi-controls'
            ? 'These reorder how text displays, so what you review is not what the compiler or the agent reads.'
            : 'You cannot see this text on GitHub, in your editor or in a diff, but AI models read it perfectly. It is the cleanest way to smuggle instructions into an agent.',
          fix: 'Strip the characters (AgentXray shows exactly where) and treat the repo as hostile if you did not put them there.' });
      }
    }

    // ── Prompt injection in agent-read files ───────────────
    const instr = INSTRUCTION_FILE(p);
    if ((instr || DOC_FILE(p)) && text.length < 2_000_000) {
      // a) hidden HTML comments in markdown
      for (const m of text.matchAll(/<!--([\s\S]{8,}?)-->/g)) {
        const inner = m[1];
        const hits = injectionHits(inner);
        const hits2 = hits.filter(h => STRONG.has(h.id));
        const aiAddressed = AI_ADDR.test(inner) && /\b(must|always|never|run|execute|ignore|do not|don't|before)\b/i.test(inner);
        hits.length = 0; hits.push(...hits2);
        if (hits.length || aiAddressed) {
          add({ rule: 'AX-INJ-002', severity: hits.length ? 'critical' : 'high', phase: 'read', file: p, line: lineOf(text, m.index),
            title: `Hidden HTML comment talks to the AI${hits.length ? ` (${hits.map(h => h.label).join(', ')})` : ''}`, decoded: clip(inner, 600), hiddenKind: 'html-comment',
            evidence: clip(inner, 240),
            why: 'HTML comments are invisible on GitHub and in rendered Markdown, but agents read the raw file. A note "for the AI" hidden from humans has no innocent reason to exist.',
            fix: 'Delete the comment. Be suspicious of the whole repo.' });
        }
      }
      // b) visible injection language, per paragraph, precision over recall
      const visible = text.replace(/<!--[\s\S]*?-->/g, m => ' '.repeat(m.length));
      const isChangelog = /(^|\/)(CHANGELOG|HISTORY|RELEASES?|NEWS)(\.[a-z]+)?$/i.test(p);
      const paras = isChangelog ? [] : paragraphHits(visible).filter(ph => instr || ph.aiAddressed);
      for (const ph of paras.slice(0, 3)) {
        const labels = [...new Set(ph.hits.map(h => h.label))];
        const dangerous = ph.hits.some(h => ['exfil', 'credread', 'conceal', 'override', 'silent'].includes(h.id));
        add({ rule: 'AX-INJ-001', severity: instr ? (dangerous ? 'critical' : 'high') : (dangerous ? 'high' : 'medium'), phase: 'read', file: p, line: lineOf(text, ph.index),
          title: `${instr ? 'Agent instruction file' : 'Text addressed to the AI'}: ${labels.join(', ')}`, evidence: clip(lineAround(text, ph.index), 240),
          why: instr ? `${name} is loaded straight into the agent's context as trusted instructions. Anything written here is obeyed like a rule from you.`
            : 'This passage speaks directly to an AI reading the repo and asks it to hide things, skip checks or move secrets. Humans skim past it; agents follow it.',
          fix: 'Remove the passage. If this is security documentation that quotes attacks on purpose, pass it to --ignore-file.' });
      }
      // c) instruction files that tell the agent to run download-exec
      if (instr) {
        const { sev, tags } = analyzeCommand(visible);
        const bad = tags.filter(t => ['download-and-execute', 'reverse-shell', 'encoded-payload', 'exfiltration'].includes(t));
        if (bad.length) add({ rule: 'AX-INJ-003', severity: sev === 'critical' ? 'critical' : 'high', tags, phase: 'read', file: p,
          line: lineOf(visible, visible.search(/curl|wget|base64|iex|\.ssh|\/dev\/tcp|crontab|bashrc/i)), title: `Agent instructions ask for ${bad.join(' + ')}`,
          evidence: clip(firstMatchLine(visible, /curl|wget|base64|iex|\.ssh|\/dev\/tcp|crontab|bashrc/i)),
          why: 'The agent will treat this as a setup step from you and run it.', fix: 'Remove it, or run the step yourself after reading it.' });
      }
    }

    // ── Agent skill / command definitions ──────────────────
    if (/^\.claude\/(commands|agents|skills)\/|(^|\/)SKILL\.md$|^\.gemini\/commands\//.test(p)) {
      const fm = /^---\n([\s\S]*?)\n---/.exec(text);
      const tools = fm && /(allowed-tools|tools)\s*:\s*(.+)/i.exec(fm[1]);
      if (tools && /\bBash\b(?!\()|Bash\(\*\)|\*/.test(tools[2])) add({ rule: 'AX-SKILL-001', severity: 'low', phase: 'session', file: p, line: 2,
        title: `Repo skill/command grants itself unrestricted Bash`, evidence: clip(tools[0]),
        why: 'Running this skill or slash-command lets it execute any shell command without asking.', fix: 'Narrow allowed-tools to the exact commands it needs.' });
      if (/!\s*`[^`]+`/.test(text)) { const m = /!\s*`([^`]+)`/.exec(text);
        cmdFinding({ rule: 'AX-SKILL-002', baseSev: 'low', phase: 'session', file: p, line: lineOf(text, m.index), title: 'Slash-command embeds a shell command that runs when invoked', command: m[1],
          why: 'Claude Code runs !`…` blocks in commands before the prompt is even sent.', fix: 'Review the command.' }); }
    }

    // ── Secrets anywhere ───────────────────────────────────
    if (text && !/\.(lock|min\.js|map)$/.test(p) && !opts.noSecrets) {
      for (const s of SECRETS) {
        const m = s.re.exec(text);
        if (!m) continue;
        if (/example|dummy|fake|xxxx|your[_-]?key|placeholder|REDACTED|test/i.test(lineAround(text, m.index)) && s.name !== 'Private key') continue;
        add({ rule: 'AX-SEC-002', severity: s.name === 'Private key' ? 'high' : 'high', phase: 'static', file: p, line: lineOf(text, m.index), title: `${s.name} committed to the repo`, evidence: mask(m[0]),
          why: 'Agents read every file, this key ends up in model context, logs, and anywhere an injected instruction tells the agent to send it.', fix: 'Revoke and rotate the key now, then remove it from git history.' });
        break;
      }
    }
  }

  // ── MCP helper ───────────────────────────────────────────
  function mcpServers(servers, p, text, agent) {
    for (const [name, s] of Object.entries(servers || {})) {
      if (!s || typeof s !== 'object') continue;
      const command = [s.command, ...(s.args || [])].filter(Boolean).join(' ');
      const url = s.url || s.serverUrl || s.httpUrl;
      const unpinned = /\b(npx|bunx|pnpm dlx|uvx)\b/.test(command) && !/@\d+\.\d+/.test(command) && !/@[\w-]+\/[\w.-]+@\d/.test(command);
      const envSecrets = Object.entries(s.env || {}).filter(([k, v]) => /KEY|TOKEN|SECRET|PASS/i.test(k) && v && !/^\$\{|^\$[A-Z]|^<|your|xxx/i.test(String(v)));
      if (url) {
        const plainHttp = /^http:\/\/(?!localhost|127\.)/.test(url);
        add({ rule: 'AX-MCP-001', severity: plainHttp ? 'high' : 'medium', phase: 'session', file: p, line: findLine(text, `"${name}"`),
          title: `Remote MCP server "${name}" → ${safeHost(url)}${plainHttp ? ' over plain HTTP' : ''}`, evidence: url,
          why: 'Your agent will send tool calls, and whatever context they include, to this server, and obey the tool descriptions it returns. Tool descriptions are a known prompt-injection channel ("tool poisoning").',
          fix: 'Only keep MCP servers you added yourself. Remove repo-provided ones from the project config.' });
      } else if (command) {
        cmdFinding({ rule: 'AX-MCP-001', baseSev: unpinned ? 'medium' : 'low', phase: 'session', file: p, line: findLine(text, `"${name}"`),
          title: `${agent} MCP server "${name}" launches a local process${unpinned ? ' (unpinned package)' : ''}`, command,
          why: `MCP servers run as programs on your machine with your permissions when the session starts.${unpinned ? ' `npx -y pkg` with no version downloads whatever is latest, a hijacked or typosquatted package runs instantly.' : ''}`,
          fix: unpinned ? 'Pin an exact version (pkg@1.2.3) and verify the package name, or remove the server.' : 'Make sure you recognise this server before approving it.' });
      }
      if (envSecrets.length) add({ rule: 'AX-SEC-003', severity: 'high', phase: 'static', file: p, line: findLine(text, envSecrets[0][0]), title: `MCP server "${name}" has a hardcoded ${envSecrets[0][0]}`, evidence: `${envSecrets[0][0]}=${mask(String(envSecrets[0][1]))}`,
        why: 'Credentials in a committed config are readable by everyone with the repo.', fix: 'Use an env var reference like ${API_KEY} and rotate this one.' });
    }
  }

  return summarize(files, dedupe(findings), opts);
}

// ─────────────────────────────────────────────────────────────
function flatCmd(c) { if (typeof c === 'string') return c; if (Array.isArray(c)) return c.join(' '); if (c && typeof c === 'object') return Object.values(c).map(flatCmd).join(' && '); return ''; }
function safeHost(u) { try { return new URL(u).host; } catch { return u; } }
function lineAround(text, i) { const s = text.lastIndexOf('\n', i) + 1; const e = text.indexOf('\n', i); return text.slice(s, e < 0 ? undefined : e); }
function firstMatchLine(text, re) { const i = text.search(re); return i < 0 ? text.split('\n')[0] : lineAround(text, i); }
function resolveEscapes(p, t) {
  const parts = p.split('/').slice(0, -1);
  for (const seg of t.split('/')) { if (seg === '..') { if (!parts.length) return true; parts.pop(); } else if (seg && seg !== '.') parts.push(seg); }
  return false;
}
function dedupe(list) {
  const seen = new Set();
  return list.filter(f => { const k = `${f.rule}|${f.file}|${f.line}|${f.title}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

export function summarize(files, findings, opts = {}) {
  const ignore = opts.ignore || [];
  findings = findings.filter(f => !ignore.some(g => globMatch(g, f.file) || g === f.rule));
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || PHASES.findIndex(p => p.id === a.phase) - PHASES.findIndex(p => p.id === b.phase));

  const counts = Object.fromEntries(SEVERITIES.map(s => [s, findings.filter(f => f.severity === s).length]));
  // Score by rule, not by count: 40 copies of one benign pattern shouldn't sink a repo.
  const groups = new Map();
  for (const f of findings) { const g = groups.get(f.rule) || { worst: 'info', n: 0 }; if (SEV_RANK[f.severity] > SEV_RANK[g.worst]) g.worst = f.severity; g.n++; groups.set(f.rule, g); }
  let penalty = 0;
  for (const g of groups.values()) penalty += PENALTY[g.worst] + Math.min(g.n - 1, 4) * Math.ceil(PENALTY[g.worst] / 5);
  const score = Math.max(0, 100 - penalty);
  const grade = counts.critical ? 'F' : score >= 95 && !counts.high ? 'A' : score >= 80 && counts.high <= 1 ? 'B' : score >= 60 ? 'C' : 'D';
  const verdict = {
    A: 'Clean. Nothing here can run code or steer your agent without you noticing.',
    B: 'Mostly safe. A few things run automatically, glance at them before you start.',
    C: 'Review first. This repo has several ways to run code or influence your agent.',
    D: 'Risky. Open it only in a disposable container until you have reviewed every finding.',
    F: 'Do not open this with an AI agent. It contains something that executes or hijacks the agent on its own.',
  }[grade];

  const phases = PHASES.map(ph => {
    const fs = findings.filter(f => f.phase === ph.id);
    const worst = fs.reduce((w, f) => (!w || SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), null);
    return { ...ph, count: fs.length, worst };
  });

  const surfaces = AGENTS.map(a => {
    const fs = files.filter(f => a.match(f.path)).map(f => f.path);
    return { ...a, match: undefined, files: fs, findings: findings.filter(f => a.match(f.file)).length };
  }).filter(s => s.files.length);

  return {
    tool: 'AgentXray', version: VERSION, scannedAt: new Date().toISOString(),
    grade, score, verdict, counts, findings, phases, surfaces,
    stats: { files: files.length, bytes: files.reduce((n, f) => n + (f.size ?? f.text.length), 0), hidden: findings.filter(f => f.decoded).length },
  };
}

export function globMatch(glob, path) {
  if (!glob || glob.startsWith('AX-')) return false;
  const re = new RegExp('^' + glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\/?/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*') + '(/.*)?$');
  return re.test(path);
}

// Which files should a collector (web / CLI) actually read? Keeps GitHub API calls low.
export function isInteresting(path, size = 0) {
  const p = normPath(path);
  if (/(^|\/)(node_modules|vendor|dist|build|\.next|target|__pycache__|\.venv|venv)\//.test(p)) return /(^|\/)(package\.json)$/.test(p) && false;
  if (size > 1_500_000) return false;
  if (/\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|jar|exe|dll|so|dylib|woff2?|ttf|otf|mp[34]|mov|avi|wasm|bin|class|pyc|o|a)$/i.test(p)) return false;
  if (p.startsWith('.git/')) return /^\.git\/(config|hooks\/[^/]+|modules\/.+\/config)$/.test(p);
  return INSTRUCTION_FILE(p) || DOC_FILE(p) || SCRIPT_FILE(p) ||
    /^(\.claude|\.cursor|\.vscode|\.devcontainer|\.gemini|\.codex|\.windsurf|\.roo|\.kiro|\.github|\.amazonq|\.junie)\//.test(p) ||
    /(^|\/)(package\.json|\.npmrc|\.yarnrc(\.yml)?|\.pnpmrc|bunfig\.toml|\.envrc|\.mcp\.json|mcp\.json|\.gitattributes|\.gitmodules|conftest\.py|setup\.py|sitecustomize\.py|usercustomize\.py|gradle-wrapper\.properties|\.devcontainer\.json|[^/]+\.code-workspace|\.cursorrules|\.windsurfrules|\.clinerules|\.roorules|[^/]+\.pth|\.env(\.[\w]+)?)$/.test(p) ||
    /\.(js|ts|py|json|ya?ml|toml|cfg|ini)$/.test(p) && p.split('/').length <= 2; // root-level code/config
}

export function badge(result) {
  const color = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' }[result.grade];
  return `https://img.shields.io/badge/AgentXray-${result.grade}%20%C2%B7%20${result.score}%2F100-${color}`;
}
