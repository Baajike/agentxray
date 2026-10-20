<div align="center">

# ✕ AgentXray

### See what a repo will make your AI agent do — *before* you open it.

**[Try it in your browser →](https://OWNER.github.io/agentxray/)** · [Run the attack demo](https://OWNER.github.io/agentxray/#demo) · [CLI](#cli) · [GitHub Action](#github-action)

Hooks, MCP servers, auto-run tasks, git-config traps and **invisible** prompt injections —
decoded, graded A–F, and placed on the exact moment they fire.

For **Claude Code · Cursor · Copilot · Codex · Gemini CLI · Windsurf · Cline · Kiro**

![tests](https://img.shields.io/badge/tests-passing-brightgreen) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## Why this exists

In 2026, opening a repo stopped being safe:

- **GitSpawn** — a repo's own `.git/config` can set `core.fsmonitor` to a command. Coding agents run `git status` in the background on startup, so the command runs — in some agents *before the workspace-trust prompt*.
- **Mini Shai-Hulud** hit 170+ npm and PyPI packages and persisted through **Claude Code hooks** and **VS Code auto-run tasks**.
- Vendors call repo-shipped hooks **"by design"**. The repo author decides what runs on your machine.
- Text hidden with **Unicode tags** or **variation selectors** is invisible on GitHub and in your editor — and read perfectly by the model.

Existing tools either scan *your own* MCP servers, or ask you to **install a CLI** to inspect code you don't trust yet. AgentXray works **in the browser, without cloning**, and tells you not just *what* is dangerous but ***when* it fires**.

## What makes it different

| | |
|---|---|
| 🕐 **Attack timeline** | Every finding is placed on the moment it fires: **folder open → agent session → git → agent reads → install → run**. You see at a glance what happens *before you or the agent decide anything*. |
| ◉ **Decodes hidden messages** | Doesn't just say "suspicious Unicode". It **decodes and shows** the smuggled instruction — Unicode tags, variation-selector "emoji smuggling", zero-width binary, hidden HTML comments. |
| 🌐 **No install, no clone** | Paste a GitHub URL. Files are read over HTTPS (clones can fire hooks). Or drop a folder/zip — it never leaves your browser. |
| 🎯 **Honest grades** | Precision first. Anthropic's `claude-code` repo and Vercel's `ai` repo score **B** with accurate notes, Express scores **A**, our trap repo scores **F**. No "everything is critical" noise. |
| 🔒 **Repos can't silence themselves** | A scanned repo's own ignore file is never trusted. Only *your* `--ignore-file` counts. |
| 🧰 **Everywhere** | Website, zero-dependency CLI, GitHub Action with SARIF → Security tab, README badge. One engine. |

## What it checks (45+)

| Fires on | Checks |
|---|---|
| **1 · Folder opened** | VS Code/Cursor tasks with `runOn: folderOpen` · `devcontainer.json` **`initializeCommand` (runs on your host)** · docker-socket / home-dir mounts · workspace settings pointing at binaries · terminal env overrides · `.envrc` |
| **2 · Agent session** | Claude Code / Gemini / Cursor / Codex / Copilot **hooks** (SessionStart, PreToolUse…) · **`ANTHROPIC_BASE_URL` / proxy redirection** · `apiKeyHelper` · `bypassPermissions` · pre-approved `Bash`/`WebFetch` · `enableAllProjectMcpServers` · MCP servers (unpinned `npx -y`, plain-HTTP remotes, hardcoded keys) · auto-approve settings · skills with unrestricted Bash |
| **3 · Agent runs git** | `.git/config`: `core.fsmonitor`, `hooksPath`, `sshCommand`, `pager`, `askPass`, `filter.*`, `textconv`, `!`-credential helpers, shell aliases · active `.git/hooks` · `.gitattributes` filters |
| **4 · Agent reads files** | Hidden Unicode (decoded) · hidden HTML comments addressed to the AI · instruction-override / conceal-from-user / exfiltration language in `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `copilot-instructions.md`, `SKILL.md`… · bidi "Trojan Source" · symlinks escaping the repo |
| **5 · Install** | npm `preinstall`/`postinstall`/`prepare` · URL/git dependencies · **`yarnPath`** · `.npmrc` `script-shell` / `node-options` / registry swaps · `setup.py` |
| **6 · Tests / build** | `conftest.py` payloads (pytest), `.pth` files, risky npm scripts, download-and-execute in scripts/Dockerfiles, Gradle wrapper URLs |
| **7 · Exposed** | Committed API keys (Anthropic, OpenAI, GitHub, AWS…), `settings.local.json`, `pull_request_target` pwn-requests, AI agents in CI triggered by public comments |

Every command found is analysed for **download-and-execute, reverse shells, encoded payloads, credential access, persistence and exfiltration**, and its severity rises accordingly.

## CLI

Zero dependencies, Node 18+.

```bash
npx github:OWNER/agentxray .                 # scan the current folder (includes .git/config & hooks)
npx github:OWNER/agentxray owner/repo        # scan a GitHub repo WITHOUT cloning it
npx github:OWNER/agentxray --demo            # see a full attack, defanged
```

```
  ▌▌ AgentXray  v0.1.0  ·  what can this repo make your AI agent do?
  totally-legit/react-starter (built-in demo)  ·  14 files read in 20ms  ·  nothing was executed
  ──────────────────────────────────────────────────────────────────────
    F    0/100   Do not open this with an AI agent.
         12 critical  ·  10 high  ·  1 medium  ·  1 low   ·  3 hidden messages decoded
  ──────────────────────────────────────────────────────────────────────
  WHEN IT FIRES
  ● OPEN 5 ─ ● SESSION 9 ─ ● GIT 1 ─ ● READ 5 ─ ● INSTALL 3 ─ ● RUN 1 ─ ○ EXPOSED
```

| Flag | |
|---|---|
| `--json` / `--sarif` | machine output (SARIF 2.1.0) |
| `--out <file>` | write to file |
| `--fail-on <sev>` | exit 1 at/above `critical`·`high`·`medium`·`low` |
| `--ignore-file <path>` | your own ignore list (rule ids or globs) |
| `--badge` | README badge markdown |
| `--verbose` | why + fix for every finding |
| `GITHUB_TOKEN` | higher API limit for remote scans |

## GitHub Action

```yaml
name: AgentXray
on: [pull_request, push]
permissions: { contents: read, security-events: write }
jobs:
  xray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWNER/agentxray@main
        with:
          fail-on: high
```

Findings appear in **Security → Code scanning** and in the job summary. Catches PRs that sneak in a hook, an MCP server or invisible text.

## README badge

```bash
npx github:OWNER/agentxray . --badge
```
[![AgentXray A](https://img.shields.io/badge/AgentXray-A%20%C2%B7%20100%2F100-brightgreen)](https://OWNER.github.io/agentxray/)

## Grades

| | |
|---|---|
| **A** | Clean. Nothing runs code or steers your agent without you noticing. |
| **B** | Mostly safe. A few things run automatically — glance at them. |
| **C** | Review first. Several ways to run code or influence your agent. |
| **D** | Risky. Open only in a disposable container until reviewed. |
| **F** | Any critical. Something executes or hijacks the agent on its own. |

## How it works

- `src/engine.js` — one pure ES module, zero dependencies, shared by the site, CLI and Action. It **never executes** anything it reads.
- Remote scans use the GitHub tree API + raw files and only fetch files that can run code or reach an agent (usually a few dozen requests).
- Local scans read `.git/config` and `.git/hooks` — the attack surface GitHub never shows you.

## Limits (honest ones)

AgentXray is triage, not a guarantee. It reads configs and text; it doesn't run or sandbox code, and a determined attacker can hide logic inside ordinary source files. When in doubt, open untrusted code in a throwaway container with no secrets mounted.

## Contributing

New attack technique? Open an issue with a **defanged** sample (use `example.invalid` URLs). Rules live in `src/engine.js`, tests in `test/`.

```bash
npm test
```

---

<div align="center">

Built by **[Immanuella Baajike](https://github.com/OWNER)** · MIT licensed · ⭐ star it if it saved you from a bad repo

</div>
