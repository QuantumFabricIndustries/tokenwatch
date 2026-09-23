# tokenwatch

Detection engine for **AI-agent credential theft** — the Muse-class
infostealer surface that sits between endpoint EDR and prompt-injection
defenses: the *local token stores and cached context* of desktop AI agents
and dev tools. Pure Python 3.9+ stdlib, zero dependencies.

Sibling tools in the QuantumFabricIndustries stack: gitguard (git layer),
phantom-snare (prompt injection / MCP), iron-gates-xdr (endpoint).
tokenwatch guards what those don't: the secrets *at rest under your home
directory* and *in agent transcript caches*.

## What it watches

~45 known store locations across agent tooling:

| Class | Stores |
|---|---|
| **Agent creds** | `~/.claude` (+`.credentials.json`, `.claude.json`), `~/.codex`, `~/.config/devin`, `~/.gemini/oauth_creds.json`, Cursor `state.vscdb`, VS Code `globalStorage`, Copilot `apps.json`, Aider, Continue, Windsurf/`.codeium`, Zed |
| **MCP configs** | `~/.cursor/mcp.json`, `claude_desktop_config.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.vscode/mcp.json` — per-server plaintext API keys |
| **Dev creds** | `.aws`, `.ssh`, `.kube`, `.docker`, `.netrc`, `.git-credentials`, gh/gcloud/azure token caches, `.npmrc`, `.pypirc`, HF token, terraform, cargo, gem, composer, maven, gradle, `.gnupg`, ollama key, configstore, vercel/netlify/railway |
| **Cached context** | `.claude/projects` transcripts, codex sessions, windsurf cascade `.pb`, PSReadLine `ConsoleHost_history.txt`, `.bash_history`/`.zsh_history` — where pasted secrets go to live forever |

## Commands

```bash
python -m tokenwatch audit [--fix] [--json] [-o file] [--extra-dir DIR]
python -m tokenwatch watch [--once] [--uninstall] [--interval S]
python -m tokenwatch honey plant|status|clean
python -m tokenwatch report [--json]
python -m tokenwatch paths
```

**audit** — inventory + permission check (POSIX mode / Windows icacls ACLs:
flags Everyone / BUILTIN\Users / Authenticated Users on any sensitive store)
+ secret scan of context caches (provider regexes + entropy-gated generic
assignments; doc-example/placeholder/sequential values excluded; secrets
masked `prefix...last4`). `--fix` locks permissions to
owner+SYSTEM+Administrators (win) / 600-700 (posix).

Findings are classified by where the secret sits: `stored-session` (+5) for
files whose purpose is credential storage (`oauth_creds.json`, `auth.json`,
`state.vscdb`, `.aws/credentials`…), `plaintext-token` (+25) for secrets in
config-shaped files, `mcp-plaintext-key` (+30) in MCP configs,
`context-secret` (+35) for leaks into transcripts/logs/history. Identical
secret values dedupe per file.

`.env` files are never "expected storage". Inside a git work tree a
secret-bearing `.env` is `repo-secret` (+40, cap 80) when the file is
tracked or not gitignored — either way it ships to the remote; a gitignored
`.env` stays `plaintext-token` (+25). Detection walks parents for `.git`
and shells out to `git ls-files --error-unmatch` / `git check-ignore -q`;
without git it degrades to `plaintext-token` with a "git unavailable" note.
`.env.example`/`.env.sample` are scanned too — doc-example values are
filtered, real-format keys still count.

**watch** — real-time read detection on all sensitive stores + honeytokens:

- **Windows** (primary): `auditpol` File-System success + a `Success` SACL
  for Everyone on each protected path via PowerShell `Set-Acl`, then Security
  event 4663 polling via `wevtutil` — full per-process attribution (exe path,
  pid, access mask). AccessMask `WRITE_DAC`/`WRITE_OWNER` on a cred store is
  reported as `perm-change` (ACL takeover).
- **Linux**: `auditctl -w path -p rwa -k tokenwatch` + `ausearch` (needs root).
- **Fallback** (macOS / no privileges): snapshot diff — detects writes and
  deletes only. **Reads are invisible in degraded mode**; the tool says so
  loudly.

Allowlist at `~/.tokenwatch/allowlist.json` — every specified field must
match (AND):

```json
[{"name": "x.exe", "process_dir": "\\nodejs\\",
  "path_contains": ".claude", "signer": "Node.js"}]
```

- `process_dir` anchors the exe's directory — a file renamed `node.exe` in
  `%TEMP%` does not pass
- `signer` resolves the Authenticode subject via
  `Get-AuthenticodeSignature` and requires `Status=Valid` (Windows;
  unverifiable signer → rule fails closed)
- defaults anchor OS noise to real install dirs + Microsoft signature, and
  agent binaries to their install directories (e.g. `Cursor.exe` only under
  a `cursor` dir, `node.exe` only under `nodejs`/`nvm` AND only for
  `.claude`/`.codeium` objects)

Everything else that touches a watched store lands in
`~/.tokenwatch/alerts.jsonl`.

**honey** — canary credentials planted where stealers look: real store
paths used only when vacant (`~/.aws/credentials`, `~/.kube/config`,
`~/.docker/config.json`, `~/.git-credentials`, `~/.cache/huggingface/token`)
plus plausible strays (`~/.env.backup`, `~/.ssh/id_rsa.bak`). Values are
realistic-format random keys with no marker strings; the manifest is keyed
by `sha256(path)` so `~/.tokenwatch/honey.json` reveals no locations. No
legitimate reader exists → any access is a zero-false-positive compromise.

**channel integrity** (part of `audit`) — the redirection half of the Muse
attack: env + WinINET/WinHTTP proxies that could reroute agent traffic,
hosts-file remaps of provider domains (redirect or sinkhole), user-scope
root CAs (HKCU\Root needs no admin — a classic malware move), and
MITM-tool CAs (mitmproxy/fiddler/burp…) in the machine root store.

## Verdicts

`HARDENED` <20 · `EXPOSED` 20-49 · `HIGH RISK` 50-79 · `COMPROMISED` 80+.

Honeytoken read, unauthorized read/write, or ACL tamper force COMPROMISED
regardless of score — observed theft attempt, not posture gap. Posture-only
leaks (live keys in shell history) can still reach COMPROMISED — those creds
should be treated as compromised and rotated.

Per-rule caps keep one noisy rule from dominating; the SUMMARY block prints
`raw -> effective (cap)` per rule so caps are never silent.

## Honest coverage boundaries

- Per-store secret scan is budgeted (64 MiB, newest-first) — a 1 GiB cascade
  store gets its freshest files scanned, not every byte.
- Binary stores (`.vscdb`, leveldb) get provider-pattern scan only, no
  generic-entropy pass.
- Windows watch needs elevation for `auditpol`/SACL install; unelevated runs
  degrade to snapshot mode.
- macOS watch is snapshot-only (Endpoint Security needs a signed entitlement);
  Linux watch needs auditd+root. Audit/inventory work everywhere.
- `.pb` protobuf cascades >16 MiB/file are stat'ed but not scanned.

## Tests

```bash
python -m unittest discover tests   # 42 tests, all synthetic fixtures —
                                    # no real credentials or malware
```
