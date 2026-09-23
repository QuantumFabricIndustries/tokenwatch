# tokenwatch — Build Plan

Goal: defensive monitor for AI-agent credential theft (Muse-class infostealers /
rogue processes harvesting desktop agent tokens + cached context). Fills the gap
between gitguard (git layer), phantom-snare (prompt injection), and
iron-gates-xdr (endpoint): none of them protect where agents *store* secrets.

## Architecture
Pure-stdlib Python package `tokenwatch` + CLI (`python -m tokenwatch`).
All platform ops go through an injectable `runner` (same fake-runner pattern as
rathat_shield's ADB layer) so the whole control plane is unit-testable.

1. **inventory** — registry of ~40 known credential/context stores:
   agent dirs (Claude Code/Desktop, Codex, Windsurf/Codeium, Cursor, Devin,
   Copilot, Aider, Continue), MCP configs with plaintext keys, generic dev creds
   (.aws/.ssh/.kube/.docker/.netrc/.git-credentials/.npmrc/.pypirc/gh/gcloud/
   azure/hf token). Per-OS path tables.
2. **secrets** — regex + Shannon-entropy detection, file/dir/sqlite-raw scan
   (Cursor state.vscdb = raw-byte scan), placeholder exclusion, masked output
   (prefix…last4 only — never log full secrets).
3. **perms** — POSIX mode audit (sensitive files 600/dirs 700) + Windows icacls
   ACL audit (flag Everyone/Users/AuthUsers read). `audit --fix` locks down.
4. **watch** — real-time read detection.
   - Windows: `auditpol` File-System success + PowerShell SACL on protected
     dirs → Security event 4663 parsed via `wevtutil` XML → process attribution.
   - Linux: `auditctl -w` + ausearch parsing (needs root).
   - macOS/no-priv fallback: snapshot backend (write/delete detection only —
     cannot see reads; documented degradation).
   - Allowlist (`~/.tokenwatch/allowlist.json`): agent binaries + OS noise;
     everything else alerts → `~/.tokenwatch/alerts.jsonl`.
5. **honey** — canary credentials planted where stealers look (only when no
   real store exists): fake ~/.aws/credentials, honey dir creds. Any read =
   zero-FP COMPROMISED. Manifest-tracked plant/status/clean.
6. **score/report** — findings → weighted score → verdict:
   HARDENED <20 · EXPOSED 20–49 · HIGH RISK 50–79 · COMPROMISED 80+ (forced on
   honeytoken touch). Console + JSON report.

## Tasks
- [x] Scaffold + pyproject (stdlib-only)
- [x] platforms.py (runner injection, path expansion, OS dispatch)
- [x] inventory.py (store registry + discover)
- [x] secrets.py (patterns, entropy gate, masking)
- [x] perms.py (posix + icacls audit, lockdown)
- [x] watch.py (backends, allowlist, alert sink)
- [x] honey.py (plant/status/clean, manifest)
- [x] score.py + report.py
- [x] cli.py + __main__.py
- [x] tests (synthetic fixtures: temp HOME tree, wevtutil XML, icacls output)
- [x] README + MIT LICENSE
- [x] Push to QuantumFabricIndustries/tokenwatch (public)

## Verification
- [x] `python -m unittest discover tests` — 42 green (2 POSIX-only skipped on win32)
- [x] `python -m tokenwatch audit` runs on this host (~13.5s)
- [x] Honey lifecycle proven on temp HOME (plant->ARMED->tamper detect->clean)
- [x] 4663 XML parse + allowlist + dedupe proven on fixture (stealer.exe
      alerts, MsMpEng allowlisted, WRITE_DAC->perm-change)

## Review
Built 2026-09-23. Gap it fills: Muse-class theft of agent token stores +
cached context — uncovered by gitguard/phantom-snare/iron-gates-xdr.
- Not exercised live: actual 4663 watch (needs elevated auditpol+SACL),
  auditd backend (no linux box), elevated icacls lockdown.
- Perf lesson embedded: literal-stem prefilter + per-store 64MiB
  newest-first budget took audit 163s -> 13.5s.
- INCIDENT: `taskkill //IM python.exe` during debugging killed unrelated
  user python processes — never kill by image name (lessons.md).
