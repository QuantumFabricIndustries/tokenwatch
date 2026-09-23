# Lessons — tokenwatch

## Never taskkill by image name
`taskkill //F //IM python.exe` killed EVERY python on the box, not just my
background audit — user processes died too. Kill by PID from the shell's own
job, or `get_output`/`kill_shell` on the tool's shell_id.

## Windows text mode mangles bytes
`Path.write_text("...\n")` on win32 translates `\n`→`\r\n` — the file's
sha256 then differs from the in-memory hash, so freshly-planted honeytokens
reported TOUCHED/MODIFIED. Write credential files with `write_bytes`.

## Secret-scan cost = passes × bytes, not bytes
15 provider regexes × ~100 MiB of transcripts ≈ 45s. One literal-stem
prefilter regex skips ~95% of files in one pass; total scan dropped to ~13s.
Also: per-store byte budget (64 MiB, newest-mtime-first) — Electron/agent
context dirs are unbounded (found 1 GiB of cascade .pb, 4000 files in
.gemini).

## Scope Electron dirs to known subpaths
`%APPDATA%/Cursor` et al. are whole app-data trees (GPUCache, blob_storage,
Service Worker). StoreSpec.scan targets `User/globalStorage/state.vscdb`,
`logs` etc.; skip-dir list carries the Chromium junk names.

## Overlapping provider patterns double-count one secret
`sk-ant-` matched both anthropic-key AND openai-key (`sk-[A-Za-z0-9_-]{20,}`).
OpenAI keys are `sk-proj-`/`sk-svcacct-`/legacy 48-alnum — no hyphens in the
legacy body, so `sk-ant-` can't collide once tightened. Dedupe findings by
(path, line, masked), not (path, pattern, line).

## Generic secret regex vs bundled libraries
`token\s*=` matches `self._remote_tokens` assignments in vendored
transformers source under `.gemini/antigravity` — entropy gate doesn't save
you from code identifiers. Keep bundled-app dirs out of scan scope; expect
generic hits only on config/history-shaped files.

## Windows console is cp1252
Em-dashes and `…` print as `?` — keep all CLI/report output ASCII.

## FileSystemAuditRule: files take NO inheritance flags
`'ContainerInherit,ObjectInherit'` throws "No flags can be set" on files —
legal only on directories. Every file SACL silently failed while dir SACLs
worked, and synthetic tests (fake runner, rc=0) couldn't see it. Branch on
`(Get-Item $p).PSIsContainer`. Only the live elevated run caught this —
always live-prove ACL/SACL code paths, fake runners lie by omission.

## Security-log events lag generation
Our own SACL-install powershell (WRITE_DAC) appeared in a poll seconds AFTER
a drain poll that should have swallowed it. Don't assume a drain poll fully
clears setup noise; expect late-arriving 4663s.
