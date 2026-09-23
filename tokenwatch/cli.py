"""tokenwatch CLI.

  python -m tokenwatch audit [--fix] [--json] [-o file]
  python -m tokenwatch watch [--once] [--uninstall] [--interval S]
  python -m tokenwatch honey plant|status|clean
  python -m tokenwatch report [--json]
  python -m tokenwatch paths
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from . import platforms, inventory, perms, secrets, honey, watch
from .report import Report
from .score import Finding

ENV_SECRET_NAMES = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_ORG_ID",
    "GOOGLE_API_KEY", "GEMINI_API_KEY", "GH_TOKEN", "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN", "AZURE_CLIENT_SECRET", "COHERE_API_KEY",
    "MISTRAL_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY",
]


def _emit(rep, as_json, out=None):
    text = rep.to_json() if as_json else rep.to_text()
    print(text)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")


def _run_audit(env, runner=None, extra_dirs=(), fix=False):
    """Core audit: inventory + perms + secret scan -> Report."""
    rep = Report()
    resolved = inventory.discover(env=env)
    rep.inventory = [(r.spec.owner, r.spec.kind, r.path) for r in resolved]

    # 1. permissions on sensitive stores
    for res in resolved:
        if not res.spec.sensitive:
            continue
        for iss in perms.audit_path(res.path, env=env, runner=runner):
            rule = "perm-acl-foreign" if platforms.PLATFORM == "windows" \
                else ("perm-loose-dir" if res.path.is_dir()
                      else "perm-loose-file")
            rep.findings.append(Finding(rule, str(iss.path), iss.detail))
            if fix and iss.fixable:
                act = perms.lockdown(res.path, env=env, runner=runner)
                if act:
                    print(f"  [fix] {act}", file=sys.stderr)

    # 2. secret scan — classified by where the secret sits:
    #    expected credential storage (stored-session) vs actual leaks
    seen = set()
    for f in inventory.context_files(resolved):
        kind = _spec_kind(f, resolved)
        for hit in secrets.scan_file(f):
            key = (str(hit.path), hit.fp)   # same VALUE in one file = once
            if key in seen:
                continue
            seen.add(key)
            rule, extra = _hit_rule(f, kind, env=env, runner=runner)
            detail = f"{hit.pattern} line {hit.line or '-'} {hit.masked}"
            if extra:
                detail += f" - {extra}"
            rep.findings.append(Finding(rule, str(hit.path), detail))

    # 3. env exposure
    for name in ENV_SECRET_NAMES:
        if env.get(name):
            rep.findings.append(Finding(
                "env-secret", f"env:{name}",
                "set in process env - inherited by every child process"))

    # 4. honeytoken posture
    for decoy_id, path, st in honey.status(env=env):
        rep.honey.append((decoy_id, path, st))
        if st == "MISSING":
            rep.findings.append(Finding(
                "honey-missing", path, "planted canary was deleted"))
    return rep.finalize()


_MCP_NAMES = {"mcp.json", ".mcp.json", "mcp_config.json",
              "claude_desktop_config.json", ".claude.json"}

# files whose PURPOSE is holding credentials — secrets inside are expected
# storage (stored-session), not leaks
_EXPECTED_CRED_NAMES = {
    ".credentials.json", "credentials", "credentials.json",
    "credentials.toml", "credentials.tfrc.json", "auth.json",
    "oauth_creds.json", "hosts.yml", "access_tokens.db", "credentials.db",
    "msal_token_cache.bin", "msal_token_cache.json", "state.vscdb",
    ".netrc", "_netrc", ".git-credentials", ".npmrc", ".yarnrc",
    ".pypirc", "token", "google_accounts.json", "apps.json",
    "config.json", ".envrc", "settings.xml",
    "gradle.properties", "nuget.config",
}
_KEY_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")

# subdirs that hold transcripts/history rather than credential files
_CONTEXTISH = {"sessions", "projects", "history", "logs", "log",
               "cascade", "transcripts", "memories", "chats"}


def _spec_kind(path, resolved):
    """Kind of the most-specific resolved spec containing `path`."""
    best = None
    for r in resolved:
        try:
            if path == r.path or r.path in path.parents:
                if best is None or len(str(r.path)) > len(str(best.path)):
                    best = r
        except TypeError:
            continue
    return best.spec.kind if best else "context"


_ENV_NAME_RE = re.compile(r"^\.env(\..*)?$", re.IGNORECASE)


def _find_repo(path):
    """Walk parents for a .git dir/file (worktrees use a .git file)."""
    for d in path.parents:
        if (d / ".git").exists():
            return d
    return None


def _env_rule(path, runner=None):
    """.env files are never 'expected storage' — repo membership decides."""
    repo = _find_repo(path)
    if repo is None:
        return "plaintext-token", ""
    if runner is None and not platforms.which("git"):
        return "plaintext-token", "git unavailable"
    rel = os.path.relpath(str(path), str(repo))
    rc, _, _ = platforms.run(
        ["git", "-C", str(repo), "ls-files", "--error-unmatch", rel],
        runner=runner)
    if rc == 127:
        return "plaintext-token", "git unavailable"
    if rc == 0:
        return "repo-secret", "tracked"
    rc, _, _ = platforms.run(
        ["git", "-C", str(repo), "check-ignore", "-q", rel], runner=runner)
    if rc == 127:
        return "plaintext-token", "git unavailable"
    if rc == 0:
        return "plaintext-token", "gitignored"
    return "repo-secret", "not gitignored"


def _hit_rule(path, spec_kind, env=None, runner=None):
    """-> (rule, detail_extra). .env classification is repo-aware."""
    name = path.name.lower()
    if _ENV_NAME_RE.match(name):
        return _env_rule(path, runner=runner)
    if name in _MCP_NAMES:
        return "mcp-plaintext-key", ""
    if any(part.lower() in _CONTEXTISH for part in path.parts):
        return "context-secret", ""
    if name in _EXPECTED_CRED_NAMES or name.startswith(_KEY_PREFIXES):
        return "stored-session", ""
    if spec_kind == "context":
        return "context-secret", ""
    if spec_kind in ("token", "key"):
        return "stored-session", ""   # inside a credential store = expected
    return "plaintext-token", ""


def cmd_audit(a):
    env = dict(os.environ)
    rep = _run_audit(env, fix=a.fix)
    if a.extra_dir:
        seen = set()
        for d in a.extra_dir:
            for f in Path(d).rglob("*"):
                if not f.is_file():
                    continue
                for hit in secrets.scan_file(f):
                    key = (str(hit.path), hit.fp)
                    if key in seen:
                        continue
                    seen.add(key)
                    rule, extra = _hit_rule(f, "config", env=env)
                    detail = f"{hit.pattern} {hit.masked}"
                    if extra:
                        detail += f" - {extra}"
                    rep.findings.append(Finding(rule, str(hit.path), detail))
        rep.finalize()
    _emit(rep, a.json, a.out)
    return 1 if rep.score >= 50 else 0


def cmd_watch(a):
    env = dict(os.environ)
    resolved = inventory.discover(env=env)
    paths = inventory.sensitive_paths(resolved) + honey.honey_paths(env)
    if not paths:
        print("no credential stores found to watch", file=sys.stderr)
        return 2
    w = watch.Watcher(paths, honey_paths=honey.honey_paths(env), env=env)
    print(f"backend: {w.backend.name} - watching {len(paths)} paths",
          file=sys.stderr)
    if w.backend.name == "snapshot-degraded":
        print("WARNING: degraded mode - reads are NOT detectable, only "
              "writes/deletes", file=sys.stderr)
    if a.uninstall:
        for act in w.uninstall():
            print(f"  {act}")
        return 0
    if a.once:
        alerts = w.poll_once()
        for ev in alerts:
            watch.Watcher._print(ev)
        print(f"poll complete - {len(alerts)} alerts "
              f"(log: {w.alert_log})", file=sys.stderr)
        return 1 if alerts else 0
    if not platforms.is_admin() and w.backend.name != "snapshot-degraded":
        print("WARNING: not elevated - audit policy/SACL install may fail",
              file=sys.stderr)
    for act in w.install():
        print(f"  {act}", file=sys.stderr)
    w.serve(interval=a.interval)
    return 0


def cmd_honey(a):
    env = dict(os.environ)
    if a.action == "plant":
        planted, skipped = honey.plant(env=env)
        for s in planted:
            print(f"  planted {s}")
        for s in skipped:
            print(f"  skipped {s}")
        print(f"{len(planted)} planted, {len(skipped)} skipped")
    elif a.action == "status":
        rows = honey.status(env=env)
        if not rows:
            print("no honeytokens planted — run `tokenwatch honey plant`")
        for i, p, s in rows:
            print(f"  {s:16} {i:12} {p}")
    elif a.action == "clean":
        for p in honey.clean(env=env):
            print(f"  removed {p}")
    return 0


def cmd_report(a):
    env = dict(os.environ)
    rep = _run_audit(env)
    rep.watch_backend = "not running (audit-only)"
    alert_log = platforms.state_dir(env) / "alerts.jsonl"
    if alert_log.exists():
        for line in alert_log.read_text(encoding="utf-8").splitlines()[-200:]:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = "honeytoken-read" if ev.get("honey") else \
                ("unauthorized-write" if ev.get("access") in
                 ("write", "delete") else "unauthorized-read")
            rep.findings.append(Finding(
                rule, ev.get("path", "?"),
                f"{ev.get('process', '?')} (pid {ev.get('pid', 0)})"))
    rep.finalize()
    _emit(rep, a.json, a.out)
    return 1 if rep.score >= 50 else 0


def cmd_paths(a):
    rows = inventory.known_specs_for()
    for spec, p in rows:
        flag = "*" if spec.sensitive else " "
        print(f"{flag} [{spec.kind:7}] {spec.owner:22} {p}")
    print("\n* = perm-enforced + watch target")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tokenwatch",
        description="AI-agent credential + context theft monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("audit", help="inventory + perm/secret audit")
    pa.add_argument("--fix", action="store_true",
                    help="lock down loose permissions")
    pa.add_argument("--json", action="store_true")
    pa.add_argument("-o", "--out")
    pa.add_argument("--extra-dir", action="append", default=[],
                    help="also secret-scan this dir (e.g. project .env)")
    pa.set_defaults(fn=cmd_audit)

    pw = sub.add_parser("watch", help="monitor stores for unauthorized reads")
    pw.add_argument("--once", action="store_true", help="single poll cycle")
    pw.add_argument("--uninstall", action="store_true",
                    help="remove audit rules")
    pw.add_argument("--interval", type=int, default=30)
    pw.set_defaults(fn=cmd_watch)

    ph = sub.add_parser("honey", help="honeytoken management")
    ph.add_argument("action", choices=["plant", "status", "clean"])
    ph.set_defaults(fn=cmd_honey)

    pr = sub.add_parser("report", help="audit + alert history -> full report")
    pr.add_argument("--json", action="store_true")
    pr.add_argument("-o", "--out")
    pr.set_defaults(fn=cmd_report)

    pp = sub.add_parser("paths", help="list known store locations")
    pp.set_defaults(fn=cmd_paths)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
