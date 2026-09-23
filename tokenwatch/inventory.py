"""Registry of credential + cached-context stores for AI agents and dev tools.

Each StoreSpec describes where a class of secrets lives per-OS. `discover()`
resolves specs against an env map (injectable for tests) and returns the
stores that actually exist on disk.

kind:    token | key | config | context
sensitive: True  -> must be owner-only (perm-enforced, watch target)
           False -> context/history (secret-scan target, perm findings are
                    informational since some tools ship loose defaults)
"""
import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import platforms


@dataclass(frozen=True)
class StoreSpec:
    id: str
    owner: str
    kind: str                       # token | key | config | context
    paths: dict                     # {"windows": [...], "linux": [...], ...}
    holds: str                      # human description of what's inside
    sensitive: bool = True
    glob: bool = False              # path entries are glob patterns
    scan: tuple = ()                # relative subpaths to secret-scan;
                                    # empty = scan the store path itself


def _p(win=(), posix=(), darwin=(), linux=()):
    d = {"posix": list(posix)}
    if win:   d["windows"] = list(win)
    if darwin: d["darwin"] = list(darwin)
    if linux:  d["linux"] = list(linux)
    return d


# ---------------------------------------------------------------- registry
STORES = [
    # --- AI coding agents -------------------------------------------------
    StoreSpec("claude-code-creds", "Claude Code", "token",
              _p(posix=["{HOME}/.claude/.credentials.json"]),
              "OAuth tokens"),
    StoreSpec("claude-code-config", "Claude Code", "config",
              _p(posix=["{HOME}/.claude.json"]),
              "account config, MCP server env/keys"),
    StoreSpec("claude-code-dir", "Claude Code", "context",
              _p(posix=["{HOME}/.claude"]),
              "session transcripts, history, settings",
              sensitive=False),
    StoreSpec("claude-desktop", "Claude Desktop", "config",
              _p(win=["{APPDATA}/Claude"],
                 darwin=["{HOME}/Library/Application Support/Claude"],
                 linux=["{HOME}/.config/Claude"]),
              "claude_desktop_config.json (MCP plaintext keys), local storage",
              scan=("claude_desktop_config.json", "Local Storage",
                    "Session Storage", "logs")),
    StoreSpec("codex-dir", "OpenAI Codex", "token",
              _p(posix=["{HOME}/.codex"]),
              "auth.json, sessions, config.toml"),
    StoreSpec("windsurf-dir", "Windsurf/Codeium", "config",
              _p(posix=["{HOME}/.codeium"]),
              "windsurf mcp_config.json, memories, cascade state",
              scan=("windsurf/mcp_config.json", "windsurf/memories",
                    "windsurf/cascade")),
    StoreSpec("cursor-app", "Cursor", "token",
              _p(win=["{APPDATA}/Cursor"],
                 darwin=["{HOME}/Library/Application Support/Cursor"],
                 linux=["{HOME}/.config/Cursor"]),
              "state.vscdb (tokens in sqlite), logs",
              scan=("User/globalStorage/state.vscdb",
                    "User/workspaceStorage", "logs")),
    StoreSpec("cursor-home", "Cursor", "config",
              _p(posix=["{HOME}/.cursor"]),
              "mcp.json with plaintext server keys"),
    StoreSpec("devin-config", "Devin", "token",
              _p(posix=["{HOME}/.config/devin"]),
              "config.json, stored credentials"),
    StoreSpec("copilot-config", "GitHub Copilot", "token",
              _p(win=["{LOCALAPPDATA}/github-copilot"],
                 posix=["{HOME}/.config/github-copilot"]),
              "apps.json / hosts.json OAuth tokens"),
    StoreSpec("vscode-global", "VS Code", "token",
              _p(win=["{APPDATA}/Code/User/globalStorage"],
                 darwin=["{HOME}/Library/Application Support/Code/User/globalStorage"],
                 linux=["{HOME}/.config/Code/User/globalStorage"]),
              "state.vscdb — extension secrets (Copilot, Cline, Roo)",
              scan=("state.vscdb", "github.copilot-chat",
                    "saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline",
                    "continue.continue", "sourcegraph.cody-ai")),
    StoreSpec("aider", "Aider", "config",
              _p(posix=["{HOME}/.aider.conf.yml", "{HOME}/.aider"]),
              "API keys in config, chat history"),
    StoreSpec("continue", "Continue.dev", "config",
              _p(posix=["{HOME}/.continue"]),
              "config.json apiKey fields, session logs"),
    StoreSpec("gemini-cli", "Gemini CLI", "token",
              _p(posix=["{HOME}/.gemini"]),
              "oauth_creds.json, google_accounts.json, settings",
              scan=("oauth_creds.json", "google_accounts.json",
                    "settings.json", "projects.json", "history")),
    StoreSpec("zed", "Zed", "config",
              _p(posix=["{HOME}/.config/zed"]),
              "settings + context DB"),

    # --- MCP configs (plaintext key hotspot) -------------------------------
    StoreSpec("mcp-cursor", "MCP", "config",
              _p(posix=["{HOME}/.cursor/mcp.json"]),
              "per-server env api keys"),
    StoreSpec("mcp-claude-desktop", "MCP", "config",
              _p(win=["{APPDATA}/Claude/claude_desktop_config.json"],
                 darwin=["{HOME}/Library/Application Support/Claude/claude_desktop_config.json"],
                 linux=["{HOME}/.config/Claude/claude_desktop_config.json"]),
              "per-server env api keys"),
    StoreSpec("mcp-windsurf", "MCP", "config",
              _p(posix=["{HOME}/.codeium/windsurf/mcp_config.json"]),
              "per-server env api keys"),
    StoreSpec("mcp-vscode", "MCP", "config",
              _p(posix=["{HOME}/.vscode/mcp.json"]),
              "per-server env api keys"),

    # --- Cloud / CLI creds --------------------------------------------------
    StoreSpec("aws", "AWS", "token",
              _p(posix=["{HOME}/.aws"]),
              "credentials, config, sso/cache tokens"),
    StoreSpec("ssh", "SSH", "key",
              _p(posix=["{HOME}/.ssh"]),
              "private keys, config tokens, known_hosts"),
    StoreSpec("kube", "Kubernetes", "token",
              _p(posix=["{HOME}/.kube"]),
              "client certs + bearer tokens in config"),
    StoreSpec("docker", "Docker", "token",
              _p(posix=["{HOME}/.docker/config.json"]),
              "base64 auth or credsStore pointer"),
    StoreSpec("netrc", "Generic", "token",
              _p(posix=["{HOME}/.netrc", "{HOME}/_netrc"]),
              "plaintext logins for ftp/curl/heroku"),
    StoreSpec("git-creds", "Git", "token",
              _p(posix=["{HOME}/.git-credentials"]),
              "plaintext https credentials"),
    StoreSpec("gh-cli", "GitHub CLI", "token",
              _p(win=["{APPDATA}/GitHub CLI/hosts.yml"],
                 posix=["{HOME}/.config/gh/hosts.yml"]),
              "oauth_token"),
    StoreSpec("gcloud", "Google Cloud", "token",
              _p(win=["{APPDATA}/gcloud"],
                 posix=["{HOME}/.config/gcloud"]),
              "access_tokens.db, credentials.db, ADC json"),
    StoreSpec("azure", "Azure", "token",
              _p(posix=["{HOME}/.azure"]),
              "msal_token_cache, accessTokens.json, service principal"),
    StoreSpec("npm", "npm", "token",
              _p(posix=["{HOME}/.npmrc"]),
              "_authToken lines"),
    StoreSpec("yarn", "Yarn", "token",
              _p(posix=["{HOME}/.yarnrc.yml", "{HOME}/.yarnrc"]),
              "npmAuthToken"),
    StoreSpec("pypi", "PyPI", "token",
              _p(posix=["{HOME}/.pypirc"]),
              "pypi-AgEI tokens"),
    StoreSpec("hf", "Hugging Face", "token",
              _p(posix=["{HOME}/.cache/huggingface/token", "{HOME}/.huggingface/token"]),
              "hf_ token"),
    StoreSpec("terraform", "Terraform", "token",
              _p(posix=["{HOME}/.terraform.d/credentials.tfrc.json"]),
              "HCP/TF Cloud tokens"),
    StoreSpec("cargo", "Cargo", "token",
              _p(posix=["{HOME}/.cargo/credentials.toml", "{HOME}/.cargo/credentials"]),
              "registry tokens"),
    StoreSpec("gem", "RubyGems", "token",
              _p(posix=["{HOME}/.gem/credentials"]),
              "rubygems_api_key"),
    StoreSpec("composer", "Composer", "token",
              _p(posix=["{HOME}/.composer/auth.json"]),
              "github-oauth/gitlab-token entries"),
    StoreSpec("maven", "Maven", "config",
              _p(posix=["{HOME}/.m2/settings.xml"]),
              "server passwords"),
    StoreSpec("gradle", "Gradle", "config",
              _p(posix=["{HOME}/.gradle/gradle.properties"]),
              "signing keys, repo credentials"),
    StoreSpec("gnupg", "GnuPG", "key",
              _p(posix=["{HOME}/.gnupg"]),
              "private keyring"),
    StoreSpec("ollama", "Ollama", "key",
              _p(posix=["{HOME}/.ollama/id_ed25519"]),
              "model-signing private key"),
    StoreSpec("configstore", "Firebase/misc CLIs", "token",
              _p(posix=["{HOME}/.config/configstore"]),
              "firebase-tools refresh tokens, misc CLI creds"),
    StoreSpec("vercel", "Vercel", "token",
              _p(posix=["{HOME}/.vercel/auth.json", "{HOME}/.local/share/com.vercel.cli/auth.json"]),
              "auth token"),
    StoreSpec("netlify", "Netlify", "token",
              _p(posix=["{HOME}/.netlify", "{HOME}/.config/netlify"]),
              "config.json auth"),
    StoreSpec("railway", "Railway", "token",
              _p(posix=["{HOME}/.railway"]),
              "config.json token"),

    # --- Cached context / history (secret-scan targets) ----------------------
    StoreSpec("pshistory", "PowerShell", "context",
              _p(win=["{APPDATA}/Microsoft/Windows/PowerShell/PSReadLine"],
                 posix=["{HOME}/.local/share/powershell/PSReadLine"]),
              "ConsoleHost_history.txt — pasted secrets persist",
              sensitive=False),
    StoreSpec("shell-history", "POSIX shells", "context",
              _p(posix=["{HOME}/.bash_history", "{HOME}/.zsh_history",
                        "{HOME}/.histfile"]),
              "commands with inline tokens persist",
              sensitive=False),
    StoreSpec("aider-history", "Aider", "context",
              _p(posix=["{HOME}/.aider.chat.history.md"]),
              "chat history", sensitive=False),
]


@dataclass
class Resolved:
    spec: StoreSpec
    path: Path
    exists: bool
    is_dir: bool = False
    size: int = 0


def _paths_for(spec, platform):
    p = spec.paths
    entries = p.get(platform)
    if entries is None and platform in ("linux", "darwin"):
        entries = p.get("posix")
    if entries is None:
        entries = p.get("posix", [])
    return entries


def discover(env=None, platform=None):
    """Resolve all registry specs -> list[Resolved] for existing paths."""
    platform = platform or platforms.PLATFORM
    out = []
    for spec in STORES:
        for raw in _paths_for(spec, platform):
            p = platforms.expand(raw, env=env, platform=platform)
            if spec.glob:
                for hit in sorted(p.parent.glob(p.name)):
                    if hit.exists():
                        out.append(_res(spec, hit))
                continue
            if p.exists():
                out.append(_res(spec, p))
    return out


def _res(spec, path):
    try:
        st = path.stat()
        return Resolved(spec, path, True, path.is_dir(), st.st_size)
    except OSError:
        return Resolved(spec, path, False)


def known_specs_for(platform=None):
    """All specs with expanded paths (existing or not) — for `paths` cmd."""
    platform = platform or platforms.PLATFORM
    rows = []
    for spec in STORES:
        for raw in _paths_for(spec, platform):
            rows.append((spec, platforms.expand(raw)))
    return rows


def context_files(resolved_list, max_files=4000, byte_budget=64 << 20):
    """Yield files under scan-target stores for secret scanning.

    Per-store byte budget, newest files first — fresh transcripts are where
    live secrets sit, and this bounds worst-case scan time. Files over
    secrets.MAX_FILE_BYTES are skipped by scan_file regardless.
    """
    for res in resolved_list:
        if res.spec.kind != "context" and res.spec.id not in _SCAN_ANYWAY:
            continue
        targets = ([res.path / s for s in res.spec.scan]
                   if res.spec.scan else [res.path])
        for target in targets:
            if not target.exists():
                continue
            files = list(_walk(target, max_files))
            files.sort(key=_mtime, reverse=True)
            spent = 0
            for f in files:
                try:
                    spent += f.stat().st_size
                except OSError:
                    continue
                if spent > byte_budget:
                    break
                yield f


# Sensitive stores also get secret-scanned (find plaintext inside token files).
_SCAN_ANYWAY = {"claude-code-config", "mcp-cursor", "mcp-claude-desktop",
                "mcp-windsurf", "mcp-vscode", "cursor-home", "windsurf-dir",
                "devin-config", "aider", "continue", "gemini-cli", "zed",
                "aws", "kube", "docker", "netrc", "git-creds", "gh-cli",
                "npm", "yarn", "pypi", "terraform", "cargo", "gem",
                "composer", "maven", "gradle", "configstore", "vercel",
                "netlify", "railway", "cursor-app", "claude-desktop",
                "vscode-global", "copilot-config"}


def sensitive_paths(resolved_list):
    """Paths that should be owner-only + watched."""
    return [r.path for r in resolved_list if r.spec.sensitive]


_SKIP_DIRS = {"node_modules", ".git", "__pycache__", "logs-old",
              # Electron/Chromium noise — can't hold secrets, pure scan cost
              "Cache", "CachedData", "CachedExtensions",
              "CachedExtensionVSIXs", "Code Cache", "GPUCache",
              "DawnWebGPUCache", "DawnGraphiteCache", "Crashpad",
              "blob_storage", "Shared Dictionary", "optimization_guide",
              "Service Worker", "Network", "File System",
              # agent/tool cache noise
              "Backups", "History", "snapshots", "checkpoints"}
_SKIP_DIRS_LOWER = {d.lower() for d in _SKIP_DIRS}


def _mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _walk(path, max_files):
    n = 0
    if path.is_file():
        yield path
        return
    stack = [path]
    while stack and n < max_files:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if n >= max_files:
                return
            try:
                if e.is_dir():
                    if (e.name.lower() not in _SKIP_DIRS_LOWER
                            and not e.name.startswith(".")):
                        stack.append(e)
                elif e.is_file():
                    n += 1
                    yield e
            except OSError:
                continue
