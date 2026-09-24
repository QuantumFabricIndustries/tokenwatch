"""Registry of credential + cached-context stores for AI agents, dev tools,
and the classic infostealer targets (browsers, messaging, wallets, OS cred
infrastructure).

Each StoreSpec describes where a class of secrets lives per-OS. `discover()`
resolves specs against an env map (injectable for tests) and returns the
stores that actually exist on disk.

kind:    token | key | config | context
sensitive: True  -> must be owner-only (perm-enforced, watch target)
           False -> context/history (secret-scan target, perm findings are
                    informational since some tools ship loose defaults)
glob:    True  -> path entries are glob patterns (any segment may contain *),
                    resolved to concrete existing paths at discover() time.
                    New profiles created later need a re-run/re-install.

Stealer-facing specs point at the SENSITIVE FILES (Login Data, Cookies,
Local State, leveldb dirs) rather than the whole profile dir — a SACL on
e.g. Chrome's entire "User Data" would drown the Security log in cache
writes. Legit readers are allowlisted per-process in watch.DEFAULT_ALLOW.
"""
import fnmatch
import glob as _glob
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

    # --- Newer agent tooling (auth.json / config trees) ---------------------
    StoreSpec("opencode", "OpenCode", "token",
              _p(posix=["{HOME}/.local/share/opencode",
                        "{HOME}/.config/opencode"]),
              "auth.json OAuth tokens, sessions"),
    StoreSpec("goose", "Block Goose", "token",
              _p(posix=["{HOME}/.config/goose"]),
              "profiles + provider keys"),
    StoreSpec("amp", "Sourcegraph Amp", "token",
              _p(posix=["{HOME}/.config/amp"]),
              "api key, secrets.json"),
    StoreSpec("factory", "Factory Droid", "token",
              _p(posix=["{HOME}/.factory"]),
              "auth tokens, settings"),
    StoreSpec("qwen-code", "Qwen Code", "token",
              _p(posix=["{HOME}/.qwen"]),
              "oauth_creds.json, settings"),
    StoreSpec("kiro", "Kiro", "token",
              _p(posix=["{HOME}/.kiro"]),
              "auth tokens, MCP configs"),

    # --- Browser credential stores (top infostealer target) -----------------
    # Cookies + Local State together = DPAPI key + session cookies =
    # MFA-immune account replay. File-level specs: watching the whole
    # "User Data" dir would flood the Security log with cache writes.
    StoreSpec("chrome-secrets", "Chrome", "token",
              _p(win=["{LOCALAPPDATA}/Google/Chrome/User Data/Local State",
                      "{LOCALAPPDATA}/Google/Chrome/User Data/*/Login Data",
                      "{LOCALAPPDATA}/Google/Chrome/User Data/*/Web Data",
                      "{LOCALAPPDATA}/Google/Chrome/User Data/*/Cookies",
                      "{LOCALAPPDATA}/Google/Chrome/User Data/*/Network/Cookies"],
                 darwin=["{HOME}/Library/Application Support/Google/Chrome/Local State",
                         "{HOME}/Library/Application Support/Google/Chrome/*/Login Data",
                         "{HOME}/Library/Application Support/Google/Chrome/*/Cookies"],
                 linux=["{HOME}/.config/google-chrome/Local State",
                        "{HOME}/.config/google-chrome/*/Login Data",
                        "{HOME}/.config/google-chrome/*/Web Data",
                        "{HOME}/.config/google-chrome/*/Cookies",
                        "{HOME}/.config/google-chrome/*/Network/Cookies"]),
              "Local State (DPAPI key), Login Data, session cookies",
              glob=True),
    StoreSpec("edge-secrets", "Edge", "token",
              _p(win=["{LOCALAPPDATA}/Microsoft/Edge/User Data/Local State",
                      "{LOCALAPPDATA}/Microsoft/Edge/User Data/*/Login Data",
                      "{LOCALAPPDATA}/Microsoft/Edge/User Data/*/Web Data",
                      "{LOCALAPPDATA}/Microsoft/Edge/User Data/*/Cookies",
                      "{LOCALAPPDATA}/Microsoft/Edge/User Data/*/Network/Cookies"],
                 darwin=["{HOME}/Library/Application Support/Microsoft Edge/Local State",
                         "{HOME}/Library/Application Support/Microsoft Edge/*/Login Data",
                         "{HOME}/Library/Application Support/Microsoft Edge/*/Cookies"],
                 linux=["{HOME}/.config/microsoft-edge/Local State",
                        "{HOME}/.config/microsoft-edge/*/Login Data",
                        "{HOME}/.config/microsoft-edge/*/Cookies"]),
              "Local State (DPAPI key), Login Data, session cookies",
              glob=True),
    StoreSpec("brave-secrets", "Brave", "token",
              _p(win=["{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/Local State",
                      "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/*/Login Data",
                      "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/*/Cookies",
                      "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/*/Network/Cookies"],
                 darwin=["{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Local State",
                         "{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/*/Login Data",
                         "{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/*/Cookies"],
                 linux=["{HOME}/.config/BraveSoftware/Brave-Browser/Local State",
                        "{HOME}/.config/BraveSoftware/Brave-Browser/*/Login Data",
                        "{HOME}/.config/BraveSoftware/Brave-Browser/*/Cookies"]),
              "Local State (DPAPI key), Login Data, session cookies",
              glob=True),
    StoreSpec("chromium-secrets", "Chromium", "token",
              _p(win=["{LOCALAPPDATA}/Chromium/User Data/Local State",
                      "{LOCALAPPDATA}/Chromium/User Data/*/Login Data",
                      "{LOCALAPPDATA}/Chromium/User Data/*/Cookies"],
                 darwin=["{HOME}/Library/Application Support/Chromium/Local State",
                         "{HOME}/Library/Application Support/Chromium/*/Login Data"],
                 linux=["{HOME}/.config/chromium/Local State",
                        "{HOME}/.config/chromium/*/Login Data",
                        "{HOME}/.config/chromium/*/Cookies"]),
              "Local State, Login Data, cookies", glob=True),
    StoreSpec("opera-secrets", "Opera", "token",
              _p(win=["{APPDATA}/Opera Software/Opera*/Local State",
                      "{APPDATA}/Opera Software/Opera*/Login Data",
                      "{APPDATA}/Opera Software/Opera*/Cookies",
                      "{APPDATA}/Opera Software/Opera*/Network/Cookies"],
                 darwin=["{HOME}/Library/Application Support/com.operasoftware.Opera*/Local State",
                         "{HOME}/Library/Application Support/com.operasoftware.Opera*/Login Data"],
                 linux=["{HOME}/.config/opera*/Local State",
                        "{HOME}/.config/opera*/Login Data",
                        "{HOME}/.config/opera*/Cookies"]),
              "Local State, Login Data, cookies", glob=True),
    StoreSpec("firefox-secrets", "Firefox", "token",
              _p(win=["{APPDATA}/Mozilla/Firefox/Profiles/*/logins.json",
                      "{APPDATA}/Mozilla/Firefox/Profiles/*/key4.db",
                      "{APPDATA}/Mozilla/Firefox/Profiles/*/cookies.sqlite"],
                 darwin=["{HOME}/Library/Application Support/Firefox/Profiles/*/logins.json",
                         "{HOME}/Library/Application Support/Firefox/Profiles/*/key4.db",
                         "{HOME}/Library/Application Support/Firefox/Profiles/*/cookies.sqlite"],
                 linux=["{HOME}/.mozilla/firefox/*/logins.json",
                        "{HOME}/.mozilla/firefox/*/key4.db",
                        "{HOME}/.mozilla/firefox/*/cookies.sqlite"]),
              "key4.db (master key) + logins.json, session cookies",
              glob=True),
    StoreSpec("thunderbird-secrets", "Thunderbird", "token",
              _p(win=["{APPDATA}/Thunderbird/Profiles/*/logins.json",
                      "{APPDATA}/Thunderbird/Profiles/*/key4.db"],
                 darwin=["{HOME}/Library/Thunderbird/Profiles/*/logins.json",
                         "{HOME}/Library/Thunderbird/Profiles/*/key4.db"],
                 linux=["{HOME}/.thunderbird/*/logins.json",
                        "{HOME}/.thunderbird/*/key4.db"]),
              "mailbox credentials", glob=True),

    # --- Browser crypto-wallet extensions (drainer targets) -----------------
    StoreSpec("wallet-ext", "Wallet extensions", "token",
              _p(win=["{LOCALAPPDATA}/Google/Chrome/User Data/*/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                      "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/*/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                      "{LOCALAPPDATA}/Microsoft/Edge/User Data/*/Local Extension Settings/ejbalbakoplchlghecdalmeeeajnimhm",
                      "{LOCALAPPDATA}/Google/Chrome/User Data/*/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",
                      "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data/*/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa"],
                 darwin=["{HOME}/Library/Application Support/Google/Chrome/*/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],
                 linux=["{HOME}/.config/google-chrome/*/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"]),
              "MetaMask/Phantom encrypted vault leveldb", glob=True),

    # --- Windows credential infrastructure ---------------------------------
    # Legit DPAPI/CredMan access flows through lsass/vaultsvc on modern
    # Windows — a user process reading these files directly IS the tell.
    StoreSpec("win-cred-infra", "Windows cred infra", "key",
              _p(win=["{APPDATA}/Microsoft/Protect",
                      "{APPDATA}/Microsoft/Credentials",
                      "{LOCALAPPDATA}/Microsoft/Credentials",
                      "{LOCALAPPDATA}/Microsoft/Vault"]),
              "DPAPI master keys, Credential Manager, vault — decrypts "
              "everything above"),

    # --- Messaging / session tokens -----------------------------------------
    StoreSpec("discord-tokens", "Discord", "token",
              _p(win=["{APPDATA}/discord*/Local Storage/leveldb"],
                 darwin=["{HOME}/Library/Application Support/discord*/Local Storage/leveldb"],
                 linux=["{HOME}/.config/discord*/Local Storage/leveldb"]),
              "auth tokens in leveldb (stable/canary/ptb)", glob=True),
    StoreSpec("slack-tokens", "Slack", "token",
              _p(win=["{APPDATA}/Slack/Local Storage/leveldb"],
                 darwin=["{HOME}/Library/Application Support/Slack/Local Storage/leveldb"],
                 linux=["{HOME}/.config/Slack/Local Storage/leveldb"]),
              "xoxc tokens + xoxd cookies in leveldb"),
    StoreSpec("telegram-tdata", "Telegram", "token",
              _p(win=["{APPDATA}/Telegram Desktop/tdata"],
                 darwin=["{HOME}/Library/Application Support/Telegram Desktop/tdata"],
                 linux=["{HOME}/.local/share/TelegramDesktop/tdata"]),
              "session keys — full account takeover"),
    StoreSpec("signal-keys", "Signal", "key",
              _p(win=["{APPDATA}/Signal/config.json"],
                 darwin=["{HOME}/Library/Application Support/Signal/config.json"],
                 linux=["{HOME}/.config/Signal/config.json"]),
              "sqlcipher db decryption key"),

    # --- Password managers ---------------------------------------------------
    StoreSpec("bitwarden", "Bitwarden", "key",
              _p(win=["{APPDATA}/Bitwarden"],
                 darwin=["{HOME}/Library/Application Support/Bitwarden"],
                 linux=["{HOME}/.config/Bitwarden"]),
              "encrypted vault (data.json) — stolen for offline crack"),
    StoreSpec("1password", "1Password", "key",
              _p(win=["{LOCALAPPDATA}/1Password", "{APPDATA}/1Password"],
                 darwin=["{HOME}/Library/Group Containers/2BUA8C4S2C.com.1password"],
                 linux=["{HOME}/.config/1Password"]),
              "vault blobs + session material"),

    # --- Crypto wallets -------------------------------------------------------
    StoreSpec("exodus-wallet", "Exodus", "key",
              _p(win=["{APPDATA}/Exodus"],
                 darwin=["{HOME}/Library/Application Support/Exodus"],
                 linux=["{HOME}/.config/Exodus"]),
              "exodus.wallet seed vault"),
    StoreSpec("electrum-wallet", "Electrum", "key",
              _p(win=["{APPDATA}/Electrum"],
                 posix=["{HOME}/.electrum"]),
              "wallets + seed"),
    StoreSpec("bitcoin-wallet", "Bitcoin Core", "key",
              _p(win=["{APPDATA}/Bitcoin"],
                 darwin=["{HOME}/Library/Application Support/Bitcoin"],
                 linux=["{HOME}/.bitcoin"]),
              "wallet.dat"),
    StoreSpec("ethereum-keystore", "Ethereum", "key",
              _p(win=["{APPDATA}/Ethereum/keystore"],
                 linux=["{HOME}/.ethereum/keystore"]),
              "UTC/JSON keystores"),
    StoreSpec("solana-keypair", "Solana", "key",
              _p(posix=["{HOME}/.config/solana/id.json"]),
              "plaintext byte-array keypair"),

    # --- File transfer / remote access (plaintext cred stores) ----------------
    StoreSpec("filezilla", "FileZilla", "token",
              _p(win=["{APPDATA}/FileZilla"],
                 posix=["{HOME}/.config/filezilla", "{HOME}/.filezilla"]),
              "sitemanager.xml / recentservers.xml — plaintext passwords",
              scan=("sitemanager.xml", "recentservers.xml")),
    StoreSpec("winscp", "WinSCP", "token",
              _p(win=["{APPDATA}/WinSCP.ini"]),
              "stored session passwords (obfuscated)"),
    StoreSpec("mremote", "mRemoteNG", "token",
              _p(win=["{APPDATA}/mRemoteNG"]),
              "confCons.xml connection credentials"),
    StoreSpec("openvpn", "OpenVPN", "token",
              _p(win=["{HOME}/OpenVPN/config"],
                 posix=["{HOME}/.config/openvpn"]),
              "profiles with embedded auth"),
    StoreSpec("anydesk", "AnyDesk", "token",
              _p(win=["{APPDATA}/AnyDesk"],
                 posix=["{HOME}/.anydesk"]),
              "service.conf, connection auth tokens"),
    StoreSpec("teamviewer", "TeamViewer", "token",
              _p(win=["{APPDATA}/TeamViewer"],
                 posix=["{HOME}/.config/teamviewer"]),
              "connection IDs + auth"),

    # --- Misc plaintext-cred files stealers glob for ---------------------------
    StoreSpec("nuget", "NuGet", "token",
              _p(win=["{APPDATA}/NuGet/NuGet.Config"],
                 posix=["{HOME}/.nuget/NuGet/NuGet.Config",
                        "{HOME}/.config/NuGet/NuGet.Config"]),
              "plaintext package-source apikeys"),
    StoreSpec("pgpass", "PostgreSQL", "token",
              _p(win=["{APPDATA}/postgresql/pgpass.conf"],
                 posix=["{HOME}/.pgpass"]),
              "plaintext db passwords"),
    StoreSpec("mysql-cnf", "MySQL", "token",
              _p(posix=["{HOME}/.my.cnf"]),
              "plaintext db passwords"),
    StoreSpec("s3cmd", "s3cmd", "token",
              _p(posix=["{HOME}/.s3cfg"]),
              "access_key/secret_key plaintext"),
    StoreSpec("boto", "gsutil/boto", "token",
              _p(posix=["{HOME}/.boto"]),
              "aws_secret_access_key plaintext"),
    StoreSpec("rclone", "rclone", "token",
              _p(win=["{APPDATA}/rclone/rclone.conf"],
                 posix=["{HOME}/.config/rclone/rclone.conf"]),
              "cloud storage creds (obscured, reversible)"),
    StoreSpec("tokenreplay-graph", "tokenreplay", "config",
              _p(posix=["{HOME}/.tokenreplay/graph.json"]),
              "Entra app credential with AuditLog.Read.All - reads every "
              "sign-in in the tenant; must hold cert_thumbprint or a DPAPI "
              "blob, never a plaintext client_secret"),
    StoreSpec("doctl", "DigitalOcean", "token",
              _p(posix=["{HOME}/.config/doctl/config.yaml"]),
              "access-token dop_v1_ plaintext"),
    StoreSpec("ngrok", "ngrok", "token",
              _p(win=["{HOME}/.ngrok2/ngrok.yml", "{LOCALAPPDATA}/ngrok"],
                 posix=["{HOME}/.ngrok2/ngrok.yml",
                        "{HOME}/.config/ngrok/ngrok.yml"]),
              "authtoken plaintext"),
    StoreSpec("svn-auth", "Subversion", "token",
              _p(win=["{APPDATA}/Subversion/auth"],
                 posix=["{HOME}/.subversion/auth"]),
              "cached realm credentials"),
    StoreSpec("steam-session", "Steam", "token",
              _p(win=["{PF86}/Steam/config", "{PF86}/Steam/ssfn*"],
                 darwin=["{HOME}/Library/Application Support/Steam/config"],
                 linux=["{HOME}/.steam/steam/config",
                        "{HOME}/.local/share/Steam/config"]),
              "ssfn auth files + loginusers config", glob=True),
    StoreSpec("jetbrains-creds", "JetBrains", "key",
              _p(win=["{APPDATA}/JetBrains/*/c.kdbx"],
                 darwin=["{HOME}/Library/Application Support/JetBrains/*/c.kdbx"],
                 linux=["{HOME}/.config/JetBrains/*/c.kdbx"]),
              "IDE credential KeePass db", glob=True),
    StoreSpec("postman", "Postman", "token",
              _p(win=["{APPDATA}/Postman/Local Storage/leveldb",
                      "{APPDATA}/Postman/IndexedDB"],
                 darwin=["{HOME}/Library/Application Support/Postman/Local Storage/leveldb"],
                 linux=["{HOME}/.config/Postman/Local Storage/leveldb"]),
              "API tokens in leveldb/IndexedDB"),
    StoreSpec("insomnia", "Insomnia", "token",
              _p(win=["{APPDATA}/Insomnia/Local Storage/leveldb"],
                 darwin=["{HOME}/Library/Application Support/Insomnia/Local Storage/leveldb"],
                 linux=["{HOME}/.config/Insomnia/Local Storage/leveldb"]),
              "API tokens in leveldb"),
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
                # glob.glob handles '*' in ANY segment (profile dirs);
                # Path.parent.glob only works on the final component
                for hit in sorted(_glob.glob(str(p))):
                    hp = Path(hit)
                    if hp.exists():
                        out.append(_res(spec, hp))
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
            rows.append((spec, platforms.expand(raw, platform=platform)))
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
_SCAN_ANYWAY = {"codex-dir", "claude-code-config", "mcp-cursor",
                "mcp-claude-desktop",
                "mcp-windsurf", "mcp-vscode", "cursor-home", "windsurf-dir",
                "devin-config", "aider", "continue", "gemini-cli", "zed",
                "aws", "kube", "docker", "netrc", "git-creds", "gh-cli",
                "npm", "yarn", "pypi", "terraform", "cargo", "gem",
                "composer", "maven", "gradle", "configstore", "vercel",
                "netlify", "railway", "cursor-app", "claude-desktop",
                "vscode-global", "copilot-config",
                "opencode", "goose", "amp", "factory", "qwen-code", "kiro",
                "discord-tokens", "slack-tokens", "filezilla", "winscp",
                "mremote", "pgpass", "mysql-cnf", "s3cmd", "boto", "rclone",
                "doctl", "ngrok", "nuget", "postman", "insomnia",
                "tokenreplay-graph"}


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
