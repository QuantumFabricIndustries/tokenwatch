"""Channel integrity: proxy, hosts-file, and root-CA tampering.

The Muse-class play isn't only reading token files — it's redirecting agent
traffic so the tokens come to the attacker. Three checks:

  proxy   — env proxies + Windows WinINET (registry) + WinHTTP (netsh)
  hosts   — provider domains remapped in the hosts file (redirect or sinkhole)
  root CA — user-scope roots (HKCU\\Root needs no admin — classic malware
            move) and MITM-tool CAs (mitmproxy/fiddler/burp…) in machine store

All commands go through the injectable runner.
"""
import os
import re
from pathlib import Path

from . import platforms

# domains whose remap is a direct interception attempt
PROVIDER_DOMAINS = (
    "anthropic.com", "claude.ai", "openai.com", "chatgpt.com",
    "oaistatic.com", "oaiusercontent.com", "googleapis.com",
    "generativelanguage.googleapis.com", "gemini.google.com",
    "huggingface.co", "github.com", "api.github.com", "githubcopilot.com",
    "registry.npmjs.org", "npmjs.org", "pypi.org", "pythonhosted.org",
    "amazonaws.com", "azure.com", "login.microsoftonline.com",
    "cursor.sh", "codeium.com", "windsurf.com", "devin.ai",
)

MITM_CA_NAMES = re.compile(
    r"(?i)(mitmproxy|fiddler|charles|burp|portswigger|owasp|zap proxy|"
    r"proxyman|http toolkit|whistle|lightproxy|reqable|stream|"
    r"paros|weberp|ettercap)")

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                  "http_proxy", "https_proxy", "all_proxy")


def _finding(rule, path, detail):
    from .score import Finding
    return Finding(rule, path, detail)


# ------------------------------------------------------------------- proxy
def _env_proxies(env):
    return [_finding("proxy-env", f"env:{k}", env[k])
            for k in PROXY_ENV_VARS if env.get(k)]


def _wininet(runner):
    """WinINET proxy from HKCU Internet Settings — agents ride WinINET."""
    rc, out, _ = platforms.run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion"
         r"\Internet Settings"], runner=runner)
    if rc != 0:
        return []
    if not re.search(r"ProxyEnable\s+REG_DWORD\s+0x1", out):
        return []
    findings = []
    m = re.search(r"ProxyServer\s+REG_SZ\s+(\S+)", out)
    if m:
        findings.append(_finding("proxy-system", "WinINET", m.group(1)))
    m = re.search(r"AutoConfigURL\s+REG_SZ\s+(\S+)", out)
    if m:
        findings.append(_finding("proxy-system", "WinINET PAC",
                                 m.group(1)))
    if not findings:
        findings.append(_finding("proxy-system", "WinINET",
                                 "proxy enabled (value unread)"))
    return findings


def _winhttp(runner):
    rc, out, _ = platforms.run(["netsh", "winhttp", "show", "proxy"],
                               runner=runner)
    if rc != 0 or "no proxy" in out.lower():
        return []
    m = re.search(r"Proxy Server\(s\)\s*:\s*(\S+)", out)
    if m and "direct" not in m.group(1).lower():
        return [_finding("proxy-system", "WinHTTP", m.group(1))]
    return []


# ------------------------------------------------------------------- hosts
def _hosts(env, runner, platform):
    if platform == "windows":
        sysroot = env.get("SystemRoot", r"C:\Windows")
        hp = Path(sysroot) / "System32" / "drivers" / "etc" / "hosts"
    else:
        hp = Path("/etc/hosts")
    try:
        text = hp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        for name in names:
            low = name.lower().rstrip(".")
            hit = next((d for d in PROVIDER_DOMAINS
                        if low == d or low.endswith("." + d)), None)
            if hit:
                kind = ("sinkhole" if ip in ("127.0.0.1", "::1", "0.0.0.0")
                        else "redirect")
                findings.append(_finding(
                    "hosts-hijack", str(hp),
                    f"{low} -> {ip} ({kind} of {hit})"))
            elif ip not in ("127.0.0.1", "::1", "0.0.0.0",
                            "255.255.255.255"):
                findings.append(_finding(
                    "hosts-entry", str(hp), f"{low} -> {ip}"))
    return findings


# ----------------------------------------------------------------- root CA
def _certutil(store, user, runner):
    argv = ["certutil"] + (["-user"] if user else []) + ["-store", store]
    rc, out, _ = platforms.run(argv, runner=runner)
    if rc != 0:
        return ""
    return out


def _subjects(certutil_text):
    return re.findall(r"^Subject:\s*(.+)$", certutil_text, re.M)


def _root_cas(runner):
    findings = []
    # user-scope roots — writable without admin, classic malware move
    for subj in _subjects(_certutil("Root", user=True, runner=runner)):
        findings.append(_finding("user-root-ca", "HKCU\\Root", subj.strip()))
    # machine store — flag MITM-tool CA names only
    for subj in _subjects(_certutil("Root", user=False, runner=runner)):
        if MITM_CA_NAMES.search(subj):
            findings.append(_finding("proxy-root-ca", "HKLM\\Root",
                                     subj.strip()))
    return findings


def audit(env=None, runner=None, platform=None):
    """All channel checks -> list[Finding]."""
    env = env if env is not None else os.environ
    platform = platform or platforms.PLATFORM
    findings = list(_env_proxies(env))
    findings += _hosts(env, runner, platform)
    if platform == "windows":
        findings += _wininet(runner)
        findings += _winhttp(runner)
        findings += _root_cas(runner)
    return findings
