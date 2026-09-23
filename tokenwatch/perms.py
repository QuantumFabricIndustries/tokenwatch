"""Permission audit + lockdown for credential stores.

POSIX:   sensitive files must be 600, dirs 700 (no group/other bits).
Windows: parse `icacls` output — flag any trustee outside
         {owner, SYSTEM, Administrators} holding read-or-more.
All icacls/chmod calls go through the injectable runner.
"""
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from . import platforms

# Windows trustees that must NOT hold read on a credential store
BAD_TRUSTEES = re.compile(
    r"(?i)^(everyone|builtin\\users|nt authority\\authenticated users|"
    r"authenticated users|.*\\domain users|users|null|guests?)$")

# Always-expected trustees — not findings
OK_TRUSTEES = re.compile(
    r"(?i)^(nt authority\\system|builtin\\administrators|.*\\administrators"
    r"|nt service\\trustedinstaller|creator owner|application package"
    r"|.*\\restricted|s-1-\d[\d-]*)$")

_READ_RIGHTS = {"F", "M", "R", "RX", "RA", "RC", "REA", "X", "WD", "RD"}


@dataclass
class PermIssue:
    path: Path
    detail: str
    fixable: bool = True


# ------------------------------------------------------------------- POSIX
def _posix_issue(path):
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    is_dir = path.is_dir()
    if is_dir:
        if mode & 0o077:
            return PermIssue(path, f"dir mode {mode:04o} — group/other access")
    elif mode & 0o077:
        return PermIssue(path, f"file mode {mode:04o} — group/other access")
    return None


def _posix_fix(path, runner=None):
    """chmod 700 dir / 600 file. Returns action string or None."""
    target = 0o700 if path.is_dir() else 0o600
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode == target:
        return None
    if runner is None or not runner.dry_run:
        os.chmod(path, target)
    return f"chmod {target:o} {path}"


# ----------------------------------------------------------------- Windows
_ICACLS_LINE = re.compile(r"^\s*([^:(]+?):\s*(?:\((\w+)\))?\(([\w,()]+)\)\s*$")


def parse_icacls(output, owner_hint=""):
    """icacls stdout -> list of (trustee, rights-str) tuples."""
    grants = []
    for line in output.splitlines():
        m = _ICACLS_LINE.match(line)
        if not m:
            continue
        trustee = m.group(1).strip()
        rights = re.findall(r"\(([\w,]+)\)", line)
        rights = ",".join(rights[1:]) if len(rights) > 1 else (rights[0] if rights else "")
        grants.append((trustee, rights.upper()))
    return grants


def _windows_issues(path, env=None, runner=None):
    rc, out, err = platforms.run(["icacls", str(path)], runner=runner)
    if rc != 0:
        return [PermIssue(path, f"icacls failed: {err.strip() or rc}",
                          fixable=False)]
    env = env if env is not None else os.environ
    owner = env.get("USERNAME", "").lower()
    userdom = (env.get("USERDOMAIN", "") + "\\" +
               env.get("USERNAME", "")).strip("\\").lower()
    issues = []
    for trustee, rights in parse_icacls(out):
        t = trustee.lower()
        if t == owner or t == userdom or OK_TRUSTEES.match(trustee):
            continue
        if BAD_TRUSTEES.match(trustee):
            issues.append(PermIssue(
                path, f"ACL: '{trustee}' holds rights ({rights or '?'})"))
    return issues


def _windows_fix(path, env=None, runner=None):
    """Strip inheritance; grant owner+SYSTEM+Administrators only."""
    env = env if env is not None else os.environ
    user = env.get("USERDOMAIN", "") + "\\" + env.get("USERNAME", "")
    user = user.strip("\\") or env.get("USERNAME", "")
    argv = ["icacls", str(path), "/inheritance:r",
            "/grant:r", f"{user}:(OI)(CI)F",
            "/grant:r", "SYSTEM:(OI)(CI)F",
            "/grant:r", "Administrators:(OI)(CI)F"]
    rc, _, err = platforms.run(argv, runner=runner)
    if rc != 0:
        return f"icacls FAILED {path}: {err.strip() or rc}"
    return f"icacls lockdown {path}"


# -------------------------------------------------------------------- API
def audit_path(path, platform=None, env=None, runner=None):
    """Return list[PermIssue] for a file or dir (non-recursive)."""
    platform = platform or platforms.PLATFORM
    path = Path(path)
    if not path.exists():
        return []
    if platform == "windows":
        return _windows_issues(path, env=env, runner=runner)
    iss = _posix_issue(path)
    return [iss] if iss else []


def lockdown(path, platform=None, env=None, runner=None):
    """Fix permissions. Returns action description or None."""
    platform = platform or platforms.PLATFORM
    path = Path(path)
    if not path.exists():
        return None
    if platform == "windows":
        return _windows_fix(path, env=env, runner=runner)
    return _posix_fix(path, runner=runner)
