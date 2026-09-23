"""Platform helpers: OS dispatch, injectable command runner, path expansion.

Every external command (icacls, auditpol, wevtutil, auditctl, powershell)
goes through `run()` / `Runner` so tests can inject a fake — same pattern as
rathat_shield's ADB runner.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

if IS_WINDOWS:
    PLATFORM = "windows"
elif IS_MAC:
    PLATFORM = "darwin"
elif IS_LINUX:
    PLATFORM = "linux"
else:
    PLATFORM = "posix"


class Runner:
    """Injectable subprocess wrapper. run(argv) -> (rc, stdout, stderr)."""

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.calls = []  # every argv attempted, for tests/auditing

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if self.dry_run:
            return 0, "", ""
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except (OSError, subprocess.TimeoutExpired) as ex:
            return 127, "", str(ex)


DEFAULT_RUNNER = Runner()


def run(argv, timeout=30, runner=None):
    return (runner or DEFAULT_RUNNER).run(argv, timeout=timeout)


def which(tool, runner=None):
    if runner is not None and runner is not DEFAULT_RUNNER:
        return True  # fake runner: assume tools exist
    return shutil.which(tool) is not None


def state_dir(env=None):
    """~/.tokenwatch — alerts, allowlist, honey manifest."""
    env = env if env is not None else os.environ
    base = env.get("TOKENWATCH_HOME")
    if base:
        return Path(base)
    return Path(home(env)) / ".tokenwatch"


def home(env=None):
    env = env if env is not None else os.environ
    h = env.get("USERPROFILE") or env.get("HOME")
    if h:
        return Path(h)
    return Path.home()


def expand(spec, env=None, platform=None):
    """Expand {HOME} {APPDATA} {LOCALAPPDATA} {CONFIG} tokens + ~ in a spec."""
    env = env if env is not None else os.environ
    platform = platform or PLATFORM
    h = str(home(env))
    if platform == "windows":
        appdata = env.get("APPDATA", h + "\\AppData\\Roaming")
        local = env.get("LOCALAPPDATA", h + "\\AppData\\Local")
        config = appdata
    elif platform == "darwin":
        appdata = local = h + "/Library/Application Support"
        config = h + "/.config"
    else:
        appdata = local = env.get("XDG_CONFIG_HOME", h + "/.config")
        config = env.get("XDG_CONFIG_HOME", h + "/.config")
    out = spec.replace("{HOME}", h).replace("~", h)
    out = out.replace("{APPDATA}", appdata)
    out = out.replace("{LOCALAPPDATA}", local)
    out = out.replace("{CONFIG}", config)
    return Path(out)


def is_admin(runner=None):
    """Best-effort elevated-privilege check."""
    if IS_WINDOWS:
        rc, out, _ = run(["net", "session"], runner=runner)
        return rc == 0
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
