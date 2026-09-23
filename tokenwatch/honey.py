"""Honeytokens: fake credentials planted where infostealers look.

Stealth model:
  - decoys live at REALISTIC paths (standard credential store locations,
    planted only when no real file exists — never overwrite real creds),
    plus plausible stray backups (~/.env.backup, ~/.ssh/id_rsa.bak)
  - no marker strings anywhere — the values look like ordinary keys
  - the manifest is keyed by sha256(path) and stores only content hashes,
    so ~/.tokenwatch/honey.json itself doesn't reveal decoy locations

Detection model: NO legitimate process ever reads these files, so any
watch-hit on a honey path is a zero-false-positive compromise signal.
"""
import hashlib
import json
import os
import secrets as _sec
import shutil
import time
from pathlib import Path

from . import platforms

MANIFEST = "honey.json"


def _tool_present(tool, env, runner):
    """Is `tool` installed? runner=None -> real PATH probe; injected ->
    `where`/`which` via the runner so tests control it."""
    if runner is None:
        e = env if env is not None else os.environ
        return shutil.which(tool, path=e.get("PATH") or None) is not None
    cmd = "where" if platforms.IS_WINDOWS else "which"
    rc, _, _ = platforms.run([cmd, tool], runner=runner)
    return rc == 0


def _skip_if_tool(*tools):
    """Guard factory: skip when a tool that AUTO-READS this path is
    installed — a decoy at a live path would shadow real auth (aws sdk,
    kubectl) and fire on every legitimate invocation."""
    def guard(env, runner):
        hit = next((t for t in tools if _tool_present(t, env, runner)),
                   None)
        return (f"{hit} installed — real tools auto-read this path"
                if hit else None)
    return guard


def _aws_guard(env, runner):
    r = _skip_if_tool("aws")(env, runner)
    if r:
        return r
    if (platforms.home(env) / ".aws" / "config").exists():
        return "~/.aws/config exists — env/SSO auth in use, decoy would shadow it"
    return None


def _git_guard(env, runner):
    """~/.git-credentials is only auto-read when helper=store."""
    rc, out, _ = platforms.run(
        ["git", "config", "--get", "credential.helper"],
        runner=runner)
    if rc == 0 and "store" in out.lower():
        return "credential.helper=store — git would send the decoy to hosts"
    return None


def _aws_creds(tok):
    return ("[default]\n"
            f"aws_access_key_id = AKIA{_sec.token_hex(8).upper()}\n"
            f"aws_secret_access_key = {_sec.token_hex(20)}\n")


def _hf_token(tok):
    return f"hf_{_sec.token_hex(17)}\n"


def _kube_config(tok):
    return ("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n"
            "    server: https://127.0.0.1:6443\n  name: local\n"
            "users:\n- name: admin\n  user:\n    token: "
            f"{_sec.token_hex(24)}\n")


def _env_backup(tok):
    return ("DATABASE_URL=postgres://app:secret@db.internal:5432/app\n"
            f"API_KEY={_sec.token_hex(20)}\n"
            f"OPENAI_API_KEY=sk-proj-{_sec.token_hex(24)}\n")


def _ssh_key(tok):
    body = "\n".join(_sec.token_hex(19) for _ in range(5))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n" \
           "-----END OPENSSH PRIVATE KEY-----\n"


def _git_creds(tok):
    return (f"https://deploy:{_sec.token_hex(20)}@github.com\n"
            f"https://bot:ghp_{_sec.token_hex(18)}@github.com\n")


def _passwords_txt(tok):
    return ("amazon.com   j.miller88      Kj9!mP2vxqW\n"
            f"netflix.com  j.miller88      {_sec.token_hex(8)}\n"
            f"chase.com    jmiller1988     {_sec.token_hex(10)}\n")


_SEED_WORDS = ("abandon ability able about above absent absorb abstract "
               "accident account accuse achieve acid acoustic acquire "
               "across action actor actress adapt add address adjust "
               "admit adult advance advice aerobic affair afford afraid "
               "again age agent agree ahead aim air airport aisle alarm "
               "album alcohol alert alien all alley allow almost alone "
               "alpha already also alter always amateur amazing among").split()


def _seed_phrase(tok):
    words = [_sec.choice(_SEED_WORDS) for _ in range(12)]
    return ("metamask wallet - keep offline\n"
            " ".join(words) + "\n")


def _wallet_bak(tok):
    return "\n".join(_sec.token_hex(20) for _ in range(8)) + "\n"


def _docker_cfg(tok):
    import base64
    auth = base64.b64encode(f"user:{_sec.token_hex(16)}".encode()).decode()
    return json.dumps({"auths": {"https://index.docker.io/v1/": {
        "auth": auth}}}, indent=2)


# (decoy_id, path, generator, description, guard)
# guard(env, runner) -> skip reason or None. Real store paths are only
# planted when the tool that auto-reads them isn't installed — otherwise the
# decoy both false-positives AND hijacks the tool's auth.
def decoys(env=None, platform=None):
    home = platforms.home(env)
    return [
        ("aws-creds", home / ".aws" / "credentials", _aws_creds,
         "standard AWS credential path", _aws_guard),
        ("hf-token", home / ".cache" / "huggingface" / "token", _hf_token,
         "standard HF token path", _skip_if_tool("huggingface-cli", "hf")),
        ("kube-config", home / ".kube" / "config", _kube_config,
         "standard kubeconfig path", _skip_if_tool("kubectl")),
        ("docker-cfg", home / ".docker" / "config.json", _docker_cfg,
         "standard docker auth path", _skip_if_tool("docker")),
        ("git-creds", home / ".git-credentials", _git_creds,
         "standard git credential store", _git_guard),
        ("env-backup", home / ".env.backup", _env_backup,
         "stray env backup — classic stealer glob target", None),
        ("ssh-key-bak", home / ".ssh" / "id_rsa.bak", _ssh_key,
         "stray key backup — nothing auto-reads it", None),
        ("passwords-txt", home / "passwords.txt", _passwords_txt,
         "stealer glob target — nothing legit reads it", None),
        ("seed-phrase", home / "seed_phrase.txt", _seed_phrase,
         "crypto seed backup — classic drainer target", None),
        ("wallet-bak", home / "wallet.dat.bak", _wallet_bak,
         "stray wallet backup — exfil-by-name target", None),
    ]


def _key(path):
    return hashlib.sha256(str(path).lower().encode()).hexdigest()


def _manifest_path(state_dir):
    return Path(state_dir) / MANIFEST


def _load(state_dir):
    p = _manifest_path(state_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _save(state_dir, manifest):
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    _manifest_path(state_dir).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")


def plant(env=None, platform=None, runner=None):
    """Plant all decoys. Returns (planted, skipped) lists of descriptions."""
    state = platforms.state_dir(env)
    manifest = _load(state)
    planted, skipped = [], []
    for decoy_id, path, gen, desc, guard in decoys(env, platform):
        if _key(path) in manifest:
            skipped.append(f"{decoy_id}: already planted")
            continue
        if path.exists():
            skipped.append(f"{decoy_id}: real file exists at {path} — "
                           "NOT overwriting")
            continue
        why = guard(env, runner) if guard else None
        if why:
            skipped.append(f"{decoy_id}: {why}")
            continue
        blob = gen(None).encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)         # bytes — text mode mangles \n on win32
        try:
            if platforms.PLATFORM != "windows":
                path.chmod(0o644)      # look plausible; stealers check perms
        except OSError:
            pass
        manifest[_key(path)] = {
            "id": decoy_id,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "planted": time.time()}
        planted.append(f"{decoy_id}: {path}")
    _save(state, manifest)
    return planted, skipped


def _planted_map(env):
    """decoy_id -> (path, manifest_entry) for decoys recorded as planted."""
    manifest = _load(platforms.state_dir(env))
    out = {}
    for decoy_id, path, gen, desc, _guard in decoys(env):
        m = manifest.get(_key(path))
        if m:
            out[decoy_id] = (path, m)
    return out


def status(env=None):
    """Verify each planted decoy: exists + content intact."""
    rows = []
    for decoy_id, (p, m) in _planted_map(env).items():
        if not p.exists():
            rows.append((decoy_id, str(p), "MISSING"))
            continue
        try:
            h = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            rows.append((decoy_id, str(p), "UNREADABLE"))
            continue
        rows.append((decoy_id, str(p),
                     "ARMED" if h == m["sha256"] else "TOUCHED/MODIFIED"))
    return rows


def clean(env=None):
    """Remove exactly the files we planted. Returns removed paths."""
    state = platforms.state_dir(env)
    manifest = _load(state)
    removed = []
    for decoy_id, (p, m) in _planted_map(env).items():
        try:
            if p.exists() and hashlib.sha256(
                    p.read_bytes()).hexdigest() == m["sha256"]:
                p.unlink()
                removed.append(str(p))
        except OSError:
            continue
    _save(state, {})
    return removed


def honey_paths(env=None):
    """Current planted paths — watcher flags reads on these as critical."""
    return [p for _, (p, m) in _planted_map(env).items()]
