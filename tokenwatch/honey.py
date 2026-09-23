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
import secrets as _sec
import time
from pathlib import Path

from . import platforms

MANIFEST = "honey.json"


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


def _docker_cfg(tok):
    import base64
    auth = base64.b64encode(f"user:{_sec.token_hex(16)}".encode()).decode()
    return json.dumps({"auths": {"https://index.docker.io/v1/": {
        "auth": auth}}}, indent=2)


# (decoy_id, path, generator, description)
def decoys(env=None, platform=None):
    home = platforms.home(env)
    return [
        ("aws-creds", home / ".aws" / "credentials", _aws_creds,
         "standard AWS credential path — planted only if absent"),
        ("hf-token", home / ".cache" / "huggingface" / "token", _hf_token,
         "standard HF token path — planted only if absent"),
        ("kube-config", home / ".kube" / "config", _kube_config,
         "standard kubeconfig path — planted only if absent"),
        ("docker-cfg", home / ".docker" / "config.json", _docker_cfg,
         "standard docker auth path — planted only if absent"),
        ("git-creds", home / ".git-credentials", _git_creds,
         "standard git credential store — planted only if absent"),
        ("env-backup", home / ".env.backup", _env_backup,
         "stray env backup — classic stealer glob target"),
        ("ssh-key-bak", home / ".ssh" / "id_rsa.bak", _ssh_key,
         "stray key backup in .ssh — planted only if id_rsa.bak absent"),
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


def plant(env=None, platform=None):
    """Plant all decoys. Returns (planted, skipped) lists of descriptions."""
    state = platforms.state_dir(env)
    manifest = _load(state)
    planted, skipped = [], []
    for decoy_id, path, gen, desc in decoys(env, platform):
        if _key(path) in manifest:
            skipped.append(f"{decoy_id}: already planted")
            continue
        if path.exists():
            skipped.append(f"{decoy_id}: real file exists at {path} — "
                           "NOT overwriting")
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
    for decoy_id, path, gen, desc in decoys(env):
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
