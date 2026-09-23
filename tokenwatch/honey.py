"""Honeytokens: fake credentials planted where infostealers look.

Planted ONLY where no real store exists (never overwrite real creds).
Every planted file is recorded in ~/.tokenwatch/honey.json so `clean`
removes exactly what we made and `status` verifies integrity.

Detection model: NO legitimate process ever reads these files, so any
watch-hit on a honey path is a zero-false-positive compromise signal.
Tokens embed a unique TWCNRY marker for attribution if they show up in
a breach dump or outbound capture.
"""
import hashlib
import json
import secrets as _sec
import time
from pathlib import Path

from . import platforms

MANIFEST = "honey.json"


def _aws_creds(token):
    return ("[default]\n"
            f"aws_access_key_id = AKIA{token[:16].upper()}\n"
            f"aws_secret_access_key = {token}/{_sec.token_hex(10)}\n")


def _env_file(token):
    return (f"OPENAI_API_KEY=sk-proj-{token}-{_sec.token_hex(16)}\n"
            f"ANTHROPIC_API_KEY=sk-ant-{token}-{_sec.token_hex(8)}\n")


def _generic_json(token):
    return json.dumps({
        "access_token": f"twcnry_{token}",
        "refresh_token": f"twcnry_r{_sec.token_hex(12)}",
        "client_id": "tokenwatch-canary",
        "expires_in": 3600}, indent=2)


def _ssh_key(token):
    body = "\n".join(_sec.token_hex(16) for _ in range(4))
    return (f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n"
            f"twcnry:{token}\n-----END OPENSSH PRIVATE KEY-----\n")


# decoy_id -> (path template, generator, description)
def decoys(env=None, platform=None):
    home = platforms.home(env)
    state = platforms.state_dir(env)
    honey_dir = state / "honey"
    return [
        ("aws-creds", home / ".aws" / "credentials", _aws_creds,
         "fake AWS credentials — only planted if ~/.aws is absent"),
        ("honey-env", honey_dir / ".env", _env_file,
         "fake .env with OpenAI+Anthropic keys"),
        ("honey-json", honey_dir / "credentials.json", _generic_json,
         "fake OAuth credential blob"),
        ("honey-ssh", honey_dir / "id_rsa_backup", _ssh_key,
         "fake SSH private key"),
        ("honey-token", honey_dir / "token.txt",
         lambda t: f"github_pat_TWCNRY{t.upper()}\n",
         "fake GitHub PAT"),
    ]


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
        if decoy_id in manifest:
            skipped.append(f"{decoy_id}: already planted at {path}")
            continue
        if path.exists():
            skipped.append(f"{decoy_id}: real file exists at {path} — "
                           "NOT overwriting")
            continue
        token = _sec.token_hex(16)
        blob = gen(token).encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)         # bytes — text mode mangles \n on win32
        try:
            if platforms.PLATFORM != "windows":
                path.chmod(0o644)      # look plausible; stealers check perms
        except OSError:
            pass
        manifest[decoy_id] = {
            "path": str(path), "sha256": hashlib.sha256(blob).hexdigest(),
            "token_marker": f"TWCNRY:{token[:8]}", "planted": time.time()}
        planted.append(f"{decoy_id}: {path}")
    _save(state, manifest)
    return planted, skipped


def status(env=None):
    """Verify each manifest entry: exists + content intact."""
    state = platforms.state_dir(env)
    manifest = _load(state)
    rows = []
    for decoy_id, m in manifest.items():
        p = Path(m["path"])
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
    for decoy_id, m in manifest.items():
        p = Path(m["path"])
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
    return [Path(m["path"]) for m in _load(platforms.state_dir(env)).values()]
