"""Secret detection: provider regexes + entropy-gated generic assignments.

Two scan modes:
  scan_text()  — decoded text files
  scan_blob()  — raw bytes (sqlite state.vscdb, leveldb, binary caches);
                 tokens sit plaintext inside the blob

Findings NEVER carry the full secret — mask() keeps prefix…last4 for triage.
"""
import math
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 16 << 20       # 16MB — context stores get big
CHUNK = 1 << 20


# (name, compiled regex on str) — high-confidence provider formats
PROVIDER_PATTERNS = [
    ("aws-access-key",  re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret",      re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("github-token",    re.compile(r"\b(ghp|gho|ghu|ghs|ghr|ghu)_[A-Za-z0-9]{36,}\b")),
    ("github-pat",      re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("openai-key",      re.compile(r"\bsk-(?:proj-[A-Za-z0-9_-]{20,}|"
                                   r"svcacct-[A-Za-z0-9_-]{20,}|"
                                   r"[A-Za-z0-9]{40,})\b")),
    ("anthropic-key",   re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google-api",      re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("hf-token",        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("pypi-token",      re.compile(r"\bpypi-AgEI[A-Za-z0-9_-]{20,}\b")),
    ("slack-token",     re.compile(r"\bxox[baprsocde]-[A-Za-z0-9-]{10,}\b"
                                   r"|\bxapp-[A-Za-z0-9-]{10,}\b")),
    ("discord-token",   re.compile(r"\bmfa\.[A-Za-z0-9_-]{20,}\b"
                                   r"|\b[MN][A-Za-z0-9_-]{23}\."
                                   r"[A-Za-z0-9_-]{6}\."
                                   r"[A-Za-z0-9_-]{27,}\b")),
    ("filezilla-pass",  re.compile(r"(?i)<Pass(?:\s+encoding=\"plaintext\")?>"
                                   r"([^<]{6,})</Pass>")),
    ("stripe-key",      re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("npm-token",       re.compile(r"(?i)_authToken\s*=\s*([A-Za-z0-9-]{20,})")),
    ("private-key-hdr", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")),
    ("gcp-sa-key",      re.compile(r'"private_key"\s*:\s*"-----BEGIN')),
    ("bearer",          re.compile(r"(?i)bearer\s+[A-Za-z0-9._~-]{24,}")),
]

# generic "key = value" — entropy-gated to kill false positives
GENERIC_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|pass|"
    r"access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)"
    r"[\s'\"]*[:=][\s'\"]*([A-Za-z0-9_\-./+~$]{16,})")

# one cheap literal-stem pass: files with no stem skip every pattern below
_STEMS = re.compile(
    r"AKIA|gh[pousr]_|github_pat_|sk-ant-|sk-proj-|sk-svcacct-|sk-[A-Za-z0-9]"
    r"|AIza|hf_|pypi-AgEI|xox[a-z]-|xapp-|mfa\.|<Pass|[sr]k_(?:live|test)_"
    r"|[\w-]{24}\.[\w-]{6}\."          # discord 3-part token shape
    r"|eyJ|_authToken"
    r"|PRIVATE KEY|private_key|[Bb]earer|api[_-]?key|apikey|secret|token"
    r"|password|passwd|pass|access[_-]?key|auth[_-]?token|client[_-]?secret",
    re.IGNORECASE)


PLACEHOLDER_RE = re.compile(
    r"(?i)^(x+|<.*>|\$\{.*\}|\$\(.*\)|changeme|change[_-]?me|your[_-]?\w*"
    r"|example|sample|test|placeholder|dummy|none|null|todo|redacted"
    r"|insert|replace|foo|bar|xxx|zzz|0+|1+|a+|password)$")

# documented example / placeholder VALUES — excluded from provider hits too.
# (the canonical AWS docs pair AKIAIOSFODNN7EXAMPLE / wJalrXU...EXAMPLEKEY
# shows up inside sqlite blobs and configs everywhere)
KNOWN_EXAMPLES = {
    "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
}
_DOC_EXAMPLE_RE = re.compile(
    r"(?i)(example|exampl3|placeholder|notreal|not_a_real|changeme|"
    r"change[_-]?me|your[_-]?(api|key|token|secret)|insert[_-]?(key|token)"
    r"|replace[_-]?(this|me|key)|dummy[_-]?(key|token)?|x{5,})")
_SEQ_RE = re.compile(
    r"(?i)(012345|123456|234567|345678|456789|abcdef|bcdefg|cdefgh|defghi"
    r"|qwerty|asdfgh)")


def _is_example(val):
    """True for doc-example/placeholder/sequential values, not real secrets."""
    v = val.strip().strip("'\"").lower()
    if not v or v in KNOWN_EXAMPLES:
        return True
    return bool(_DOC_EXAMPLE_RE.search(v) or _SEQ_RE.search(v))

ENTROPY_MIN = 3.4               # bits/char for generic candidates


@dataclass
class SecretHit:
    pattern: str
    path: Path
    line: int          # 0 for binary/blob hits
    masked: str        # "ghp_...9f2c" — safe to display
    generic: bool = False
    fp: str = ""       # sha256[:16] of raw value — dedupe key, never shown


def mask(value):
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return v[:2] + "..." + v[-2:]
    return v[:7] + "..." + v[-4:]


def shannon(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _generic_ok(value):
    v = value.strip().strip("'\"")
    if PLACEHOLDER_RE.match(v):
        return False
    if len(set(v)) < 4:            # aaaa / 1111 / ababab
        return False
    return shannon(v) >= ENTROPY_MIN


def scan_text(text, path):
    if not _STEMS.search(text):
        return []
    import hashlib
    hits = []
    for name, rx in PROVIDER_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if _is_example(val):
                continue
            line = text.count("\n", 0, m.start()) + 1
            hits.append(SecretHit(name, Path(path), line, mask(val),
                                  fp=hashlib.sha256(
                                      val.encode()).hexdigest()[:16]))
    for m in GENERIC_RE.finditer(text):
        val = m.group(2)
        if _generic_ok(val) and not _is_example(val):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(SecretHit(f"generic:{m.group(1).lower()}", Path(path),
                                  line, mask(val), generic=True,
                                  fp=hashlib.sha256(
                                      val.encode()).hexdigest()[:16]))
    return hits


def redact(text):
    """Return text with detected secrets replaced by masked forms.

    For lines we LOG rather than scan — 4688 command lines can carry
    'curl -H "Authorization: Bearer …"', 'mysql -p…', 'git clone
    https://token@…'. alerts.jsonl must never hold the raw value."""
    if not text or not _STEMS.search(text):
        return text
    spans = []
    for name, rx in PROVIDER_PATTERNS:
        for m in rx.finditer(text):
            # group(1) is the secret for assignment-style patterns, but
            # some patterns group only a prefix alternation (ghp|gho|…)
            # — masking 3 chars would leave the token body behind
            g = (m.span(1) if m.lastindex and len(m.group(1)) > 8
                 else m.span(0))
            if not _is_example(text[g[0]:g[1]]):
                spans.append((g[0], g[1], mask(text[g[0]:g[1]])))
    for m in GENERIC_RE.finditer(text):
        val = m.group(2)
        if _generic_ok(val) and not _is_example(val):
            spans.append((m.start(2), m.end(2), mask(val)))
    if not spans:
        return text
    spans.sort()
    out, last = [], 0
    for a, b, rep in spans:
        if a < last:
            continue                     # overlap — already redacted
        out += [text[last:a], rep]
        last = b
    out.append(text[last:])
    return "".join(out)


_TEXT_EXT = {".json", ".txt", ".md", ".yml", ".yaml", ".toml", ".ini",
             ".cfg", ".conf", ".env", ".xml", ".csv", ".log", ".history",
             ".py", ".js", ".ts", ".sh", ".ps1", ".rdl", ".jsonl", ""}


def scan_file(path, max_bytes=MAX_FILE_BYTES):
    """Scan one file; binary-ish files go through the byte scanner."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0 or size > max_bytes:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if path.suffix.lower() in _TEXT_EXT and b"\x00" not in data[:8192]:
        try:
            return scan_text(data.decode("utf-8", errors="replace"), path)
        except Exception:
            return []
    return scan_blob(data, path)


def scan_blob(data, path):
    """Raw-byte scan for sqlite/leveldb/binary caches."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []
    if not _STEMS.search(text):
        return []
    import hashlib
    hits = []
    for name, rx in PROVIDER_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if _is_example(val):
                continue
            hits.append(SecretHit(name, Path(path), 0, mask(val),
                                  fp=hashlib.sha256(
                                      val.encode()).hexdigest()[:16]))
    return hits
