"""Findings -> weighted score -> verdict.

Verdicts: HARDENED <20 · EXPOSED 20-49 · HIGH RISK 50-79 · COMPROMISED 80+.
A honeytoken touch or confirmed unauthorized access forces COMPROMISED —
that's an observed theft attempt, not a posture gap.

`stored-session` (secrets in files whose PURPOSE is credential storage —
oauth_creds.json, auth.json, state.vscdb, .aws/credentials) is scored low:
expected storage is posture, not a leak. Clean machines can reach HARDENED.

Per-rule caps keep one noisy rule from dominating; the report surfaces raw
vs effective points so caps are never silent.
"""
from dataclasses import dataclass, field

VERDICTS = [(0, "HARDENED"), (20, "EXPOSED"), (50, "HIGH RISK"),
            (80, "COMPROMISED")]

RULE_WEIGHTS = {
    # posture gaps (audit)
    "stored-session":       5,   # expected credential storage at rest
    "perm-loose-file":     40,
    "perm-loose-dir":      30,
    "perm-acl-foreign":    40,
    "plaintext-token":     25,   # secret where it doesn't belong
    "mcp-plaintext-key":   30,
    "repo-secret":         40,   # .env tracked by / not ignored by git
    "context-secret":      35,   # secret leaked into transcripts/history
    "env-secret":           5,   # API key in process env — inherited widely
    # channel integrity (proxy / hosts / root-CA tampering)
    "proxy-env":           15,
    "proxy-system":        30,
    "hosts-entry":          5,   # custom non-provider mapping (review)
    "hosts-hijack":        60,   # provider domain remapped
    "user-root-ca":        50,   # user-scope root CA — no admin needed
    "proxy-root-ca":       60,   # MITM-tool CA in machine root store
    "honey-missing":       10,
    # observed events (watch)
    "unauthorized-read":   50,
    "unauthorized-write":  60,
    "perm-change":         70,
    "honeytoken-read":    100,
    # housekeeping signals
    "sacl-reapply":        10,   # audit rule vanished — atomic rewrite or
                               # tamper; a signal, not proof of theft
    "debug-launch":        80,   # browser w/ debug-port+headless spawned
                               # by a non-shell parent (DevTools cookie
                               # extraction — ABE-era stealer playbook)
}

FORCE_COMPROMISED = {"honeytoken-read", "unauthorized-read",
                     "perm-change", "unauthorized-write", "debug-launch"}

# per-rule caps so one noisy rule can't dominate
RULE_CAPS = {"plaintext-token": 60, "context-secret": 70,
             "perm-loose-file": 80, "perm-acl-foreign": 80,
             "stored-session": 20, "repo-secret": 80, "hosts-entry": 15}


@dataclass
class Finding:
    rule: str
    path: str
    detail: str = ""
    points: int = 0

    def __post_init__(self):
        if not self.points:
            self.points = RULE_WEIGHTS.get(self.rule, 10)


@dataclass
class ScoreResult:
    total: int
    verdict: str
    forced: bool
    # rule -> {"count": int, "raw": int, "effective": int}
    rules: dict = field(default_factory=dict)


def score_detail(findings):
    """Full scoring breakdown — raw vs cap-limited points per rule."""
    rules = {}
    for f in findings:
        r = rules.setdefault(f.rule, {"count": 0, "raw": 0})
        r["count"] += 1
        r["raw"] += f.points
    total = 0
    for rule, r in rules.items():
        r["effective"] = min(r["raw"], RULE_CAPS.get(rule, r["raw"]))
        total += r["effective"]
    forced = any(f.rule in FORCE_COMPROMISED for f in findings)
    verdict = "COMPROMISED" if forced else next(
        name for hi, name in reversed(VERDICTS) if total >= hi)
    return ScoreResult(total, verdict, forced, rules)


def score(findings):
    """Compat wrapper -> (total, verdict)."""
    d = score_detail(findings)
    return d.total, d.verdict
