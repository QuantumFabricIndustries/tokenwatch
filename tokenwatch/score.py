"""Findings -> weighted score -> verdict.

Verdicts: HARDENED <20 · EXPOSED 20-49 · HIGH RISK 50-79 · COMPROMISED 80+.
A honeytoken touch or confirmed unauthorized read forces COMPROMISED —
that's an observed theft attempt, not a posture gap.
"""
from dataclasses import dataclass, field

VERDICTS = [(0, "HARDENED"), (20, "EXPOSED"), (50, "HIGH RISK"),
            (80, "COMPROMISED")]

RULE_WEIGHTS = {
    # posture gaps (audit)
    "perm-loose-file":     40,
    "perm-loose-dir":      30,
    "perm-acl-foreign":    40,
    "plaintext-token":     25,   # secret inside a sensitive store (at rest)
    "mcp-plaintext-key":   30,
    "context-secret":      35,   # secret leaked into transcripts/history
    "env-secret":           5,   # API key in process env — inherited widely
    "honey-missing":       10,
    # observed events (watch)
    "unauthorized-read":   50,
    "unauthorized-write":  60,
    "perm-change":         70,
    "honeytoken-read":    100,
}

FORCE_COMPROMISED = {"honeytoken-read", "unauthorized-read",
                     "perm-change", "unauthorized-write"}

# per-rule caps so one noisy rule can't dominate
RULE_CAPS = {"plaintext-token": 60, "context-secret": 70,
             "perm-loose-file": 80, "perm-acl-foreign": 80}


@dataclass
class Finding:
    rule: str
    path: str
    detail: str = ""
    points: int = 0

    def __post_init__(self):
        if not self.points:
            self.points = RULE_WEIGHTS.get(self.rule, 10)


def score(findings):
    """list[Finding] -> (total, verdict)."""
    by_rule = {}
    for f in findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + f.points
    total = sum(min(pts, RULE_CAPS.get(rule, pts))
                for rule, pts in by_rule.items())
    forced = any(f.rule in FORCE_COMPROMISED for f in findings)
    verdict = "COMPROMISED" if forced else next(
        name for hi, name in reversed(VERDICTS) if total >= hi)
    return total, verdict
