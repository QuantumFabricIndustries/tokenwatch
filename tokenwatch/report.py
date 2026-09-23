"""Report assembly: findings grouped by rule, score + verdict, text/JSON."""
import json
import platform
import time
from collections import Counter

from .score import score as _score


class Report:
    def __init__(self, target="host"):
        self.target = target
        self.findings = []          # list[Finding]
        self.inventory = []         # (owner, kind, path, exists)
        self.watch_backend = ""
        self.honey = []             # (decoy_id, path, status)
        self.ts = time.time()
        self.score = 0
        self.verdict = "HARDENED"

    def finalize(self):
        self.score, self.verdict = _score(self.findings)
        return self

    def to_json(self):
        return json.dumps({
            "tool": "tokenwatch", "target": self.target,
            "host": platform.node(), "ts": self.ts,
            "score": self.score, "verdict": self.verdict,
            "watch_backend": self.watch_backend,
            "inventory": [{"owner": o, "kind": k, "path": str(p)}
                          for o, k, p in self.inventory],
            "honey": [{"id": i, "path": p, "status": s}
                      for i, p, s in self.honey],
            "findings": [{"rule": f.rule, "path": str(f.path),
                          "detail": f.detail, "points": f.points}
                         for f in self.findings]}, indent=2)

    def to_text(self):
        out = [f"tokenwatch report - {platform.node() or self.target}",
               f"verdict: {self.verdict} (score {self.score})", ""]
        if self.inventory:
            out.append("== STORES FOUND ==")
            for owner, kind, p in self.inventory:
                out.append(f"  [{kind:7}] {owner:22} {p}")
            out.append("")
        if self.honey:
            out.append("== HONEYTOKENS ==")
            for i, p, s in self.honey:
                out.append(f"  {s:16} {i:12} {p}")
            out.append("")
        if self.watch_backend:
            out.append(f"watch backend: {self.watch_backend}")
            if "degraded" in self.watch_backend:
                out.append("  NOTE: degraded mode cannot detect reads - "
                           "writes/deletes only")
            out.append("")
        if self.findings:
            out.append("== FINDINGS ==")
            for f in sorted(self.findings, key=lambda x: -x.points):
                out.append(f"  [{f.rule:>17}] +{f.points:<3} {f.path}"
                           + (f" - {f.detail}" if f.detail else ""))
        else:
            out.append("no findings - credential surface is clean")
        counts = Counter(f.rule for f in self.findings)
        if counts:
            out += ["", "== SUMMARY =="] + [
                f"  {rule}: {n}" for rule, n in counts.most_common()]
        return "\n".join(out)
