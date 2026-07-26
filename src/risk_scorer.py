"""
Risk scoring engine.

Converts a list of `Finding` objects into:
  - a bounded 0-100 risk score
  - a verdict: SAFE / SUSPICIOUS / MALICIOUS
  - a recommended action, mirroring the project's required decision tree:
        SAFE        -> Close
        SUSPICIOUS  -> Warn User
        MALICIOUS   -> Block Domain & Escalate
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .analyzer import Finding

VERDICT_ACTIONS = {
    "SAFE": "Close",
    "SUSPICIOUS": "Warn User",
    "MALICIOUS": "Block Domain & Escalate",
}


@dataclass
class RiskResult:
    score: int
    verdict: str
    action: str
    findings: List[Finding]


def score_findings(findings: List[Finding], config: Dict) -> RiskResult:
    weights = config.get("scoring_weights", {})
    thresholds = config.get("thresholds", {"suspicious_at": 25, "malicious_at": 55})

    raw_score = 0
    seen_categories = set()
    for finding in findings:
        weight = weights.get(finding.category, 5)
        # Diminishing returns for repeated hits in the same category so one
        # noisy category (e.g. many urgency keywords) can't alone dominate.
        multiplier = 1.0 if finding.category not in seen_categories else 0.4
        raw_score += weight * multiplier
        seen_categories.add(finding.category)

    score = max(0, min(100, round(raw_score)))

    if score >= thresholds.get("malicious_at", 55):
        verdict = "MALICIOUS"
    elif score >= thresholds.get("suspicious_at", 25):
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return RiskResult(
        score=score,
        verdict=verdict,
        action=VERDICT_ACTIONS[verdict],
        findings=findings,
    )
