from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .evidence import EvidenceItem, EvidenceLedger

SEVERITY_WEIGHTS = {
    "info": 0.0,
    "low": 8.0,
    "medium": 18.0,
    "high": 35.0,
    "critical": 60.0,
}

VERDICTS = ("SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE")
MALICIOUS_SCORE = 65.0
SUSPICIOUS_SCORE = 25.0
SAFE_SCORE = 15.0


@dataclass
class RiskAssessment:
    verdict: str
    score: int
    confidence: float
    reasons: list[str] = field(default_factory=list)
    required_coverage: list[str] = field(default_factory=list)
    malformed: bool = False

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError("invalid verdict")
        self.score = max(0, min(100, int(self.score)))
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "risk_score": self.score,
            "confidence": round(self.confidence, 3),
            "reasons": list(self.reasons),
            "required_coverage": list(self.required_coverage),
        }


def _weighted_score(items: Sequence[EvidenceItem]) -> float:
    if not items:
        return 0.0
    weighted = sorted(
        (SEVERITY_WEIGHTS.get(item.severity, 0.0) * max(0.2, item.confidence) for item in items),
        reverse=True,
    )
    score = 0.0
    for index, value in enumerate(weighted):
        if value <= 0:
            continue
        score += value * (1.0 if index < 4 else 0.35 if index < 10 else 0.15)
    return min(100.0, score)


def _coverage_confidence(ledger: EvidenceLedger, required: Sequence[str]) -> float:
    if not required:
        return 1.0
    values = []
    for name in required:
        status = ledger.coverage_status(name)
        values.append(1.0 if status == "ok" else 0.4 if status == "partial" else 0.0)
    return sum(values) / len(values)


def assess_risk(
    ledger: EvidenceLedger,
    *,
    required_coverage: Iterable[str] = (),
    extra_reasons: Iterable[str] = (),
) -> RiskAssessment:
    required = list(dict.fromkeys(required_coverage))
    all_items = list(ledger.items)
    malformed = any(item.code == "malformed_result" for item in all_items)
    items = [item for item in all_items if item.code != "malformed_result"]
    score = _weighted_score(items)
    reasons: list[str] = []

    critical = [item for item in items if item.severity == "critical" and item.confidence >= 0.6]
    high = [item for item in items if item.severity == "high" and item.confidence >= 0.5]
    medium = [item for item in items if item.severity == "medium" and item.confidence >= 0.45]
    suspicious_codes = {
        "private_destination_blocked",
        "metadata_private_destination",
        "known_bad_hash",
        "malware_signature",
        "executable_content",
        "credential_harvesting",
        "brand_impersonation",
        "punycode_domain",
        "newly_registered_domain",
        "suspicious_redirect",
        "blocked_request",
    }
    code_hits = [item for item in items if item.code in suspicious_codes and item.severity in {"medium", "high", "critical"}]

    if critical or (high and (score >= 55 or len(high) >= 2)):
        verdict = "MALICIOUS"
        reasons.append("Critical or multiple high-confidence high-severity findings were observed.")
    elif score >= MALICIOUS_SCORE:
        verdict = "MALICIOUS"
        reasons.append("Accumulated evidence exceeded the malicious risk threshold.")
    elif score >= SUSPICIOUS_SCORE or medium or high or code_hits:
        verdict = "SUSPICIOUS"
        reasons.append("Suspicious evidence requires analyst review.")
    elif malformed:
        verdict = "INCONCLUSIVE"
        reasons.append("A security result was malformed and could not be reliably interpreted.")
    elif not ledger.all_coverage_ok(required):
        verdict = "INCONCLUSIVE"
        reasons.append("Required investigation coverage is incomplete.")
    elif score < SAFE_SCORE and not medium and not high and not critical:
        verdict = "SAFE"
        reasons.append("No meaningful threat evidence was found and required coverage completed.")
    else:
        verdict = "INCONCLUSIVE"
        reasons.append("Evidence is insufficient for a safe or malicious conclusion.")

    if any(item.code == "detector_unavailable" for item in all_items):
        if verdict == "SAFE":
            verdict = "INCONCLUSIVE"
        reasons.append("An authenticity detector was unavailable, so authenticity cannot be certified.")
    if malformed and verdict == "SAFE":
        verdict = "INCONCLUSIVE"
        reasons.append("Malformed security output prevents a safe verdict.")

    reasons.extend(text for text in extra_reasons if text)

    maximum = max((item.confidence for item in items), default=0.0)
    if verdict == "MALICIOUS":
        confidence = max(0.65, min(0.98, 0.55 + maximum * 0.35))
    elif verdict == "SUSPICIOUS":
        confidence = max(0.45, min(0.92, 0.35 + maximum * 0.4))
    elif verdict == "SAFE":
        confidence = max(0.35, min(0.95, 0.45 + _coverage_confidence(ledger, required) * 0.35))
    else:
        confidence = max(0.2, min(0.75, _coverage_confidence(ledger, required) * 0.55))

    return RiskAssessment(
        verdict=verdict,
        score=round(score),
        confidence=confidence,
        reasons=reasons,
        required_coverage=required,
        malformed=malformed,
    )
