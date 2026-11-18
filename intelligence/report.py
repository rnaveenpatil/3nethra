from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .evidence import EvidenceLedger, safe_text, safe_value
from .risk_score import RiskAssessment

VERDICT_DESCRIPTIONS = {
    "SAFE": "No meaningful threat evidence was detected within completed coverage.",
    "SUSPICIOUS": "Suspicious indicators were found and analyst review is recommended.",
    "MALICIOUS": "High-confidence malicious indicators were detected.",
    "INCONCLUSIVE": "Evidence is insufficient or investigation coverage is incomplete.",
}

RECOMMENDATIONS = {
    "SAFE": [
        "Treat this result as limited to the checks that completed.",
        "Re-run the investigation if the target changes or new intelligence becomes available.",
    ],
    "SUSPICIOUS": [
        "Do not open or execute the target until a human analyst reviews the evidence.",
        "Submit the target to organizational security controls for further examination.",
        "Preserve the collected artifacts and evidence identifiers.",
    ],
    "MALICIOUS": [
        "Block the target immediately using organizational security controls.",
        "Do not open or execute the target on any host.",
        "Preserve evidence and notify the security incident response process.",
        "Hunt for prior access to the target across affected environments.",
    ],
    "INCONCLUSIVE": [
        "Do not treat this target as safe.",
        "Complete missing coverage or retry with an available sandbox and detector.",
        "Escalate to a human analyst for manual review.",
    ],
}


@dataclass
class InvestigationReport:
    report_id: str
    target: str
    target_type: str
    status: str
    verdict: str
    risk_score: int
    confidence: float
    summary: str
    started_at: str
    completed_at: str
    assessment: RiskAssessment
    ledger: EvidenceLedger
    threats: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    sandbox_sessions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    report_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report_version,
            "report_id": self.report_id,
            "target": safe_text(self.target, 2048),
            "target_type": self.target_type,
            "status": self.status,
            "verdict": self.verdict,
            "risk_score": int(self.risk_score),
            "confidence": round(float(self.confidence), 3),
            "summary": safe_text(self.summary, 8000),
            "verdict_description": VERDICT_DESCRIPTIONS.get(self.verdict, ""),
            "reasons": list(self.assessment.reasons),
            "threats": safe_value(self.threats),
            "recommendations": [safe_text(item, 1024) for item in self.recommendations],
            "evidence": [item.to_dict() for item in self.ledger.items],
            "steps": [step.to_dict() for step in self.ledger.steps],
            "coverage": [record.to_dict() for record in self.ledger.coverage.values()],
            "warnings": list(self.ledger.warnings),
            "errors": list(self.ledger.errors),
            "artifacts": [artifact.to_dict() for artifact in self.ledger.artifacts],
            "sandbox_sessions": list(self.sandbox_sessions),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": safe_value(self.metadata),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)


def _report_id(target: str, target_type: str, started_at: str) -> str:
    digest = hashlib.sha256(f"{target_type}|{target}|{started_at}".encode("utf-8")).hexdigest()[:16]
    return f"trn-{digest}"


def _threats(ledger: EvidenceLedger) -> list[dict[str, Any]]:
    ranked = sorted(
        (item for item in ledger.items if item.severity in {"medium", "high", "critical"}),
        key=lambda item: ({"critical": 3, "high": 2, "medium": 1}.get(item.severity, 0), item.confidence),
        reverse=True,
    )
    return [
        {
            "id": item.evidence_id,
            "source": item.source,
            "category": item.category,
            "title": item.title,
            "severity": item.severity,
            "confidence": round(item.confidence, 3),
            "code": item.code,
        }
        for item in ranked[:50]
    ]


def build_report(
    *,
    target: str,
    target_type: str,
    started_at: str,
    assessment: RiskAssessment,
    ledger: EvidenceLedger,
    summary: str | None = None,
    status: str = "completed",
    sandbox_sessions: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> InvestigationReport:
    completed_at = datetime.now(timezone.utc).isoformat()
    if not summary:
        summary = VERDICT_DESCRIPTIONS.get(assessment.verdict, "")
        if assessment.reasons:
            summary = f"{summary} {' '.join(assessment.reasons[:3])}".strip()
    return InvestigationReport(
        report_id=_report_id(target, target_type, started_at),
        target=target,
        target_type=target_type,
        status=status,
        verdict=assessment.verdict,
        risk_score=assessment.score,
        confidence=assessment.confidence,
        summary=summary,
        started_at=started_at,
        completed_at=completed_at,
        assessment=assessment,
        ledger=ledger,
        threats=_threats(ledger),
        recommendations=list(RECOMMENDATIONS.get(assessment.verdict, [])),
        sandbox_sessions=sandbox_sessions or [],
        metadata=metadata or {},
    )
