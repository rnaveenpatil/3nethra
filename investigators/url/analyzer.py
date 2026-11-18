from __future__ import annotations

from typing import Any

from intelligence.evidence import EvidenceLedger, safe_text

from .browser import analyze_browser
from .dns import analyze_dns
from .redirects import analyze_http


class URLInvestigator:
    required_coverage = ("dns", "http", "browser")

    def analyze(self, ledger: EvidenceLedger, evidence: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(evidence, dict):
            ledger.error("url_analysis", "URL evidence was malformed")
            ledger.add(
                source="url.analysis",
                category="coverage",
                title="URL evidence was malformed",
                severity="high",
                confidence=0.9,
                code="malformed_result",
            )
            return {"analyzed": False, "reason": "malformed_evidence"}
        kind = safe_text(evidence.get("kind", ""), 32)
        if kind and kind != "url":
            ledger.error("url_analysis", "unexpected evidence kind")
            ledger.add(
                source="url.analysis",
                category="coverage",
                title="Unexpected evidence type",
                severity="high",
                confidence=0.9,
                data={"kind": kind},
                code="malformed_result",
            )
            return {"analyzed": False, "reason": "unexpected_kind"}
        outcome = safe_text(evidence.get("outcome", ""), 64)
        if outcome == "blocked":
            ledger.warn("Sandbox blocked the URL before full analysis")
        errors = evidence.get("errors") if isinstance(evidence.get("errors"), list) else []
        for error in errors[:10]:
            if not isinstance(error, dict):
                continue
            ledger.error("sandbox", safe_text(error.get("message") or error.get("error") or "sandbox error", 512))
        analyze_dns(ledger, evidence)
        analyze_http(ledger, evidence)
        analyze_browser(ledger, evidence)
        for warning in evidence.get("warnings", [])[:10] if isinstance(evidence.get("warnings"), list) else []:
            ledger.warn(safe_text(warning, 512))
        return {
            "analyzed": True,
            "outcome": outcome,
            "coverage": {
                name: ledger.coverage_status(name)
                for name in self.required_coverage
            },
            "evidence_count": len(ledger.items),
        }
