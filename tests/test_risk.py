from intelligence.evidence import EvidenceLedger
from intelligence.risk_score import assess_risk


def test_safe_requires_complete_coverage():
    ledger = EvidenceLedger()
    ledger.mark_coverage("file_analysis", "ok")
    ledger.add(
        source="test",
        category="metadata",
        title="Benign metadata",
        severity="info",
        confidence=1.0,
    )
    assessment = assess_risk(ledger, required_coverage=["file_analysis"])
    assert assessment.verdict == "SAFE"
    assert assessment.score == 0


def test_missing_coverage_is_inconclusive():
    ledger = EvidenceLedger()
    ledger.mark_coverage("file_analysis", "failed")
    assessment = assess_risk(ledger, required_coverage=["file_analysis"])
    assert assessment.verdict == "INCONCLUSIVE"
    assert "coverage" in " ".join(assessment.reasons).lower()


def test_malformed_evidence_is_not_safe():
    ledger = EvidenceLedger()
    ledger.mark_coverage("file_analysis", "ok")
    ledger.add(
        source="test",
        category="coverage",
        title="Malformed",
        severity="high",
        confidence=0.9,
        code="malformed_result",
    )
    assessment = assess_risk(ledger, required_coverage=["file_analysis"])
    assert assessment.verdict == "INCONCLUSIVE"
    assert assessment.malformed is True


def test_multiple_high_findings_are_malicious():
    ledger = EvidenceLedger()
    ledger.mark_coverage("dns", "ok")
    ledger.mark_coverage("http", "ok")
    ledger.mark_coverage("browser", "ok")
    for code in ("private_destination_blocked", "credential_harvesting"):
        ledger.add(
            source="test",
            category="threat",
            title="High risk",
            severity="high",
            confidence=0.9,
            code=code,
        )
    assessment = assess_risk(ledger, required_coverage=["dns", "http", "browser"])
    assert assessment.verdict == "MALICIOUS"
    assert assessment.score >= 55


def test_detector_unavailable_prevents_safe_video_verdict():
    ledger = EvidenceLedger()
    for name in ("file_analysis", "frame_extraction", "video_detector"):
        ledger.mark_coverage(name, "ok")
    ledger.add(
        source="test",
        category="coverage",
        title="Detector unavailable",
        severity="info",
        confidence=0.9,
        code="detector_unavailable",
    )
    assessment = assess_risk(
        ledger,
        required_coverage=["file_analysis", "frame_extraction", "video_detector"],
    )
    assert assessment.verdict == "INCONCLUSIVE"


def test_medium_finding_is_suspicious():
    ledger = EvidenceLedger()
    ledger.mark_coverage("file_analysis", "ok")
    ledger.add(
        source="test",
        category="threat",
        title="Suspicious",
        severity="medium",
        confidence=0.8,
        code="suspicious_keyword",
    )
    assessment = assess_risk(ledger, required_coverage=["file_analysis"])
    assert assessment.verdict == "SUSPICIOUS"
