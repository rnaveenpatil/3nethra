import pytest

from config.settings import Settings
from intelligence.evidence import EvidenceLedger
from intelligence.risk_score import assess_risk
from investigators.file import FileInvestigator
from investigators.url import URLInvestigator
from investigators.video import VideoInvestigator


def url_evidence():
    return {
        "kind": "url",
        "outcome": "completed",
        "target": {"url": "https://example.com/login", "host": "example.com", "scheme": "https"},
        "dns": {"status": "ok", "addresses": ["93.184.216.34"]},
        "http": {
            "redirect_chain": [
                {
                    "url": "https://example.com/login",
                    "host": "example.com",
                    "port": 443,
                    "addresses": ["93.184.216.34"],
                    "status": 200,
                    "reason": "OK",
                    "content_type": "text/html",
                    "content_length": 128,
                    "body_size": 128,
                    "headers": {},
                    "tls": {"verified": True},
                }
            ],
            "final": {
                "url": "https://example.com/login",
                "status": 200,
                "content_type": "text/html",
            },
            "downloads": [],
        },
        "browser": {
            "available": True,
            "final_url": "https://example.com/login",
            "title": "Login",
            "forms": [
                {
                    "action": "https://collector.example.net/steal",
                    "method": "post",
                    "inputs": [{"type": "password", "name": "password"}],
                }
            ],
            "warnings": [],
            "javascript": {},
            "scripts": {},
            "responses": [
                {
                    "url": "https://example.com/login",
                    "status": 200,
                    "resource_type": "document",
                    "headers": {"content-type": "text/html"},
                },
                {
                    "url": "https://cdn.example.com/app.js",
                    "status": 200,
                    "resource_type": "script",
                    "headers": {"content-type": "application/javascript"},
                },
            ],
            "blocked_requests": [],
        },
        "warnings": [],
        "errors": [],
    }


def test_url_analyzer_detects_cross_origin_password_form():
    ledger = EvidenceLedger()
    URLInvestigator().analyze(ledger, url_evidence())
    assert ledger.coverage_status("dns") == "ok"
    assert ledger.coverage_status("http") == "ok"
    assert ledger.coverage_status("browser") == "ok"
    assert any(item.code == "credential_harvesting" for item in ledger.items)
    assert any(item.code == "http_network_response" for item in ledger.items)
    browser_network = [item for item in ledger.items if item.code == "browser_network_response"]
    assert len(browser_network) == 2
    assert browser_network[1].data["resource_type"] == "script"


def test_dns_failure_is_inconclusive_not_suspicious():
    evidence = url_evidence()
    evidence["outcome"] = "completed_with_errors"
    evidence["dns"] = {
        "status": "blocked",
        "error": {
            "type": "NetworkPolicyError",
            "code": "dns_failure",
            "message": "DNS resolution failed",
        },
    }
    evidence["http"] = {}
    evidence["browser"] = {}
    ledger = EvidenceLedger()
    URLInvestigator().analyze(ledger, evidence)
    assert ledger.coverage_status("dns") == "failed"
    assert not any(item.code == "private_destination_blocked" for item in ledger.items)
    assert any(item.code == "dns_resolution_failed" for item in ledger.items)
    assessment = assess_risk(ledger, required_coverage=URLInvestigator.required_coverage)
    assert assessment.verdict == "INCONCLUSIVE"


def test_http_resolution_failure_is_inconclusive_not_suspicious():
    evidence = url_evidence()
    evidence["outcome"] = "completed_with_errors"
    evidence["http"] = {
        "redirect_chain": [],
        "final": {
            "url": "https://unstop.com/",
            "resolution_failed": True,
            "error": {"type": "NetworkPolicyError", "code": "dns_failure", "message": "DNS resolution failed"},
        },
        "warnings": [],
        "downloads": [],
        "tls": {},
    }
    evidence["browser"] = {}
    ledger = EvidenceLedger()
    URLInvestigator().analyze(ledger, evidence)
    assert ledger.coverage_status("http") == "failed"
    assert not any(item.code == "blocked_request" for item in ledger.items)
    assert any(item.code == "http_request_failed" for item in ledger.items)
    assessment = assess_risk(ledger, required_coverage=URLInvestigator.required_coverage)
    assert assessment.verdict == "INCONCLUSIVE"


def test_http_policy_block_remains_suspicious_evidence():
    evidence = url_evidence()
    evidence["dns"] = {"status": "ok", "addresses": ["93.184.216.34"]}
    evidence["http"] = {
        "redirect_chain": [],
        "final": {
            "url": "https://example.com/",
            "blocked": True,
            "error": {"type": "NetworkPolicyError", "code": "forbidden_destination", "message": "forbidden"},
        },
        "warnings": [],
        "downloads": [],
        "tls": {},
    }
    evidence["browser"] = {}
    ledger = EvidenceLedger()
    URLInvestigator().analyze(ledger, evidence)
    assert ledger.coverage_status("http") == "blocked"
    assert any(
        item.code == "blocked_request" and item.severity == "medium"
        for item in ledger.items
    )


def test_forbidden_dns_destination_is_still_high_severity():
    evidence = url_evidence()
    evidence["outcome"] = "blocked"
    evidence["dns"] = {
        "status": "blocked",
        "error": {
            "type": "NetworkPolicyError",
            "code": "forbidden_destination",
            "message": "DNS resolution points to a forbidden destination: private network",
        },
    }
    evidence["http"] = {}
    evidence["browser"] = {}
    ledger = EvidenceLedger()
    URLInvestigator().analyze(ledger, evidence)
    assert ledger.coverage_status("dns") == "blocked"
    assert any(
        item.code == "private_destination_blocked" and item.severity == "high"
        for item in ledger.items
    )


def test_file_analyzer_detects_macro_indicator():
    ledger = EvidenceLedger()
    evidence = {
        "kind": "file",
        "outcome": "completed",
        "file": {
            "filename": "invoice.doc",
            "size": 100,
            "file_type": "ole_compound",
            "hashes": {"sha256": "a" * 64},
            "entropy": 7.8,
            "indicators": ["office_macro_indicator"],
            "strings": ["AutoOpen", "powershell", "cmd.exe", "frombase64string"],
            "urls": [],
            "ip_addresses": [],
            "executable": {},
            "archive": None,
            "media": {},
            "executed": False,
        },
        "warnings": [],
        "errors": [],
    }
    FileInvestigator().analyze(ledger, evidence)
    assert ledger.coverage_status("file_analysis") == "ok"
    assert any(item.code == "office_macro_indicator" for item in ledger.items)
    assert any(item.code == "suspicious_keyword" for item in ledger.items)


class UnavailableDetector:
    enabled = False

    async def close(self):
        return None

    async def detect(self, frames, metadata=None):
        raise AssertionError("detector must not be called")


@pytest.mark.asyncio
async def test_video_analyzer_marks_detector_unavailable(tmp_path):
    settings = Settings(workspace=tmp_path / "workspace")
    investigator = VideoInvestigator(settings, detector=UnavailableDetector())
    ledger = EvidenceLedger()
    evidence = {
        "kind": "file",
        "outcome": "completed",
        "file": {
            "filename": "sample.mp4",
            "file_type": "mp4_video",
            "media": {
                "ffprobe": {
                    "metadata": {
                        "format": {"duration": "4.0", "format_name": "mov,mp4"},
                        "streams": [
                            {"codec_type": "video", "codec_name": "h264", "width": 640, "height": 360},
                            {"codec_type": "audio", "codec_name": "aac", "channels": 2},
                        ],
                    }
                },
                "frames": [{"name": "frame_001.jpg"}],
                "warnings": [],
            },
        },
        "warnings": [],
        "errors": [],
    }
    result = await investigator.analyze(ledger, evidence)
    assert result["detector"] == "unavailable"
    assert ledger.coverage_status("video_detector") == "unavailable"
    assert any(item.code == "detector_unavailable" for item in ledger.items)
