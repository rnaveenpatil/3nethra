import pytest

from config.settings import Settings
from intelligence.evidence import EvidenceLedger
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
                    "status": 200,
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
