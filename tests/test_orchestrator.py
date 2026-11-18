import pytest

from agent.orchestrator import InvestigationAgent
from agent.reasoning import ReasoningEngine
from agent.sandbox_client import SandboxSession
from config.settings import Settings


class FakeSandbox:
    def __init__(self, url_evidence, file_evidence=None):
        self.url_result = url_evidence
        self.file_result = file_evidence
        self.destroyed = []

    async def create_url_session(self, url, *, options=None):
        return SandboxSession("sid-url", "url", "now", "later")

    async def create_file_session(self, path, *, filename=None, options=None):
        return SandboxSession("sid-file", "file", "now", "later")

    async def investigate(self, session_id):
        return {"id": session_id, "status": "running"}

    async def wait(self, session_id, *, timeout_seconds=None, poll_seconds=None):
        return {"id": session_id, "status": "completed", "error": None}

    async def evidence(self, session_id):
        return self.url_result if session_id == "sid-url" else self.file_result

    async def logs(self, session_id):
        return ""

    async def artifacts(self, session_id):
        return []

    async def destroy(self, session_id):
        self.destroyed.append(session_id)


def safe_url_evidence():
    return {
        "kind": "url",
        "outcome": "completed",
        "target": {"url": "https://example.com", "host": "example.com", "scheme": "https"},
        "dns": {"status": "ok", "addresses": ["93.184.216.34"]},
        "http": {
            "redirect_chain": [
                {
                    "url": "https://example.com",
                    "status": 200,
                    "headers": {},
                    "tls": {"verified": True},
                }
            ],
            "final": {"url": "https://example.com", "status": 200, "content_type": "text/html"},
            "downloads": [],
        },
        "browser": {
            "available": True,
            "final_url": "https://example.com",
            "title": "Example",
            "forms": [],
            "warnings": [],
            "javascript": {},
            "scripts": {},
        },
        "warnings": [],
        "errors": [],
    }


def file_evidence():
    return {
        "kind": "file",
        "outcome": "completed",
        "file": {
            "filename": "notes.txt",
            "size": 10,
            "file_type": "unknown",
            "hashes": {"sha256": "b" * 64},
            "entropy": 3.0,
            "indicators": [],
            "strings": ["hello"],
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


def settings_for(tmp_path):
    return Settings(
        workspace=tmp_path / "workspace",
        history_path=tmp_path / "history.db",
        approval_mode="auto",
        llm_api_key=None,
    )


@pytest.mark.asyncio
async def test_url_investigation_produces_safe_report_and_history(tmp_path):
    settings = settings_for(tmp_path)
    sandbox = FakeSandbox(safe_url_evidence())
    agent = InvestigationAgent(
        settings,
        sandbox=sandbox,
        reasoning=ReasoningEngine(settings),
    )
    report = await agent.investigate_url("https://example.com")
    assert report.verdict == "SAFE"
    assert report.status == "completed"
    assert report.sandbox_sessions == ["sid-url"]
    assert sandbox.destroyed == ["sid-url"]
    assert report.to_dict()["report_id"]
    history = await agent.history.list()
    assert history[0]["report_id"] == report.report_id
    assert history[0]["verdict"] == "SAFE"


@pytest.mark.asyncio
async def test_file_investigation_stores_report(tmp_path):
    settings = settings_for(tmp_path)
    target = tmp_path / "notes.txt"
    target.write_text("hello")
    sandbox = FakeSandbox(safe_url_evidence(), file_evidence())
    agent = InvestigationAgent(
        settings,
        sandbox=sandbox,
        reasoning=ReasoningEngine(settings),
    )
    report = await agent.investigate_file(target)
    assert report.target_type == "file"
    assert report.verdict == "SAFE"
    assert report.sandbox_sessions == ["sid-file"]
    stored = await agent.history.get(report.report_id)
    assert stored["verdict"] == "SAFE"


@pytest.mark.asyncio
async def test_invalid_target_is_rejected(tmp_path):
    settings = settings_for(tmp_path)
    agent = InvestigationAgent(
        settings,
        sandbox=FakeSandbox(safe_url_evidence()),
        reasoning=ReasoningEngine(settings),
    )
    with pytest.raises(ValueError):
        await agent.investigate_url("file:///etc/passwd")
    await agent.close()


def malicious_url_evidence():
    evidence = safe_url_evidence()
    evidence["browser"]["forms"] = [
        {
            "action": "https://collector.example.net/steal",
            "method": "post",
            "inputs": [{"type": "password", "name": "password"}],
        }
    ]
    evidence["http"]["downloads"] = [
        {
            "name": "invoice.exe",
            "size": 10,
            "sha256": "c" * 64,
            "content_type": "application/octet-stream",
        }
    ]
    return evidence


@pytest.mark.asyncio
async def test_url_investigation_escalates_multiple_high_findings(tmp_path):
    settings = settings_for(tmp_path)
    sandbox = FakeSandbox(malicious_url_evidence())
    agent = InvestigationAgent(
        settings,
        sandbox=sandbox,
        reasoning=ReasoningEngine(settings),
    )
    report = await agent.investigate_url("https://example.com")
    assert report.verdict == "MALICIOUS"
    assert report.risk_score >= 50
    assert any(threat["severity"] == "high" for threat in report.threats)


@pytest.mark.asyncio
async def test_video_without_detector_is_inconclusive(tmp_path):
    settings = settings_for(tmp_path)
    target = tmp_path / "sample.mp4"
    target.write_bytes(b"not really video")
    evidence = file_evidence()
    evidence["file"].update(
        {
            "filename": "sample.mp4",
            "file_type": "mp4_video",
            "media": {
                "ffprobe": {
                    "metadata": {
                        "format": {"duration": "3.0"},
                        "streams": [{"codec_type": "video", "codec_name": "h264"}],
                    }
                },
                "frames": [{"name": "frame_001.jpg"}],
                "warnings": [],
            },
        }
    )
    sandbox = FakeSandbox(safe_url_evidence(), evidence)
    agent = InvestigationAgent(
        settings,
        sandbox=sandbox,
        reasoning=ReasoningEngine(settings),
    )
    report = await agent.investigate_video(target)
    assert report.verdict == "INCONCLUSIVE"
    assert any(item["code"] == "detector_unavailable" for item in report.to_dict()["evidence"])
