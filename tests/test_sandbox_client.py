import json

import httpx
import pytest

from agent.sandbox_client import SandboxClient, SandboxError
from config.settings import Settings


def settings_for(tmp_path):
    return Settings(
        workspace=tmp_path / "workspace",
        history_path=tmp_path / "history.db",
        sandbox_url="http://sandbox.test",
        sandbox_token="a" * 40,
        approval_mode="auto",
    )


@pytest.mark.asyncio
async def test_sandbox_client_lifecycle_and_artifact(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.headers.get("authorization")))
        if request.url.path == "/v1/sessions" and request.method == "POST":
            payload = json.loads(request.content)
            assert payload["kind"] == "url"
            return httpx.Response(
                201,
                json={
                    "id": "sid1",
                    "status": "created",
                    "created_at": "now",
                    "expires_at": "later",
                },
            )
        if request.url.path == "/v1/sessions/sid1/investigate":
            return httpx.Response(202, json={"id": "sid1", "status": "running"})
        if request.url.path == "/v1/sessions/sid1" and request.method == "DELETE":
            return httpx.Response(204)
        if request.url.path == "/v1/sessions/sid1":
            return httpx.Response(
                200,
                json={
                    "id": "sid1",
                    "kind": "url",
                    "status": "completed",
                    "created_at": "now",
                    "updated_at": "now",
                    "expires_at": "later",
                },
            )
        if request.url.path == "/v1/sessions/sid1/evidence":
            return httpx.Response(200, json={"status": "completed"})
        if request.url.path == "/v1/sessions/sid1/artifacts":
            return httpx.Response(
                200,
                json={
                    "id": "sid1",
                    "artifacts": [
                        {
                            "name": "screenshot.png",
                            "size": 3,
                            "sha256": "abc",
                            "content_type": "image/png",
                        }
                    ],
                },
            )
        if request.url.path == "/v1/sessions/sid1/artifacts/screenshot.png":
            return httpx.Response(200, content=b"png")
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "missing"}})

    http_client = httpx.AsyncClient(
        base_url="http://sandbox.test",
        transport=httpx.MockTransport(handler),
    )
    client = SandboxClient(settings_for(tmp_path), client=http_client)
    session = await client.create_url_session("https://example.com")
    assert session.session_id == "sid1"
    await client.investigate(session.session_id)
    status = await client.wait(session.session_id, timeout_seconds=1, poll_seconds=0.01)
    assert status["status"] == "completed"
    assert await client.evidence(session.session_id) == {"status": "completed"}
    artifacts = await client.artifacts(session.session_id)
    assert artifacts[0]["name"] == "screenshot.png"
    assert await client.artifact(session.session_id, "screenshot.png") == b"png"
    await client.destroy(session.session_id)
    assert all(call[2] == "Bearer " + "a" * 40 for call in calls)
    await http_client.aclose()


@pytest.mark.asyncio
async def test_sandbox_client_rejects_oversized_artifact(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "1000"},
            content=b"x" * 1000,
        )

    http_client = httpx.AsyncClient(
        base_url="http://sandbox.test",
        transport=httpx.MockTransport(handler),
    )
    client = SandboxClient(settings_for(tmp_path), client=http_client)
    with pytest.raises(SandboxError):
        await client.artifact("sid", "large.bin", max_bytes=10)
    await http_client.aclose()
