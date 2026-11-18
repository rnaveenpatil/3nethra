from __future__ import annotations

import asyncio
import base64
import io
import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sandbox import config, security
from sandbox.manager import CollectedEvidence, DockerSandboxRuntime, SandboxService, WorkerEnvironment, create_app

TOKEN = "t" * 48
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class FakeRuntime:
    def __init__(self, running: bool = False) -> None:
        self.running = running
        self.start_calls: list[dict[str, Any]] = []
        self.disposed: list[str] = []
        self.stopped: list[str] = []
        self.started = False

    async def startup(self) -> None:
        self.started = True

    async def shutdown(self) -> None:
        self.started = False

    async def start(self, session_id: str, task: dict[str, Any], input_path: Path | None) -> WorkerEnvironment:
        self.start_calls.append({"session_id": session_id, "task": task, "input_path": input_path})
        return WorkerEnvironment(session_id=session_id)

    async def state(self, env: WorkerEnvironment) -> dict[str, Any]:
        if self.running:
            return {"status": "running", "running": True, "exit_code": None, "oom_killed": False}
        return {"status": "exited", "running": False, "exit_code": 0, "oom_killed": False}

    async def poll_status(self, env: WorkerEnvironment) -> dict[str, Any]:
        return {"phase": "browser", "progress": 50}

    async def logs(self, env: WorkerEnvironment, max_bytes: int) -> str:
        return "worker log line"

    async def collect(self, env: WorkerEnvironment, destination: Path) -> CollectedEvidence:
        destination.mkdir(parents=True, exist_ok=True)
        results = {
            "schema_version": 1,
            "status": "completed",
            "outcome": "completed",
            "findings": {"indicator": "clear"},
        }
        (destination / "results.json").write_text(__import__("json").dumps(results), encoding="utf-8")
        (destination / "page.txt").write_bytes(b"safe artifact")
        metadata = {
            "name": "page.txt",
            "size": 13,
            "sha256": security.sha256_bytes(b"safe artifact"),
            "content_type": "text/plain; charset=utf-8",
        }
        return CollectedEvidence(data=results, artifacts=[metadata])

    async def stop(self, env: WorkerEnvironment) -> None:
        self.stopped.append(env.session_id)

    async def dispose(self, env: WorkerEnvironment) -> None:
        self.disposed.append(env.session_id)


def make_settings(tmp_path: Path, **overrides: Any) -> config.Settings:
    values: dict[str, Any] = {
        "api_token": TOKEN,
        "enable_host_firewall": False,
        "allow_unsafe_network": True,
        "evidence_root": tmp_path / "evidence",
        "sweeper_interval_seconds": 3600,
        "poll_interval_seconds": 0.05,
    }
    values.update(overrides)
    return replace(config.Settings(), **values)


def make_client(tmp_path: Path, runtime: FakeRuntime | None = None, **overrides: Any) -> tuple[TestClient, FakeRuntime, SandboxService]:
    runtime = runtime or FakeRuntime()
    settings = make_settings(tmp_path, **overrides)
    app = create_app(settings, runtime)
    client = TestClient(app)
    service = app.state.service
    return client, runtime, service


def wait_status(client: TestClient, session_id: str, statuses: set[str], timeout: float = 5.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/v1/sessions/{session_id}", headers=AUTH)
        if response.status_code == 200:
            last = response.json()
            if last.get("status") in statuses:
                return last
        time.sleep(0.02)
    raise AssertionError(f"session did not reach {statuses}: {last}")


def test_authentication_is_required(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(tmp_path)
    with client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/v1/sessions").status_code == 401
        assert client.get("/v1/sessions", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_url_session_lifecycle_and_evidence(tmp_path: Path) -> None:
    client, runtime, _service = make_client(tmp_path)
    with client:
        response = client.post(
            "/v1/sessions",
            headers=AUTH,
            json={"kind": "url", "url": "https://example.com/path?token=secret"},
        )
        assert response.status_code == 201
        session_id = response.json()["id"]
        assert runtime.start_calls == []

        pending = client.get(f"/v1/sessions/{session_id}/evidence", headers=AUTH)
        assert pending.status_code == 409

        accepted = client.post(f"/v1/sessions/{session_id}/investigate", headers=AUTH)
        assert accepted.status_code == 202
        status_payload = wait_status(client, session_id, {"completed"})
        assert status_payload["evidence_available"] is True
        assert status_payload["phase"] == "completed"
        assert status_payload["artifacts"][0]["name"] == "page.txt"

        evidence = client.get(f"/v1/sessions/{session_id}/evidence", headers=AUTH)
        assert evidence.status_code == 200
        assert evidence.json()["session_id"] == session_id
        assert evidence.json()["findings"]["indicator"] == "clear"

        artifacts = client.get(f"/v1/sessions/{session_id}/artifacts", headers=AUTH)
        assert artifacts.status_code == 200
        artifact = client.get(f"/v1/sessions/{session_id}/artifacts/page.txt", headers=AUTH)
        assert artifact.status_code == 200
        assert artifact.headers["content-type"].startswith("text/plain")
        assert artifact.content == b"safe artifact"
        assert artifact.headers["x-content-type-options"] == "nosniff"

        missing = client.get(f"/v1/sessions/{session_id}/artifacts/../results.json", headers=AUTH)
        assert missing.status_code in {404, 400}

        logs = client.get(f"/v1/sessions/{session_id}/logs", headers=AUTH)
        assert logs.status_code == 200
        assert "worker log line" in logs.json()["logs"]


def test_private_url_is_rejected(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(tmp_path)
    with client:
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://localhost/"):
            response = client.post("/v1/sessions", headers=AUTH, json={"kind": "url", "url": url})
            assert response.status_code == 400
            assert response.json()["error"]["code"] in {"forbidden_destination", "forbidden_hostname"}


def test_file_session_uses_isolated_input(tmp_path: Path) -> None:
    client, runtime, _service = make_client(tmp_path)
    payload = {
        "kind": "file",
        "file": {
            "filename": "../../payload.bin",
            "content_base64": base64.b64encode(b"MZpayload").decode("ascii"),
        },
    }
    with client:
        response = client.post("/v1/sessions", headers=AUTH, json=payload)
        assert response.status_code == 201
        session_id = response.json()["id"]
        client.post(f"/v1/sessions/{session_id}/investigate", headers=AUTH)
        wait_status(client, session_id, {"completed"})
        call = runtime.start_calls[0]
        assert call["task"]["input"]["filename"] == "payload.bin"
        assert call["task"]["kind"] == "file"
        assert call["input_path"] is not None
        assert not call["input_path"].exists()


def test_checksum_and_validation_errors(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(tmp_path)
    with client:
        invalid = client.post("/v1/sessions", headers=AUTH, json={"kind": "file"})
        assert invalid.status_code == 422
        mismatch = client.post(
            "/v1/sessions",
            headers=AUTH,
            json={
                "kind": "file",
                "file": {
                    "filename": "a.bin",
                    "content_base64": base64.b64encode(b"abc").decode("ascii"),
                    "sha256": "0" * 64,
                },
            },
        )
        assert mismatch.status_code == 400
        assert mismatch.json()["error"]["code"] == "checksum_mismatch"


def test_upload_size_limit(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(
        tmp_path,
        max_upload_bytes=1024,
        api_request_limit_bytes=8192,
    )
    with client:
        response = client.post(
            "/v1/sessions",
            headers=AUTH,
            json={
                "kind": "file",
                "file": {
                    "filename": "large.bin",
                    "content_base64": base64.b64encode(b"x" * 2048).decode("ascii"),
                },
            },
        )
        assert response.status_code == 413


def test_body_limit_is_enforced(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(
        tmp_path,
        max_upload_bytes=1024,
        api_request_limit_bytes=2048,
    )
    with client:
        response = client.post("/v1/sessions", headers=AUTH, content=b"x" * 4096)
        assert response.status_code == 413


def test_running_session_can_be_terminated_and_destroyed(tmp_path: Path) -> None:
    runtime = FakeRuntime(running=True)
    client, _runtime, service = make_client(tmp_path, runtime)
    with client:
        response = client.post("/v1/sessions", headers=AUTH, json={"kind": "url", "url": "https://example.com/"})
        session_id = response.json()["id"]
        client.post(f"/v1/sessions/{session_id}/investigate", headers=AUTH)
        wait_status(client, session_id, {"running"})
        workdir = service.sessions[session_id].workdir
        terminated = client.post(f"/v1/sessions/{session_id}/terminate", headers=AUTH)
        assert terminated.status_code == 200
        assert terminated.json()["status"] == "terminated"
        deleted = client.delete(f"/v1/sessions/{session_id}", headers=AUTH)
        assert deleted.status_code == 204
        assert not workdir.exists()
        assert client.get(f"/v1/sessions/{session_id}", headers=AUTH).status_code == 404


def test_session_listing_and_capacity(tmp_path: Path) -> None:
    client, _runtime, _service = make_client(tmp_path, max_sessions=1)
    with client:
        first = client.post("/v1/sessions", headers=AUTH, json={"kind": "url", "url": "https://example.com/"})
        assert first.status_code == 201
        second = client.post("/v1/sessions", headers=AUTH, json={"kind": "url", "url": "https://example.org/"})
        assert second.status_code == 429
        listing = client.get("/v1/sessions", headers=AUTH)
        assert listing.status_code == 200
        assert len(listing.json()["sessions"]) == 1


def test_unhandled_runtime_failure_is_reported_without_internal_details(tmp_path: Path) -> None:
    class FailingRuntime(FakeRuntime):
        async def start(self, session_id: str, task: dict[str, Any], input_path: Path | None) -> WorkerEnvironment:
            raise RuntimeError("/tmp/secret-host-path")

    client, _runtime, _service = make_client(tmp_path, FailingRuntime())
    with client:
        response = client.post("/v1/sessions", headers=AUTH, json={"kind": "url", "url": "https://example.com/"})
        session_id = response.json()["id"]
        client.post(f"/v1/sessions/{session_id}/investigate", headers=AUTH)
        status_payload = wait_status(client, session_id, {"failed"})
        assert status_payload["error"]["code"] == "sandbox_error"
        assert "secret-host-path" not in status_payload["error"]["message"]


def test_docker_collect_strips_archive_root(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    runtime = DockerSandboxRuntime(settings)
    archive = security.build_tar(
        {
            "evidence/results.json": json.dumps(
                {"schema_version": 1, "status": "completed", "outcome": "completed"}
            ).encode("utf-8"),
            "evidence/page.txt": b"safe artifact",
        }
    )

    class ArchiveContainer:
        def get_archive(self, path: str) -> tuple[io.BytesIO, dict[str, Any]]:
            assert path == "/work/evidence"
            return io.BytesIO(archive), {}

    destination = tmp_path / "collected"
    collected = asyncio.run(
        runtime.collect(WorkerEnvironment(session_id="session", container=ArchiveContainer()), destination)
    )
    assert collected.data is not None
    assert collected.data["status"] == "completed"
    assert [item["name"] for item in collected.artifacts] == ["page.txt"]
    assert (destination / "results.json").is_file()
    assert (destination / "page.txt").read_bytes() == b"safe artifact"
    assert not list(destination.parent.glob(".collect-*"))


def test_build_tar_preserves_worker_ownership() -> None:
    archive = security.build_tar({"task.json": b"{}"}, uid=10001, gid=10001)
    with __import__("tarfile").open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        member = handle.getmember("task.json")
    assert member.uid == 10001
    assert member.gid == 10001
