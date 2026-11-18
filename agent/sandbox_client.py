from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

import httpx

from config.settings import Settings


class SandboxError(RuntimeError):
    def __init__(self, message: str, *, code: str = "sandbox_error", status_code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass
class SandboxSession:
    session_id: str
    kind: str
    created_at: str
    expires_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.session_id,
            "kind": self.kind,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class SandboxClient:
    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._owns_client = client is None
        headers = {"Accept": "application/json", "User-Agent": settings.user_agent}
        if settings.sandbox_token:
            headers["Authorization"] = f"Bearer {settings.sandbox_token}"
        self._headers = headers
        self._client = client or httpx.AsyncClient(
            base_url=settings.sandbox_url,
            headers=headers,
            timeout=httpx.Timeout(settings.sandbox_timeout_seconds),
            follow_redirects=False,
        )

    async def __aenter__(self) -> "SandboxClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _request(self, method: str, path: str, *, json_body: Any = None, timeout: float | None = None) -> Any:
        try:
            response = await self._client.request(
                method,
                path,
                headers=self._headers,
                json=json_body,
                timeout=timeout if timeout is not None else self.settings.sandbox_timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise SandboxError("sandbox request timed out", code="sandbox_timeout") from exc
        except httpx.HTTPError as exc:
            raise SandboxError("sandbox is unreachable", code="sandbox_unreachable") from exc
        if response.status_code >= 400:
            code = "sandbox_error"
            message = f"sandbox request failed with HTTP {response.status_code}"
            try:
                payload = response.json()
                error = payload.get("error") if isinstance(payload, dict) else None
                if isinstance(error, dict):
                    code = str(error.get("code", code))
                    message = str(error.get("message", message))
            except (ValueError, TypeError):
                pass
            raise SandboxError(message, code=code, status_code=response.status_code)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise SandboxError("sandbox returned malformed JSON", code="sandbox_invalid_response") from exc

    async def health(self) -> dict[str, Any]:
        data = await self._request("GET", "/healthz")
        if not isinstance(data, dict) or data.get("status") != "ok":
            raise SandboxError("sandbox health check failed", code="sandbox_unhealthy")
        return data

    async def create_url_session(
        self,
        url: str,
        *,
        options: Mapping[str, Any] | None = None,
    ) -> SandboxSession:
        payload = {
            "kind": "url",
            "url": url,
            "options": self._options(options),
        }
        return await self._create(payload, kind="url")

    async def create_file_session(
        self,
        path: Path,
        *,
        filename: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> SandboxSession:
        path = Path(path)
        try:
            stat = path.stat()
        except OSError as exc:
            raise SandboxError("evidence file is not readable", code="file_unreadable") from exc
        if not path.is_file() or path.is_symlink():
            raise SandboxError("evidence file must be a regular file", code="invalid_file")
        if stat.st_size <= 0:
            raise SandboxError("evidence file is empty", code="invalid_file")
        if stat.st_size > self.settings.max_file_bytes:
            raise SandboxError("evidence file exceeds the configured limit", code="file_too_large")
        raw = await asyncio.to_thread(path.read_bytes)
        digest = hashlib.sha256(raw).hexdigest()
        payload = {
            "kind": "file",
            "file": {
                "filename": filename or path.name,
                "content_base64": base64.b64encode(raw).decode("ascii"),
                "sha256": digest,
            },
            "options": self._options(options),
        }
        return await self._create(payload, kind="file")

    def _options(self, overrides: Mapping[str, Any] | None) -> dict[str, Any]:
        options = {
            "take_screenshot": True,
            "capture_html": True,
            "capture_console": True,
            "allow_downloads": False,
            "analyze_media": False,
            "extract_video_frames": False,
            "full_page_screenshot": False,
            "max_redirects": 5,
            "timeout_seconds": self.settings.sandbox_investigation_timeout_seconds,
        }
        if overrides:
            for key in options:
                if key in overrides:
                    options[key] = overrides[key]
        options["timeout_seconds"] = max(5, min(int(options["timeout_seconds"]), 600))
        options["max_redirects"] = max(0, min(int(options["max_redirects"]), 10))
        return options

    async def _create(self, payload: dict[str, Any], *, kind: str) -> SandboxSession:
        data = await self._request("POST", "/v1/sessions", json_body=payload)
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            raise SandboxError("sandbox returned an invalid session", code="sandbox_invalid_response")
        return SandboxSession(
            session_id=data["id"],
            kind=kind,
            created_at=str(data.get("created_at", "")),
            expires_at=str(data.get("expires_at", "")),
        )

    async def investigate(self, session_id: str) -> dict[str, Any]:
        data = await self._request("POST", f"/v1/sessions/{quote(session_id, safe='')}/investigate")
        if not isinstance(data, dict):
            raise SandboxError("sandbox returned an invalid investigation response", code="sandbox_invalid_response")
        return data

    async def status(self, session_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/v1/sessions/{quote(session_id, safe='')}")
        if not isinstance(data, dict):
            raise SandboxError("sandbox returned an invalid status", code="sandbox_invalid_response")
        return data

    async def wait(
        self,
        session_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_seconds: float | None = None,
    ) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (timeout_seconds or self.settings.sandbox_investigation_timeout_seconds + 30)
        interval = poll_seconds or self.settings.sandbox_poll_seconds
        while True:
            status = await self.status(session_id)
            state = status.get("status")
            if state in {"completed", "failed", "timed_out", "terminated"}:
                return status
            if loop.time() >= deadline:
                await self.terminate(session_id)
                raise SandboxError("sandbox investigation timed out", code="sandbox_timeout")
            await asyncio.sleep(interval)

    async def evidence(self, session_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/v1/sessions/{quote(session_id, safe='')}/evidence")
        if not isinstance(data, dict):
            raise SandboxError("sandbox returned invalid evidence", code="sandbox_invalid_response")
        return data

    async def logs(self, session_id: str) -> str:
        data = await self._request("GET", f"/v1/sessions/{quote(session_id, safe='')}/logs")
        if not isinstance(data, dict):
            return ""
        return str(data.get("logs", ""))[: self.settings.max_tool_output_chars]

    async def artifacts(self, session_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/v1/sessions/{quote(session_id, safe='')}/artifacts")
        if not isinstance(data, dict) or not isinstance(data.get("artifacts"), list):
            raise SandboxError("sandbox returned invalid artifacts", code="sandbox_invalid_response")
        result = []
        for item in data["artifacts"]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            try:
                size = int(item.get("size", 0))
            except (TypeError, ValueError):
                continue
            result.append(
                {
                    "name": name,
                    "size": size,
                    "sha256": str(item.get("sha256", "")),
                    "content_type": str(item.get("content_type", "application/octet-stream")),
                }
            )
        return result

    async def artifact(self, session_id: str, name: str, *, max_bytes: int | None = None) -> bytes:
        limit = max_bytes or self.settings.sandbox_max_artifact_bytes
        path = f"/v1/sessions/{quote(session_id, safe='')}/artifacts/{quote(name, safe='/')}"
        chunks: list[bytes] = []
        total = 0
        try:
            async with self._client.stream(
                "GET",
                path,
                headers=self._headers,
                timeout=self.settings.sandbox_timeout_seconds,
            ) as response:
                if response.status_code >= 400:
                    raise SandboxError(
                        f"sandbox artifact download failed with HTTP {response.status_code}",
                        code="artifact_unavailable",
                        status_code=response.status_code,
                    )
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > limit:
                    raise SandboxError("sandbox artifact exceeds the configured limit", code="artifact_too_large")
                async for chunk in response.aiter_bytes(256 * 1024):
                    total += len(chunk)
                    if total > limit:
                        raise SandboxError("sandbox artifact exceeds the configured limit", code="artifact_too_large")
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise SandboxError("sandbox artifact download timed out", code="sandbox_timeout") from exc
        except httpx.HTTPError as exc:
            raise SandboxError("sandbox artifact download failed", code="sandbox_unreachable") from exc
        return b"".join(chunks)

    async def terminate(self, session_id: str) -> dict[str, Any]:
        data = await self._request("POST", f"/v1/sessions/{quote(session_id, safe='')}/terminate")
        return data if isinstance(data, dict) else {}

    async def destroy(self, session_id: str) -> None:
        await self._request("DELETE", f"/v1/sessions/{quote(session_id, safe='')}")
