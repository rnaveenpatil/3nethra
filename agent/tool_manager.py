from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable

from config.settings import Settings
from intelligence.evidence import ArtifactRecord, EvidenceLedger, safe_text, safe_value
from investigators.file import FileInvestigator
from investigators.url import URLInvestigator
from investigators.video import VideoInvestigator
from investigators.video.detector import VideoDetector

from .approval import ApprovalBroker
from .sandbox_client import SandboxClient, SandboxError, SandboxSession
from .terminal import ReadonlyTerminal, TerminalError


@dataclass
class SandboxRun:
    kind: str
    session_id: str
    status: str
    evidence: dict[str, Any] | None = None
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    logs: str = ""
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        evidence = self.evidence or {}
        return {
            "kind": self.kind,
            "session_id": self.session_id,
            "status": self.status,
            "outcome": safe_text(evidence.get("outcome", ""), 64),
            "evidence_keys": sorted(str(key) for key in evidence.keys())[:40],
            "artifacts": [record.name for record in self.artifacts[:40]],
            "log_excerpt": safe_text(self.logs[-2048:], 2048),
            "error": self.error,
        }


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "summary": safe_text(self.summary, 2048),
            "data": safe_value(self.data),
            "error_code": self.error_code,
        }


Handler = Callable[[dict[str, Any]], Awaitable[ToolResult]]


class ToolManager:
    def __init__(
        self,
        settings: Settings,
        *,
        target: str,
        target_type: str,
        ledger: EvidenceLedger,
        sandbox: SandboxClient,
        approval: ApprovalBroker,
        url_investigator: URLInvestigator | None = None,
        file_investigator: FileInvestigator | None = None,
        video_investigator: VideoInvestigator | None = None,
    ) -> None:
        self.settings = settings
        self.target = target
        self.target_type = target_type
        self.ledger = ledger
        self.sandbox = sandbox
        self.approval = approval
        self.url_investigator = url_investigator or URLInvestigator()
        self.file_investigator = file_investigator or FileInvestigator()
        self.video_investigator = video_investigator or VideoInvestigator(settings)
        self.terminal = ReadonlyTerminal(settings.workspace, max_output=settings.max_tool_output_chars)
        self.workspace = Path(settings.workspace).resolve()
        artifact_root = self.workspace / "sandbox-artifacts"
        artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved_root = artifact_root.resolve()
        if self.workspace not in resolved_root.parents:
            raise ValueError("artifact workspace is not contained by the agent workspace")
        self.artifact_root = resolved_root
        self._closed = False
        self.session_ids: list[str] = []
        self.completed_tools: list[str] = []
        self.last_results: dict[str, ToolResult] = {}
        self._runs: dict[str, SandboxRun] = {}
        self._handlers: dict[str, Handler] = {
            "sandbox_url_investigation": self._sandbox_url,
            "sandbox_file_investigation": self._sandbox_file,
            "analyze_url_evidence": self._analyze_url,
            "analyze_file_evidence": self._analyze_file,
            "analyze_video_evidence": self._analyze_video,
            "run_readonly_command": self._terminal_command,
        }
        self._descriptions = {
            "sandbox_url_investigation": "Collect DNS, HTTP, redirect, browser and media evidence for the target URL inside the isolated sandbox.",
            "sandbox_file_investigation": "Upload the submitted file to the isolated sandbox and collect static and media evidence.",
            "analyze_url_evidence": "Analyze collected URL evidence and record deterministic findings.",
            "analyze_file_evidence": "Analyze collected file evidence and record deterministic findings.",
            "analyze_video_evidence": "Analyze collected video metadata and frames, using the configured authenticity detector when available.",
            "run_readonly_command": "Run a narrowly allowed read-only command against a file already inside the agent workspace.",
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.video_investigator.close()
        except Exception:
            pass

    def schemas(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for name in self._handlers:
            if name.startswith("sandbox_url") and self.target_type != "url":
                continue
            if name.startswith("sandbox_file") and self.target_type not in {"file", "video"}:
                continue
            schemas.append(
                {
                    "name": name,
                    "description": self._descriptions[name],
                    "input_schema": self._schema_for(name),
                }
            )
        return schemas

    def _schema_for(self, name: str) -> dict[str, Any]:
        if name in {"sandbox_url_investigation", "sandbox_file_investigation"}:
            return {
                "type": "object",
                "properties": {
                    "capture_html": {"type": "boolean"},
                    "capture_console": {"type": "boolean"},
                    "take_screenshot": {"type": "boolean"},
                    "allow_downloads": {"type": "boolean"},
                    "analyze_media": {"type": "boolean"},
                    "extract_video_frames": {"type": "boolean"},
                    "full_page_screenshot": {"type": "boolean"},
                    "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10},
                    "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 600},
                },
                "additionalProperties": False,
            }
        if name == "run_readonly_command":
            return {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 2,
                        "maxItems": 32,
                    },
                    "purpose": {"type": "string", "maxLength": 500},
                },
                "required": ["command"],
                "additionalProperties": False,
            }
        return {"type": "object", "properties": {}, "additionalProperties": False}

    async def execute(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        handler = self._handlers.get(name)
        if handler is None:
            return ToolResult(False, "The requested tool is not available.", error_code="unknown_tool")
        if not isinstance(arguments, dict):
            return ToolResult(False, "Tool arguments must be an object.", error_code="invalid_arguments")
        if name.startswith("sandbox_url") and self.target_type != "url":
            return ToolResult(False, "URL sandbox tool is not valid for this target.", error_code="invalid_tool")
        if name.startswith("sandbox_file") and self.target_type not in {"file", "video"}:
            return ToolResult(False, "File sandbox tool is not valid for this target.", error_code="invalid_tool")
        try:
            result = await handler(arguments)
        except SandboxError as exc:
            result = ToolResult(False, f"Sandbox operation failed: {exc}", error_code=exc.code)
            self.ledger.error(name, f"sandbox error: {exc.code}")
        except TerminalError as exc:
            result = ToolResult(False, f"Terminal command rejected: {exc}", error_code="terminal_rejected")
            self.ledger.error(name, f"terminal rejected: {exc}")
        except ToolError as exc:
            result = ToolResult(False, f"Tool arguments were rejected: {exc}", error_code="invalid_arguments")
            self.ledger.error(name, "invalid tool arguments")
        except Exception as exc:
            result = ToolResult(
                False,
                "Tool execution failed safely without exposing internal details.",
                error_code="tool_failed",
            )
            self.ledger.error(name, f"tool failure: {type(exc).__name__}")
        self.last_results[name] = result
        if result.ok:
            self.completed_tools.append(name)
        return result

    def _sandbox_options(self, arguments: dict[str, Any], *, video: bool) -> dict[str, Any]:
        allowed = {
            "capture_html",
            "capture_console",
            "take_screenshot",
            "allow_downloads",
            "analyze_media",
            "extract_video_frames",
            "full_page_screenshot",
            "max_redirects",
            "timeout_seconds",
        }
        unknown = set(arguments) - allowed
        if unknown:
            raise ToolError("invalid_arguments")
        options: dict[str, Any] = {}
        for key in (
            "capture_html",
            "capture_console",
            "take_screenshot",
            "allow_downloads",
            "analyze_media",
            "extract_video_frames",
            "full_page_screenshot",
        ):
            if key in arguments:
                if not isinstance(arguments[key], bool):
                    raise ToolError("invalid_arguments")
                options[key] = arguments[key]
        for key in ("max_redirects", "timeout_seconds"):
            if key in arguments:
                value = arguments[key]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ToolError("invalid_arguments")
                options[key] = value
        if video:
            options.setdefault("analyze_media", True)
            options.setdefault("extract_video_frames", True)
        return options

    async def _sandbox_url(self, arguments: dict[str, Any]) -> ToolResult:
        if "url_evidence" in self._runs:
            return ToolResult(True, "URL sandbox evidence was already collected.", self._runs["url_evidence"].summary())
        options = self._sandbox_options(arguments, video=False)
        run = await self._run_url(options)
        return self._sandbox_result(run, label="URL")

    async def _sandbox_file(self, arguments: dict[str, Any]) -> ToolResult:
        if "file_evidence" in self._runs:
            return ToolResult(True, "File sandbox evidence was already collected.", self._runs["file_evidence"].summary())
        options = self._sandbox_options(arguments, video=self.target_type == "video")
        run = await self._run_file(options)
        return self._sandbox_result(run, label="File")

    def _sandbox_result(self, run: SandboxRun, *, label: str) -> ToolResult:
        summary = run.summary()
        if run.evidence is None:
            return ToolResult(False, f"{label} sandbox investigation produced no evidence.", summary, "sandbox_failed")
        if run.status != "completed":
            return ToolResult(
                False,
                f"{label} sandbox investigation ended with status {run.status}.",
                summary,
                "sandbox_incomplete",
            )
        return ToolResult(True, f"{label} sandbox evidence was collected.", summary)

    async def _run_url(self, options: dict[str, Any]) -> SandboxRun:
        session: SandboxSession | None = None
        status: dict[str, Any] = {}
        try:
            session = await self.sandbox.create_url_session(self.target, options=options)
            self.session_ids.append(session.session_id)
            await self.sandbox.investigate(session.session_id)
            status = await self.sandbox.wait(
                session.session_id,
                timeout_seconds=int(options.get("timeout_seconds", self.settings.sandbox_investigation_timeout_seconds)) + 30,
            )
            evidence = await self._safe_evidence(session.session_id)
            artifacts = await self._download_artifacts(session.session_id)
            logs = await self._safe_logs(session.session_id)
            run = SandboxRun(
                kind="url",
                session_id=session.session_id,
                status=safe_text(status.get("status", "unknown"), 32),
                evidence=evidence,
                artifacts=artifacts,
                logs=logs,
                error=self._status_error(status),
            )
            self._runs["url_evidence"] = run
            return run
        except SandboxError as exc:
            self.ledger.error("sandbox.url", f"sandbox error: {exc.code}")
            run = SandboxRun(
                kind="url",
                session_id=session.session_id if session else "",
                status="failed",
                error=exc.code,
            )
            self._runs["url_evidence"] = run
            return run
        finally:
            if session is not None:
                await self._destroy(session.session_id)

    async def _run_file(self, options: dict[str, Any]) -> SandboxRun:
        session: SandboxSession | None = None
        status: dict[str, Any] = {}
        try:
            session = await self.sandbox.create_file_session(Path(self.target), options=options)
            self.session_ids.append(session.session_id)
            await self.sandbox.investigate(session.session_id)
            status = await self.sandbox.wait(
                session.session_id,
                timeout_seconds=int(options.get("timeout_seconds", self.settings.sandbox_investigation_timeout_seconds)) + 30,
            )
            evidence = await self._safe_evidence(session.session_id)
            artifacts = await self._download_artifacts(session.session_id)
            logs = await self._safe_logs(session.session_id)
            run = SandboxRun(
                kind="file",
                session_id=session.session_id,
                status=safe_text(status.get("status", "unknown"), 32),
                evidence=evidence,
                artifacts=artifacts,
                logs=logs,
                error=self._status_error(status),
            )
            self._runs["file_evidence"] = run
            return run
        except SandboxError as exc:
            self.ledger.error("sandbox.file", f"sandbox error: {exc.code}")
            run = SandboxRun(
                kind="file",
                session_id=session.session_id if session else "",
                status="failed",
                error=exc.code,
            )
            self._runs["file_evidence"] = run
            return run
        finally:
            if session is not None:
                await self._destroy(session.session_id)

    def _status_error(self, status: dict[str, Any]) -> str | None:
        error = status.get("error")
        if isinstance(error, dict):
            return safe_text(error.get("code", "sandbox_error"), 128)
        return None

    async def _safe_evidence(self, session_id: str) -> dict[str, Any] | None:
        try:
            return await self.sandbox.evidence(session_id)
        except SandboxError as exc:
            self.ledger.warn(f"Sandbox evidence was unavailable: {exc.code}")
            return None

    async def _safe_logs(self, session_id: str) -> str:
        try:
            return safe_text(await self.sandbox.logs(session_id), 8192)
        except SandboxError:
            return ""

    async def _destroy(self, session_id: str) -> None:
        try:
            await self.sandbox.destroy(session_id)
        except SandboxError as exc:
            self.ledger.warn(f"Sandbox cleanup reported {exc.code}")

    async def _download_artifacts(self, session_id: str) -> list[ArtifactRecord]:
        try:
            metadata = await self.sandbox.artifacts(session_id)
        except SandboxError as exc:
            self.ledger.warn(f"Sandbox artifact listing was unavailable: {exc.code}")
            return []
        total = 0
        records: list[ArtifactRecord] = []
        for item in metadata:
            if len(records) >= 100:
                self.ledger.warn("Sandbox artifact count limit reached")
                break
            name = item.get("name")
            if not isinstance(name, str):
                continue
            try:
                size = int(item.get("size", 0))
            except (TypeError, ValueError):
                continue
            if size <= 0 or size > self.settings.sandbox_max_artifact_bytes:
                continue
            if total + size > self.settings.sandbox_max_artifact_total_bytes:
                self.ledger.warn("Sandbox artifact total size limit reached")
                break
            local = self._artifact_path(session_id, name)
            if local is None:
                self.ledger.warn("An unsafe sandbox artifact name was rejected")
                continue
            try:
                data = await self.sandbox.artifact(
                    session_id,
                    name,
                    max_bytes=min(self.settings.sandbox_max_artifact_bytes, self.settings.sandbox_max_artifact_total_bytes - total),
                )
            except SandboxError as exc:
                self.ledger.warn(f"Sandbox artifact download failed: {exc.code}")
                continue
            digest = hashlib.sha256(data).hexdigest()
            expected = item.get("sha256")
            if isinstance(expected, str) and expected and expected.lower() != digest:
                self.ledger.warn("Sandbox artifact checksum mismatch was rejected")
                continue
            try:
                local.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                self.ledger.warn("Sandbox artifact could not be stored")
                continue
            total += len(data)
            record = ArtifactRecord(
                name=name,
                size=len(data),
                sha256=digest,
                content_type=str(item.get("content_type", "application/octet-stream"))[:128],
                local_path=str(local),
            )
            records.append(record)
            self.ledger.add_artifact(record)
        return records

    def _artifact_path(self, session_id: str, name: str) -> Path | None:
        if not name or "\x00" in name or "\\" in name or name.startswith("/"):
            return None
        parts = PurePosixPath(name).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return None
        session_root = self.artifact_root / session_id
        local = session_root.joinpath(*parts)
        try:
            resolved_parent = local.parent.resolve()
            session_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.artifact_root not in resolved_parent.parents and resolved_parent != self.artifact_root:
                return None
        except OSError:
            return None
        return local

    async def _analyze_url(self, arguments: dict[str, Any]) -> ToolResult:
        if arguments:
            return ToolResult(False, "This tool takes no arguments.", error_code="invalid_arguments")
        run = self._runs.get("url_evidence")
        if run is None or run.evidence is None:
            return ToolResult(False, "URL sandbox evidence is not available.", error_code="missing_evidence")
        data = self.url_investigator.analyze(self.ledger, run.evidence)
        return ToolResult(
            True,
            "URL evidence was converted into structured findings.",
            data if isinstance(data, dict) else {},
        )

    async def _analyze_file(self, arguments: dict[str, Any]) -> ToolResult:
        if arguments:
            return ToolResult(False, "This tool takes no arguments.", error_code="invalid_arguments")
        run = self._runs.get("file_evidence")
        if run is None or run.evidence is None:
            return ToolResult(False, "File sandbox evidence is not available.", error_code="missing_evidence")
        data = self.file_investigator.analyze(self.ledger, run.evidence)
        return ToolResult(
            True,
            "File evidence was converted into structured findings.",
            data if isinstance(data, dict) else {},
        )

    async def _analyze_video(self, arguments: dict[str, Any]) -> ToolResult:
        if arguments:
            return ToolResult(False, "This tool takes no arguments.", error_code="invalid_arguments")
        run = self._runs.get("file_evidence")
        if run is None or run.evidence is None:
            return ToolResult(False, "Video sandbox evidence is not available.", error_code="missing_evidence")
        data = await self.video_investigator.analyze(
            self.ledger,
            run.evidence,
            artifacts=run.artifacts,
        )
        return ToolResult(
            True,
            "Video evidence was assessed with the configured capabilities.",
            data if isinstance(data, dict) else {},
        )

    async def _terminal_command(self, arguments: dict[str, Any]) -> ToolResult:
        if not self.settings.terminal_enabled:
            return ToolResult(False, "Terminal tools are disabled.", error_code="terminal_disabled")
        command = arguments.get("command")
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            return ToolResult(False, "Terminal command must be an array of strings.", error_code="invalid_arguments")
        unknown = set(arguments) - {"command", "purpose"}
        if unknown:
            return ToolResult(False, "Invalid terminal arguments.", error_code="invalid_arguments")
        purpose = safe_text(arguments.get("purpose", "Inspect a workspace file"), 500)
        if self.settings.terminal_requires_approval or self.approval.mode == "deny":
            approved = await self.approval.request(
                action="run_readonly_command",
                purpose=purpose,
                risk="medium",
                details={"command": " ".join(item[:128] for item in command[:12])},
            )
            if not approved:
                return ToolResult(False, "Terminal command was not approved.", error_code="not_approved")
        result = await self.terminal.run(command)
        self.ledger.add(
            source="agent.terminal",
            category="tool_output",
            title="Read-only terminal command completed" if not result.timed_out else "Read-only terminal command timed out",
            severity="info",
            confidence=0.7,
            description="Terminal output is untrusted data and is not a security verdict.",
            data={
                "command": result.command,
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            code="terminal_output",
        )
        return ToolResult(
            not result.timed_out and result.returncode == 0,
            "Read-only terminal command completed.",
            {
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            "terminal_timeout" if result.timed_out else "terminal_failed" if result.returncode != 0 else None,
        )


class ToolError(RuntimeError):
    pass
