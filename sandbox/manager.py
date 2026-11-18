from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import ipaddress
import json
import logging
import os
import shutil
import socket
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import ValidationError

from . import config, network_policy, security
from .protocol import (
    ArtifactInfo,
    CreateSessionRequest,
    ErrorDetail,
    HealthResponse,
    InvestigationAccepted,
    SessionCreated,
    SessionList,
    SessionStatus,
    TerminationResult,
)

logger = logging.getLogger("trinetra.sandbox")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _structured_log(event: dict[str, Any]) -> None:
    try:
        logger.info(json.dumps(security.sanitize_evidence(event), separators=(",", ":"), default=str))
    except Exception:
        logger.info(json.dumps({"event": "log_error"}))


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _raise_api(status_code: int, code: str, message: str) -> None:
    raise HTTPException(status_code=status_code, detail=_error(code, message))


@dataclass
class WorkerEnvironment:
    session_id: str
    container: Any = None
    network: Any = None
    isolation: network_policy.HostNetworkIsolation | None = None
    resolver: network_policy.FilteringDNSResolver | None = None
    disposed: bool = False


@dataclass
class CollectedEvidence:
    data: dict[str, Any] | None = None
    artifacts: list[dict[str, Any]] = field(default_factory=list)


class DockerSandboxRuntime:
    def __init__(self, settings: config.Settings) -> None:
        self.settings = settings
        self.client: Any = None
        self.docker: Any = None
        self.types: Any = None
        self._lock = asyncio.Lock()
        self.owner = f"{socket.gethostname()}:{os.getpid()}"

    async def startup(self) -> None:
        try:
            import docker
            from docker import types
        except Exception as exc:
            raise RuntimeError("the docker Python SDK is required") from exc
        self.docker = docker
        self.types = types
        self.client = await asyncio.to_thread(
            docker.DockerClient,
            base_url=self.settings.docker_base_url,
            timeout=120,
            version="auto",
        )
        await self._call(self.client.ping)
        try:
            await self._call(self.client.images.get, self.settings.worker_image)
        except Exception as exc:
            raise RuntimeError(f"worker image is not available: {self.settings.worker_image}") from exc
        if self.settings.enable_host_firewall:
            probe = network_policy.HostNetworkIsolation(
                session_id="preflight",
                subnet="198.18.0.0/30",
                gateway="198.18.0.1",
                resolver_port=self.settings.dns_port,
                enabled=True,
                allow_unsafe=False,
                logger=_structured_log,
            )
            await asyncio.to_thread(probe.verify)
        if self.settings.manage_orphans:
            await self.recover_orphans()

    async def shutdown(self) -> None:
        if self.client is not None:
            try:
                await asyncio.to_thread(self.client.close)
            except Exception:
                pass
            self.client = None

    async def _call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        async with self._lock:
            return await asyncio.to_thread(func, *args, **kwargs)

    def _labels(self, session_id: str) -> dict[str, str]:
        return {
            "trinetra.sandbox": "true",
            "trinetra.sandbox.managed": "true",
            "trinetra.sandbox.session": session_id,
            "trinetra.sandbox.owner": self.owner,
        }

    async def recover_orphans(self) -> None:
        try:
            containers = await self._call(
                self.client.containers.list,
                all=True,
                filters={"label": "trinetra.sandbox.managed=true"},
            )
        except Exception:
            containers = []
        for container in containers:
            try:
                await self._call(container.remove, force=True, v=True)
                _structured_log({"event": "orphan_container_removed", "container": container.id[:12]})
            except Exception:
                continue
        try:
            networks = await self._call(
                self.client.networks.list,
                filters={"label": "trinetra.sandbox.managed=true"},
            )
        except Exception:
            networks = []
        for network in networks:
            await self._remove_orphan_network(network)

    async def _remove_orphan_network(self, network: Any) -> None:
        try:
            await self._call(network.reload)
            attrs = network.attrs
            labels = attrs.get("Labels") or {}
            session_id = labels.get("trinetra.sandbox.session", "orphan")
            ipam = attrs.get("IPAM", {}).get("Config") or []
            if ipam:
                subnet = ipam[0].get("Subnet")
                gateway = ipam[0].get("Gateway")
            else:
                subnet = None
                gateway = None
            if subnet and not gateway:
                gateway = str(ipaddress.ip_network(subnet, strict=False)[1])
            if subnet and gateway:
                isolation = network_policy.HostNetworkIsolation(
                    session_id=session_id,
                    subnet=subnet,
                    gateway=gateway,
                    resolver_port=self.settings.dns_port,
                    enabled=self.settings.enable_host_firewall,
                    allow_unsafe=self.settings.allow_unsafe_network,
                    logger=_structured_log,
                )
                await asyncio.to_thread(isolation.remove)
            await self._call(network.remove)
            _structured_log({"event": "orphan_network_removed", "network": network.id[:12]})
        except Exception:
            return

    def _security_options(self) -> list[str]:
        options = ["no-new-privileges:true"]
        if self.settings.seccomp_profile is not None:
            profile = Path(self.settings.seccomp_profile).expanduser().resolve()
            try:
                loaded = json.loads(profile.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("sandbox seccomp profile is invalid") from exc
            options.append(f"seccomp={json.dumps(loaded, separators=(',', ':'))}")
        if self.settings.apparmor_profile:
            options.append(f"apparmor={self.settings.apparmor_profile}")
        return options

    def _worker_kwargs(self, session_id: str, network_name: str, gateway: str) -> dict[str, Any]:
        uid = self.settings.worker_uid
        gid = self.settings.worker_gid
        ulimits = [
            self.types.Ulimit(name="nofile", soft=1024, hard=1024),
            self.types.Ulimit(name="nproc", soft=self.settings.worker_pids, hard=self.settings.worker_pids),
            self.types.Ulimit(name="core", soft=0, hard=0),
        ]
        log_config = self.types.LogConfig(
            type="json-file",
            config={"max-size": "5m", "max-file": "1"},
        )
        kwargs: dict[str, Any] = {
            "image": self.settings.worker_image,
            "command": ["python", "-m", "sandbox.worker"],
            "name": f"trinetra-worker-{session_id[:12]}",
            "detach": True,
            "user": f"{uid}:{gid}",
            "working_dir": "/app",
            "hostname": "sandbox",
            "environment": {
                "HOME": "/tmp",
                "TMPDIR": "/tmp",
                "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            "network": network_name,
            "dns": [gateway] if self.settings.enable_host_firewall else [],
            "read_only": True,
            "tmpfs": {
                "/tmp": f"rw,nosuid,nodev,noexec,size={self.settings.worker_tmpfs_bytes},uid={uid},gid={gid},mode=0700",
                "/run": "rw,nosuid,nodev,noexec,size=16m,mode=0755",
            },
            "volumes": ["/work"],
            "cap_drop": ["ALL"],
            "cap_add": [],
            "security_opt": self._security_options(),
            "pids_limit": self.settings.worker_pids,
            "mem_limit": self.settings.worker_memory_bytes,
            "memswap_limit": self.settings.worker_memory_bytes,
            "nano_cpus": int(self.settings.worker_cpus * 1_000_000_000),
            "shm_size": self.settings.worker_shm_bytes,
            "ulimits": ulimits,
            "log_config": log_config,
            "privileged": False,
            "devices": [],
            "auto_remove": False,
            "stdin_open": False,
            "tty": False,
            "init": True,
            "labels": self._labels(session_id),
        }
        if self.settings.docker_runtime:
            kwargs["runtime"] = self.settings.docker_runtime
        return kwargs

    async def start(self, session_id: str, task: dict[str, Any], input_path: Path | None) -> WorkerEnvironment:
        env = WorkerEnvironment(session_id=session_id)
        try:
            network_name = f"{self.settings.network_name_prefix}-{session_id[:12]}"
            env.network = await self._call(
                self.client.networks.create,
                network_name,
                driver="bridge",
                enable_ipv6=False,
                options={
                    "com.docker.network.bridge.enable_icc": "false",
                    "com.docker.network.bridge.enable_ip_masquerade": "true",
                },
                labels=self._labels(session_id),
            )
            await self._call(env.network.reload)
            ipam = env.network.attrs.get("IPAM", {}).get("Config") or []
            if not ipam or not ipam[0].get("Subnet"):
                raise RuntimeError("sandbox network has no IPv4 subnet")
            subnet = ipam[0]["Subnet"]
            gateway = ipam[0].get("Gateway")
            if not gateway:
                gateway = str(ipaddress.ip_network(subnet, strict=False)[1])
            env.isolation = network_policy.HostNetworkIsolation(
                session_id=session_id,
                subnet=subnet,
                gateway=gateway,
                resolver_port=self.settings.dns_port,
                enabled=self.settings.enable_host_firewall,
                allow_unsafe=self.settings.allow_unsafe_network,
                logger=_structured_log,
            )
            await asyncio.to_thread(env.isolation.install)
            if self.settings.enable_host_firewall:
                env.resolver = network_policy.FilteringDNSResolver(
                    [gateway],
                    port=self.settings.dns_port,
                    upstreams=self.settings.dns_upstreams,
                    logger=_structured_log,
                )
                await env.resolver.start()
            env.container = await self._call(
                self.client.containers.create,
                **self._worker_kwargs(session_id, network_name, gateway),
            )
            await self._call(env.container.start)
            task_payload = security.json_bytes(task)
            files: dict[str, bytes] = {}
            if input_path is not None:
                files["input/input.bin"] = await asyncio.to_thread(Path(input_path).read_bytes)
            files["task.json"] = task_payload
            archive = security.build_tar(files, uid=self.settings.worker_uid, gid=self.settings.worker_gid)
            await self._call(env.container.put_archive, "/work", archive)
            _structured_log({"event": "worker_started", "session_id": session_id, "container": env.container.id[:12]})
            return env
        except BaseException:
            await self.dispose(env)
            raise

    async def state(self, env: WorkerEnvironment) -> dict[str, Any]:
        if env.container is None:
            return {"status": "missing", "running": False, "exit_code": None}
        try:
            await self._call(env.container.reload)
            state = env.container.attrs.get("State") or {}
            return {
                "status": state.get("Status"),
                "running": bool(state.get("Running")),
                "exit_code": state.get("ExitCode"),
                "oom_killed": bool(state.get("OOMKilled")),
                "error": security.sanitize_text(state.get("Error", ""), 512),
            }
        except Exception:
            return {"status": "missing", "running": False, "exit_code": None}

    async def poll_status(self, env: WorkerEnvironment) -> dict[str, Any] | None:
        if env.container is None:
            return None
        command = [
            "python", "-c",
            "import sys;sys.stdout.buffer.write(open('/work/status.json','rb').read(131072))",
        ]
        try:
            result = await self._call(
                env.container.exec_run,
                command,
                demux=False,
                user=f"{self.settings.worker_uid}:{self.settings.worker_gid}",
            )
        except Exception:
            return None
        if result.exit_code != 0 or not result.output:
            return None
        payload = result.output[:131072]
        try:
            parsed = json.loads(payload.decode("utf-8", "replace"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    async def logs(self, env: WorkerEnvironment, max_bytes: int) -> str:
        if env.container is None:
            return ""
        try:
            raw = await self._call(
                env.container.logs,
                stdout=True,
                stderr=True,
                tail=2000,
            )
        except Exception:
            return ""
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8", "replace")
        raw = bytes(raw)[-max_bytes:]
        return security.sanitize_log(raw.decode("utf-8", "replace"), max_length=max_bytes)

    async def stop(self, env: WorkerEnvironment) -> None:
        if env.container is None:
            return
        with contextlib.suppress(Exception):
            await self._call(env.container.kill)

    async def collect(self, env: WorkerEnvironment, destination: Path) -> CollectedEvidence:
        if env.container is None:
            return CollectedEvidence()
        destination = Path(destination)
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(prefix=".collect-", dir=str(destination.parent)))
        try:
            stream, _stat = await self._call(env.container.get_archive, "/work/evidence")
            try:
                archive = await asyncio.to_thread(
                    security.read_stream_bounded,
                    stream,
                    self.settings.max_evidence_bytes,
                )
            finally:
                close = getattr(stream, "close", None)
                if close is not None:
                    with contextlib.suppress(Exception):
                        close()
            await asyncio.to_thread(
                security.safe_extract_tar,
                archive,
                staging,
                max_bytes=self.settings.max_evidence_bytes,
                max_files=self.settings.max_evidence_files,
            )
            nested = staging / "evidence"
            if nested.is_dir() and not (staging / "results.json").is_file():
                payload_root = nested
            else:
                payload_root = staging
            results_path = payload_root / "results.json"
            if not results_path.is_file() or results_path.is_symlink():
                return CollectedEvidence()
            if results_path.stat().st_size > self.settings.max_evidence_bytes:
                return CollectedEvidence()
            try:
                data = json.loads(results_path.read_text(encoding="utf-8", errors="replace"))
                if not isinstance(data, dict):
                    return CollectedEvidence()
                sanitized = security.sanitize_evidence(data, max_string=65536)
                if len(security.json_bytes(sanitized)) > self.settings.max_evidence_bytes:
                    return CollectedEvidence()
            except Exception:
                return CollectedEvidence()
            for item in payload_root.iterdir():
                os.replace(item, destination / item.name)
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            return CollectedEvidence()
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        artifacts: list[dict[str, Any]] = []
        total = 0
        for path in sorted(destination.rglob("*")):
            if len(artifacts) >= self.settings.max_artifacts:
                break
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(destination).as_posix()
            if relative == "results.json":
                continue
            try:
                name = security.require_safe_artifact_name(relative)
            except security.SecurityError:
                continue
            size = path.stat().st_size
            if size <= 0 or size > self.settings.max_artifact_bytes:
                continue
            total += size
            if total > self.settings.max_evidence_bytes:
                break
            prefix = await asyncio.to_thread(security.read_prefix, path, 16)
            artifacts.append(
                {
                    "name": name,
                    "size": size,
                    "sha256": await asyncio.to_thread(security.sha256_file, path),
                    "content_type": security.artifact_content_type(name, prefix),
                }
            )
        return CollectedEvidence(data=sanitized, artifacts=artifacts)

    async def dispose(self, env: WorkerEnvironment) -> None:
        if env.disposed:
            return
        env.disposed = True
        if env.container is not None:
            with contextlib.suppress(Exception):
                await self.stop(env)
            with contextlib.suppress(Exception):
                await self._call(env.container.remove, force=True, v=True)
            env.container = None
        if env.resolver is not None:
            with contextlib.suppress(Exception):
                await env.resolver.stop()
            env.resolver = None
        if env.isolation is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(env.isolation.remove)
            env.isolation = None
        if env.network is not None:
            with contextlib.suppress(Exception):
                await self._call(env.network.remove)
            env.network = None


@dataclass
class Session:
    id: str
    kind: str
    status: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    options: dict[str, Any]
    task: dict[str, Any]
    workdir: Path
    input_path: Path | None = None
    phase: str = "created"
    progress: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: dict[str, str] | None = None
    evidence: dict[str, Any] | None = None
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    artifact_paths: dict[str, Path] = field(default_factory=dict)
    logs: str = ""
    environment: WorkerEnvironment | None = None
    task_handle: asyncio.Task[Any] | None = None
    terminate_requested: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
            "expires_at": _iso(self.expires_at),
            "started_at": _iso(self.started_at) if self.started_at else None,
            "completed_at": _iso(self.completed_at) if self.completed_at else None,
            "phase": self.phase,
            "progress": self.progress,
            "error": self.error,
            "evidence_available": self.evidence is not None,
            "artifacts": [
                ArtifactInfo(
                    name=item["name"],
                    size=int(item["size"]),
                    sha256=str(item["sha256"]),
                    content_type=str(item["content_type"]),
                ).model_dump()
                for item in self.artifacts
            ],
        }


class SandboxService:
    def __init__(self, settings: config.Settings, runtime: Any) -> None:
        self.settings = settings
        self.runtime = runtime
        self.sessions: dict[str, Session] = {}
        self.sweeper: asyncio.Task[Any] | None = None
        self.started = False

    async def startup(self) -> None:
        self.settings.validate()
        self.settings.prepare_evidence_root()
        await self.runtime.startup()
        self.started = True
        self.sweeper = asyncio.create_task(self._sweep_loop())

    async def shutdown(self) -> None:
        if self.sweeper is not None:
            self.sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.sweeper
            self.sweeper = None
        for session in list(self.sessions.values()):
            try:
                await self.terminate(session.id)
                await self.destroy(session.id)
            except Exception:
                continue
        with contextlib.suppress(Exception):
            await self.runtime.shutdown()
        self.started = False

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(self.settings.sweeper_interval_seconds)
            now = _utc_now()
            for session in list(self.sessions.values()):
                if session.expires_at > now:
                    continue
                try:
                    await self.terminate(session.id)
                    await self.destroy(session.id)
                    _structured_log({"event": "session_expired", "session_id": session.id})
                except Exception:
                    continue

    def _session(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)
        if session is None:
            _raise_api(status.HTTP_404_NOT_FOUND, "not_found", "sandbox session not found")
        return session

    def _live_count(self) -> int:
        return sum(1 for session in self.sessions.values() if session.status in {"created", "running"})

    def _make_workdir(self, session_id: str) -> Path:
        root = self.settings.prepare_evidence_root()
        path = Path(tempfile.mkdtemp(prefix=f"trinetra-session-{session_id[:12]}-", dir=root))
        path.chmod(0o700)
        return path

    def _remove_workdir(self, session: Session) -> None:
        try:
            resolved = security.ensure_within(self.settings.prepare_evidence_root(), session.workdir)
            shutil.rmtree(resolved, ignore_errors=True)
        except Exception:
            pass

    def _remove_inputs(self, session: Session) -> None:
        for relative in ("task.json", "input"):
            target = session.workdir / relative
            try:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target, ignore_errors=True)
                elif target.exists() or target.is_symlink():
                    target.unlink()
            except Exception:
                continue

    async def create_session(self, request: CreateSessionRequest) -> Session:
        if self._live_count() >= self.settings.max_sessions:
            _raise_api(status.HTTP_429_TOO_MANY_REQUESTS, "capacity_exceeded", "sandbox session capacity is exhausted")
        options = request.options.model_dump()
        options["max_redirects"] = min(int(options["max_redirects"]), self.settings.max_redirects)
        options["timeout_seconds"] = max(
            5,
            min(int(options["timeout_seconds"]), self.settings.max_timeout_seconds),
        )
        session_id = uuid.uuid4().hex
        created = _utc_now()
        workdir = self._make_workdir(session_id)
        input_path: Path | None = None
        input_meta: dict[str, str] | None = None
        try:
            if request.kind == "url":
                try:
                    validated = network_policy.validate_url(request.url or "")
                except network_policy.NetworkPolicyError as exc:
                    _raise_api(status.HTTP_400_BAD_REQUEST, exc.code, exc.message)
                target_url = validated.url
            else:
                payload = request.file
                if payload is None:
                    _raise_api(status.HTTP_400_BAD_REQUEST, "invalid_request", "file payload is required")
                encoded = payload.content_base64
                if len(encoded) > (self.settings.max_upload_bytes * 4 // 3) + 8:
                    _raise_api(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file_too_large", "uploaded file exceeds the limit")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    _raise_api(status.HTTP_400_BAD_REQUEST, "invalid_file", "file content is not valid base64")
                if not raw:
                    _raise_api(status.HTTP_400_BAD_REQUEST, "invalid_file", "uploaded file is empty")
                if len(raw) > self.settings.max_upload_bytes:
                    _raise_api(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file_too_large", "uploaded file exceeds the limit")
                digest = security.sha256_bytes(raw)
                if payload.sha256 and digest.lower() != payload.sha256.lower():
                    _raise_api(status.HTTP_400_BAD_REQUEST, "checksum_mismatch", "uploaded file checksum does not match")
                filename = security.sanitize_filename(payload.filename)
                input_dir = workdir / "input"
                input_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                input_path = input_dir / "input.bin"
                descriptor = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                input_meta = {
                    "filename": filename,
                    "container_path": "/work/input/input.bin",
                    "sha256": digest,
                    "size": str(len(raw)),
                }
                target_url = None
            task: dict[str, Any] = {
                "schema_version": 1,
                "session_id": session_id,
                "kind": request.kind,
                "url": target_url if request.kind == "url" else None,
                "input": input_meta,
                "options": options,
                "limits": {
                    "max_http_body_bytes": self.settings.max_http_body_bytes,
                    "max_download_bytes": self.settings.max_download_bytes,
                    "max_evidence_bytes": self.settings.max_evidence_bytes,
                    "max_artifact_bytes": self.settings.max_artifact_bytes,
                    "max_artifacts": self.settings.max_artifacts,
                },
            }
            security.write_json_atomic(workdir / "task.json", task)
        except Exception:
            shutil.rmtree(workdir, ignore_errors=True)
            raise
        session = Session(
            id=session_id,
            kind=request.kind,
            status="created",
            created_at=created,
            updated_at=created,
            expires_at=created + timedelta(seconds=self.settings.session_ttl_seconds),
            options=options,
            task=task,
            workdir=workdir,
            input_path=input_path,
        )
        self.sessions[session_id] = session
        _structured_log({"event": "session_created", "session_id": session_id, "kind": request.kind})
        return session

    async def start_session(self, session_id: str) -> Session:
        session = self._session(session_id)
        async with session.lock:
            if session.status != "created":
                _raise_api(status.HTTP_409_CONFLICT, "invalid_state", "session cannot be started in its current state")
            session.status = "running"
            session.started_at = _utc_now()
            session.updated_at = session.started_at
            session.phase = "starting"
            session.progress = 1
            session.task_handle = asyncio.create_task(self._run_session(session))
        return session

    async def _run_session(self, session: Session) -> None:
        env: WorkerEnvironment | None = None
        timed_out = False
        terminated = False
        exit_code: int | None = None
        collected = CollectedEvidence()
        try:
            env = await self.runtime.start(session.id, session.task, session.input_path)
            session.environment = env
            self._remove_inputs(session)
            timeout_seconds = int(session.options["timeout_seconds"])
            deadline = time.monotonic() + timeout_seconds
            last_poll = 0.0
            while True:
                if session.terminate_requested:
                    terminated = True
                    session.status = "terminated"
                    session.phase = "terminated"
                    await self.runtime.stop(env)
                    break
                state = await self.runtime.state(env)
                if not state.get("running"):
                    exit_code = state.get("exit_code")
                    if state.get("oom_killed"):
                        session.error = _error("worker_oom", "sandbox worker was killed for exceeding memory limits")
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    session.status = "timed_out"
                    session.phase = "timed_out"
                    session.error = _error("timeout", "investigation exceeded its time limit")
                    await self.runtime.stop(env)
                    for _ in range(20):
                        state = await self.runtime.state(env)
                        if not state.get("running"):
                            exit_code = state.get("exit_code")
                            break
                        await asyncio.sleep(0.25)
                    break
                now = time.monotonic()
                if now - last_poll >= 0.75:
                    last_poll = now
                    status_payload = await self.runtime.poll_status(env)
                    if isinstance(status_payload, dict):
                        phase = security.sanitize_text(status_payload.get("phase", session.phase), 64)
                        if phase:
                            session.phase = phase
                        try:
                            session.progress = max(0, min(100, int(status_payload.get("progress", session.progress))))
                        except (TypeError, ValueError):
                            pass
                        session.updated_at = _utc_now()
                await asyncio.sleep(self.settings.poll_interval_seconds)
            try:
                session.logs = await self.runtime.logs(env, self.settings.max_log_bytes)
            except Exception:
                session.logs = ""
            if not terminated:
                try:
                    collected = await self.runtime.collect(env, session.workdir / "evidence")
                except Exception:
                    collected = CollectedEvidence()
            if collected.data is not None:
                collected.data["session_id"] = session.id
                session.evidence = collected.data
                session.artifacts = collected.artifacts
                session.artifact_paths = {
                    item["name"]: session.workdir / "evidence" / item["name"]
                    for item in collected.artifacts
                    if isinstance(item.get("name"), str)
                }
            if terminated:
                session.status = "terminated"
                session.phase = "terminated"
            elif timed_out:
                session.status = "timed_out"
                session.phase = "timed_out"
            elif session.error is not None and session.error.get("code") == "worker_oom":
                session.status = "failed"
                session.phase = "failed"
            elif exit_code not in (0, None):
                session.status = "failed"
                session.phase = "failed"
                session.error = session.error or _error("worker_failed", f"worker exited with code {exit_code}")
            elif collected.data is None:
                session.status = "failed"
                session.phase = "failed"
                session.error = session.error or _error("evidence_missing", "worker produced no evidence")
            elif collected.data.get("status") == "failed":
                session.status = "failed"
                session.phase = "failed"
                error_info = collected.data.get("error") if isinstance(collected.data.get("error"), dict) else {}
                session.error = _error(
                    str(error_info.get("code", "worker_failed")),
                    security.sanitize_text(error_info.get("message", "worker reported failure"), 512),
                )
            else:
                session.status = "completed"
                session.phase = "completed"
                session.progress = 100
        except asyncio.CancelledError:
            terminated = True
            session.terminate_requested = True
            session.status = "terminated"
            session.phase = "terminated"
            with contextlib.suppress(Exception):
                if env is not None:
                    await self.runtime.stop(env)
            raise
        except Exception as exc:
            session.status = "failed"
            session.phase = "failed"
            session.error = _error("sandbox_error", "sandbox execution failed")
            _structured_log(
                {
                    "event": "session_error",
                    "session_id": session.id,
                    "error_type": type(exc).__name__,
                    "error": security.sanitize_text(str(exc), 512),
                }
            )
        finally:
            self._remove_inputs(session)
            if not session.logs and env is not None:
                with contextlib.suppress(Exception):
                    session.logs = await self.runtime.logs(env, self.settings.max_log_bytes)
            if env is not None:
                with contextlib.suppress(Exception):
                    await self.runtime.dispose(env)
            session.environment = None
            session.completed_at = session.completed_at or _utc_now()
            session.updated_at = _utc_now()
            if session.status == "running":
                session.status = "failed"
                session.phase = "failed"
                session.error = session.error or _error("sandbox_error", "sandbox session ended unexpectedly")
            _structured_log({"event": "session_finished", "session_id": session.id, "status": session.status})

    async def terminate(self, session_id: str) -> Session:
        session = self._session(session_id)
        async with session.lock:
            if session.status in {"completed", "failed", "timed_out", "terminated"}:
                return session
            session.terminate_requested = True
            task = session.task_handle
            if task is None:
                session.status = "terminated"
                session.phase = "terminated"
                session.completed_at = session.completed_at or _utc_now()
                session.updated_at = _utc_now()
                return session
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        async with session.lock:
            if session.status not in {"completed", "failed", "timed_out"}:
                session.status = "terminated"
                session.phase = "terminated"
            session.completed_at = session.completed_at or _utc_now()
            session.updated_at = _utc_now()
            session.terminate_requested = True
            session.task_handle = None
        return session

    async def destroy(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session is None:
            _raise_api(status.HTTP_404_NOT_FOUND, "not_found", "sandbox session not found")
        await self.terminate(session_id)
        async with session.lock:
            self.sessions.pop(session_id, None)
            session.evidence = None
            session.artifacts = []
            session.artifact_paths = {}
        self._remove_workdir(session)
        _structured_log({"event": "session_destroyed", "session_id": session_id})

    def status_payload(self, session: Session) -> dict[str, Any]:
        return session.public()

    def evidence_payload(self, session: Session) -> dict[str, Any]:
        if session.evidence is None:
            _raise_api(status.HTTP_409_CONFLICT, "evidence_pending", "evidence is not available yet")
        return session.evidence

    def artifact(self, session: Session, artifact_path: str) -> tuple[Path, dict[str, Any]]:
        if session.evidence is None:
            _raise_api(status.HTTP_409_CONFLICT, "evidence_pending", "evidence is not available yet")
        try:
            name = security.require_safe_artifact_name(artifact_path)
        except security.SecurityError:
            _raise_api(status.HTTP_404_NOT_FOUND, "artifact_not_found", "artifact not found")
        metadata = next((item for item in session.artifacts if item.get("name") == name), None)
        if metadata is None:
            _raise_api(status.HTTP_404_NOT_FOUND, "artifact_not_found", "artifact not found")
        base = session.workdir / "evidence"
        path = base / name
        try:
            resolved = security.ensure_within(base, path)
        except security.SecurityError:
            _raise_api(status.HTTP_404_NOT_FOUND, "artifact_not_found", "artifact not found")
        if not resolved.is_file() or resolved.is_symlink():
            _raise_api(status.HTTP_404_NOT_FOUND, "artifact_not_found", "artifact not found")
        return resolved, metadata


class BodyLimitMiddleware:
    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send, code="invalid_content_length")
                return
        total = 0
        started = False

        async def limited_receive() -> Any:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def wrapped_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, wrapped_send)
        except _BodyTooLarge:
            if not started:
                await self._reject(send, code="request_too_large")

    async def _reject(self, send: Any, code: str = "request_too_large") -> None:
        body = json.dumps({"error": {"code": code, "message": "request body exceeds the configured limit"}}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass


def create_app(settings: config.Settings | None = None, runtime: Any = None) -> FastAPI:
    settings = settings or config.Settings.from_env()
    runtime = runtime or DockerSandboxRuntime(settings)
    service = SandboxService(settings, runtime)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        await service.startup()
        app.state.service = service
        try:
            yield
        finally:
            await service.shutdown()

    app = FastAPI(
        title="Trinetra Sandbox Manager",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.service = service
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.api_request_limit_bytes)

    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable[[Request], Any]) -> Any:
        request_id = security.sanitize_text(request.headers.get("x-request-id", ""), 128) or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail and "message" in detail:
            error = detail
        elif isinstance(detail, str):
            error = _error("request_failed", security.sanitize_text(detail, 512))
        else:
            error = _error("request_failed", "request failed")
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": error, "request_id": getattr(request.state, "request_id", None)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": _error("validation_error", "request validation failed"),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        _structured_log(
            {
                "event": "unhandled_api_error",
                "error_type": type(exc).__name__,
                "error": security.sanitize_text(str(exc), 512),
            }
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": _error("internal_error", "internal server error"),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    async def require_token(
        request: Request,
        authorization: str | None = Header(default=None),
        x_sandbox_token: str | None = Header(default=None),
    ) -> None:
        token = x_sandbox_token
        if authorization:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer":
                token = value.strip()
        if not security.token_matches(token, settings.api_token):
            _raise_api(status.HTTP_401_UNAUTHORIZED, "unauthorized", "authentication required")

    router = APIRouter(prefix="/v1", dependencies=[Depends(require_token)])

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz() -> HealthResponse:
        return HealthResponse(status="ok", service="trinetra-sandbox", version="1.0.0")

    @router.post("/sessions", response_model=SessionCreated, status_code=status.HTTP_201_CREATED)
    async def create_session(payload: CreateSessionRequest) -> SessionCreated:
        session = await service.create_session(payload)
        return SessionCreated(
            id=session.id,
            status=session.status,
            created_at=_iso(session.created_at),
            expires_at=_iso(session.expires_at),
        )

    @router.get("/sessions", response_model=SessionList)
    async def list_sessions() -> SessionList:
        return SessionList(sessions=[SessionStatus(**service.status_payload(session)) for session in service.sessions.values()])

    @router.get("/sessions/{session_id}", response_model=SessionStatus)
    async def get_session(session_id: str) -> SessionStatus:
        return SessionStatus(**service.status_payload(service._session(session_id)))

    @router.post("/sessions/{session_id}/investigate", response_model=InvestigationAccepted, status_code=status.HTTP_202_ACCEPTED)
    async def investigate(session_id: str) -> InvestigationAccepted:
        session = await service.start_session(session_id)
        return InvestigationAccepted(id=session.id, status=session.status)

    @router.get("/sessions/{session_id}/evidence")
    async def get_evidence(session_id: str) -> JSONResponse:
        session = service._session(session_id)
        return JSONResponse(content=service.evidence_payload(session))

    @router.get("/sessions/{session_id}/logs")
    async def get_logs(session_id: str) -> dict[str, Any]:
        session = service._session(session_id)
        return {"id": session.id, "logs": security.sanitize_log(session.logs, settings.max_log_bytes)}

    @router.get("/sessions/{session_id}/artifacts")
    async def list_artifacts(session_id: str) -> dict[str, Any]:
        session = service._session(session_id)
        return {"id": session.id, "artifacts": [ArtifactInfo(**item).model_dump() for item in session.artifacts]}

    @router.get("/sessions/{session_id}/artifacts/{artifact_path:path}")
    async def get_artifact(session_id: str, artifact_path: str) -> FileResponse:
        session = service._session(session_id)
        path, metadata = service.artifact(session, artifact_path)
        content_type = security.artifact_content_type(metadata["name"], security.read_prefix(path, 16))
        return FileResponse(
            path=path,
            media_type=content_type,
            filename=metadata["name"],
            headers={
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Cache-Control": "no-store",
            },
        )

    @router.post("/sessions/{session_id}/terminate", response_model=TerminationResult)
    async def terminate(session_id: str) -> TerminationResult:
        session = await service.terminate(session_id)
        return TerminationResult(id=session.id, status=session.status)

    @router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def destroy(session_id: str) -> Response:
        await service.destroy(session_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    env_settings = config.Settings.from_env()
    uvicorn.run(
        "sandbox.manager:app",
        host=env_settings.bind_host,
        port=env_settings.bind_port,
        workers=1,
        log_level="info",
    )
