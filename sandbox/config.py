from __future__ import annotations

import ipaddress
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SECCOMP_PROFILE = BASE_DIR / "docker" / "seccomp-worker.json"


def _env_str(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _env_int(name: str, default: int) -> int:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_str(name)
    if raw is None:
        return default
    normalized = raw.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _env_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _env_str(name)
    if raw is None:
        return default
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    return values or default


@dataclass(frozen=True)
class Settings:
    api_token: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    docker_base_url: str = "unix:///var/run/docker.sock"
    docker_runtime: str | None = None
    worker_image: str = "trinetra-sandbox-worker:latest"
    seccomp_profile: Path | None = DEFAULT_SECCOMP_PROFILE
    apparmor_profile: str | None = None
    enable_host_firewall: bool = True
    allow_unsafe_network: bool = False
    allow_default_seccomp: bool = False
    manage_orphans: bool = True
    dns_upstreams: tuple[str, ...] = ("1.1.1.1", "9.9.9.9")
    dns_port: int = 15353
    session_ttl_seconds: int = 900
    default_timeout_seconds: int = 120
    max_timeout_seconds: int = 300
    max_sessions: int = 4
    max_redirects: int = 5
    worker_cpus: float = 1.0
    worker_memory_bytes: int = 1024 * 1024 * 1024
    worker_pids: int = 256
    worker_tmpfs_bytes: int = 512 * 1024 * 1024
    worker_work_bytes: int = 256 * 1024 * 1024
    worker_shm_bytes: int = 256 * 1024 * 1024
    max_upload_bytes: int = 25 * 1024 * 1024
    max_evidence_bytes: int = 64 * 1024 * 1024
    max_evidence_files: int = 64
    max_artifact_bytes: int = 16 * 1024 * 1024
    max_artifacts: int = 32
    max_log_bytes: int = 1024 * 1024
    max_http_body_bytes: int = 2 * 1024 * 1024
    max_download_bytes: int = 10 * 1024 * 1024
    evidence_root: Path = Path(tempfile.gettempdir()) / "trinetra-evidence"
    sweeper_interval_seconds: int = 15
    poll_interval_seconds: float = 0.5
    api_request_limit_bytes: int = 40 * 1024 * 1024
    network_name_prefix: str = "trinetra-sb"
    worker_uid: int = 10001
    worker_gid: int = 10001

    @classmethod
    def from_env(cls) -> "Settings":
        seccomp_raw = _env_str("SANDBOX_SECCOMP_PROFILE")
        seccomp = Path(seccomp_raw).expanduser() if seccomp_raw else DEFAULT_SECCOMP_PROFILE
        evidence_raw = _env_str("SANDBOX_EVIDENCE_ROOT")
        evidence_root = Path(evidence_raw).expanduser() if evidence_raw else Path(tempfile.gettempdir()) / "trinetra-evidence"
        return cls(
            api_token=_env_str("SANDBOX_API_TOKEN"),
            bind_host=_env_str("SANDBOX_BIND_HOST", "127.0.0.1") or "127.0.0.1",
            bind_port=_env_int("SANDBOX_BIND_PORT", 8765),
            docker_base_url=_env_str("SANDBOX_DOCKER_URL", "unix:///var/run/docker.sock") or "unix:///var/run/docker.sock",
            docker_runtime=_env_str("SANDBOX_DOCKER_RUNTIME"),
            worker_image=_env_str("SANDBOX_WORKER_IMAGE", "trinetra-sandbox-worker:latest") or "trinetra-sandbox-worker:latest",
            seccomp_profile=seccomp,
            apparmor_profile=_env_str("SANDBOX_APPARMOR_PROFILE"),
            enable_host_firewall=_env_bool("SANDBOX_ENABLE_HOST_FIREWALL", True),
            allow_unsafe_network=_env_bool("SANDBOX_ALLOW_UNSAFE_NETWORK", False),
            allow_default_seccomp=_env_bool("SANDBOX_ALLOW_DEFAULT_SECCOMP", False),
            manage_orphans=_env_bool("SANDBOX_MANAGE_ORPHANS", True),
            dns_upstreams=_env_csv("SANDBOX_DNS_UPSTREAMS", ("1.1.1.1", "9.9.9.9")),
            dns_port=_env_int("SANDBOX_DNS_PORT", 15353),
            session_ttl_seconds=_env_int("SANDBOX_SESSION_TTL_SECONDS", 900),
            default_timeout_seconds=_env_int("SANDBOX_DEFAULT_TIMEOUT_SECONDS", 120),
            max_timeout_seconds=_env_int("SANDBOX_MAX_TIMEOUT_SECONDS", 300),
            max_sessions=_env_int("SANDBOX_MAX_SESSIONS", 4),
            max_redirects=_env_int("SANDBOX_MAX_REDIRECTS", 5),
            worker_cpus=_env_float("SANDBOX_WORKER_CPUS", 1.0),
            worker_memory_bytes=_env_int("SANDBOX_WORKER_MEMORY_BYTES", 1024 * 1024 * 1024),
            worker_pids=_env_int("SANDBOX_WORKER_PIDS", 256),
            worker_tmpfs_bytes=_env_int("SANDBOX_WORKER_TMPFS_BYTES", 512 * 1024 * 1024),
            worker_work_bytes=_env_int("SANDBOX_WORKER_WORK_BYTES", 256 * 1024 * 1024),
            worker_shm_bytes=_env_int("SANDBOX_WORKER_SHM_BYTES", 256 * 1024 * 1024),
            max_upload_bytes=_env_int("SANDBOX_MAX_UPLOAD_BYTES", 25 * 1024 * 1024),
            max_evidence_bytes=_env_int("SANDBOX_MAX_EVIDENCE_BYTES", 64 * 1024 * 1024),
            max_evidence_files=_env_int("SANDBOX_MAX_EVIDENCE_FILES", 64),
            max_artifact_bytes=_env_int("SANDBOX_MAX_ARTIFACT_BYTES", 16 * 1024 * 1024),
            max_artifacts=_env_int("SANDBOX_MAX_ARTIFACTS", 32),
            max_log_bytes=_env_int("SANDBOX_MAX_LOG_BYTES", 1024 * 1024),
            max_http_body_bytes=_env_int("SANDBOX_MAX_HTTP_BODY_BYTES", 2 * 1024 * 1024),
            max_download_bytes=_env_int("SANDBOX_MAX_DOWNLOAD_BYTES", 10 * 1024 * 1024),
            evidence_root=evidence_root,
            sweeper_interval_seconds=_env_int("SANDBOX_SWEEPER_INTERVAL_SECONDS", 15),
            poll_interval_seconds=_env_float("SANDBOX_POLL_INTERVAL_SECONDS", 0.5),
            api_request_limit_bytes=_env_int("SANDBOX_API_REQUEST_LIMIT_BYTES", 40 * 1024 * 1024),
            network_name_prefix=_env_str("SANDBOX_NETWORK_PREFIX", "trinetra-sb") or "trinetra-sb",
            worker_uid=_env_int("SANDBOX_WORKER_UID", 10001),
            worker_gid=_env_int("SANDBOX_WORKER_GID", 10001),
        )

    def validate(self) -> None:
        if not self.api_token or len(self.api_token) < 32:
            raise RuntimeError("SANDBOX_API_TOKEN must be set to at least 32 characters")
        if not 1 <= self.bind_port <= 65535:
            raise RuntimeError("SANDBOX_BIND_PORT is invalid")
        if not 1 <= self.dns_port <= 65535:
            raise RuntimeError("SANDBOX_DNS_PORT is invalid")
        if self.worker_cpus <= 0:
            raise RuntimeError("SANDBOX_WORKER_CPUS must be positive")
        if self.worker_memory_bytes < 128 * 1024 * 1024:
            raise RuntimeError("SANDBOX_WORKER_MEMORY_BYTES is too small")
        if self.worker_pids < 32:
            raise RuntimeError("SANDBOX_WORKER_PIDS is too small")
        if self.session_ttl_seconds < 30:
            raise RuntimeError("SANDBOX_SESSION_TTL_SECONDS is too small")
        if not 5 <= self.default_timeout_seconds <= self.max_timeout_seconds:
            raise RuntimeError("sandbox investigation timeout configuration is invalid")
        if self.session_ttl_seconds < self.max_timeout_seconds:
            raise RuntimeError("SANDBOX_SESSION_TTL_SECONDS must be >= SANDBOX_MAX_TIMEOUT_SECONDS")
        if not 1 <= self.max_sessions <= 64:
            raise RuntimeError("SANDBOX_MAX_SESSIONS is invalid")
        if not 1 <= self.max_redirects <= 10:
            raise RuntimeError("SANDBOX_MAX_REDIRECTS is invalid")
        if self.max_upload_bytes < 1024:
            raise RuntimeError("SANDBOX_MAX_UPLOAD_BYTES is too small")
        if self.max_evidence_bytes < self.max_upload_bytes:
            raise RuntimeError("SANDBOX_MAX_EVIDENCE_BYTES must be >= SANDBOX_MAX_UPLOAD_BYTES")
        if self.max_artifact_bytes > self.max_evidence_bytes:
            raise RuntimeError("SANDBOX_MAX_ARTIFACT_BYTES must be <= SANDBOX_MAX_EVIDENCE_BYTES")
        if self.max_artifacts < 1:
            raise RuntimeError("SANDBOX_MAX_ARTIFACTS is invalid")
        if self.max_log_bytes < 4096:
            raise RuntimeError("SANDBOX_MAX_LOG_BYTES is too small")
        if self.api_request_limit_bytes < self.max_upload_bytes:
            raise RuntimeError("SANDBOX_API_REQUEST_LIMIT_BYTES must be >= SANDBOX_MAX_UPLOAD_BYTES")
        if self.worker_tmpfs_bytes < 64 * 1024 * 1024:
            raise RuntimeError("SANDBOX_WORKER_TMPFS_BYTES is too small")
        if self.worker_work_bytes < 16 * 1024 * 1024:
            raise RuntimeError("SANDBOX_WORKER_WORK_BYTES is too small")
        if not self.dns_upstreams:
            raise RuntimeError("SANDBOX_DNS_UPSTREAMS must not be empty")
        for upstream in self.dns_upstreams:
            try:
                address = ipaddress.ip_address(upstream)
            except ValueError as exc:
                raise RuntimeError("SANDBOX_DNS_UPSTREAMS must contain IP addresses") from exc
            if not address.is_global or address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
                raise RuntimeError("SANDBOX_DNS_UPSTREAMS must be public resolver addresses")
        if self.enable_host_firewall and self.allow_unsafe_network:
            raise RuntimeError("SANDBOX_ALLOW_UNSAFE_NETWORK cannot be used while host firewall is enabled")
        if not self.enable_host_firewall and not self.allow_unsafe_network:
            raise RuntimeError("host firewall cannot be disabled without SANDBOX_ALLOW_UNSAFE_NETWORK=1")
        if not self.allow_default_seccomp:
            if self.seccomp_profile is None or not Path(self.seccomp_profile).is_file():
                raise RuntimeError("sandbox seccomp profile is missing")
        if self.evidence_root.exists() and not self.evidence_root.is_dir():
            raise RuntimeError("SANDBOX_EVIDENCE_ROOT must be a directory")

    def prepare_evidence_root(self) -> Path:
        root = Path(self.evidence_root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        return root
