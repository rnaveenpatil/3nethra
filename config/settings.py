from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    pass


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    value = _env(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    normalized = value.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean")


def _path(name: str, default: str) -> Path:
    value = _env(name, default) or default
    return Path(value).expanduser()


@dataclass(frozen=True)
class Settings:
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 60.0
    llm_max_tokens: int = 1800
    llm_temperature: float = 0.0
    sandbox_url: str = "http://127.0.0.1:8765"
    sandbox_token: str | None = None
    sandbox_timeout_seconds: float = 30.0
    sandbox_investigation_timeout_seconds: int = 180
    sandbox_poll_seconds: float = 0.5
    sandbox_max_artifact_bytes: int = 16 * 1024 * 1024
    sandbox_max_artifact_total_bytes: int = 64 * 1024 * 1024
    workspace: Path = Path("workspace")
    history_path: Path = Path("storage/trinetra.db")
    max_file_bytes: int = 25 * 1024 * 1024
    max_steps: int = 8
    max_followup_rounds: int = 2
    max_evidence_items: int = 500
    max_text_chars: int = 4096
    max_tool_output_chars: int = 65536
    approval_mode: str = "interactive"
    terminal_enabled: bool = True
    terminal_requires_approval: bool = True
    video_detector_url: str | None = None
    video_detector_token: str | None = None
    video_detector_model: str = "trinetra-video-detector"
    video_detector_timeout_seconds: float = 45.0
    video_detector_max_frames: int = 4
    video_detector_max_frame_bytes: int = 2 * 1024 * 1024
    user_agent: str = "TrinetraInvestigationAgent/1.0"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            llm_base_url=(_env("TRINETRA_LLM_BASE_URL", "https://api.openai.com/v1") or "https://api.openai.com/v1").rstrip("/"),
            llm_api_key=_env("TRINETRA_LLM_API_KEY"),
            llm_model=_env("TRINETRA_LLM_MODEL", "gpt-4o-mini") or "gpt-4o-mini",
            llm_timeout_seconds=_env_float("TRINETRA_LLM_TIMEOUT_SECONDS", 60.0),
            llm_max_tokens=_env_int("TRINETRA_LLM_MAX_TOKENS", 1800),
            llm_temperature=_env_float("TRINETRA_LLM_TEMPERATURE", 0.0),
            sandbox_url=(_env("TRINETRA_SANDBOX_URL", "http://127.0.0.1:8765") or "http://127.0.0.1:8765").rstrip("/"),
            sandbox_token=_env("TRINETRA_SANDBOX_TOKEN") or _env("SANDBOX_API_TOKEN"),
            sandbox_timeout_seconds=_env_float("TRINETRA_SANDBOX_TIMEOUT_SECONDS", 30.0),
            sandbox_investigation_timeout_seconds=_env_int("TRINETRA_SANDBOX_INVESTIGATION_TIMEOUT_SECONDS", 180),
            sandbox_poll_seconds=_env_float("TRINETRA_SANDBOX_POLL_SECONDS", 0.5),
            sandbox_max_artifact_bytes=_env_int("TRINETRA_SANDBOX_MAX_ARTIFACT_BYTES", 16 * 1024 * 1024),
            sandbox_max_artifact_total_bytes=_env_int("TRINETRA_SANDBOX_MAX_ARTIFACT_TOTAL_BYTES", 64 * 1024 * 1024),
            workspace=_path("TRINETRA_WORKSPACE", "workspace"),
            history_path=_path("TRINETRA_HISTORY_PATH", "storage/trinetra.db"),
            max_file_bytes=_env_int("TRINETRA_MAX_FILE_BYTES", 25 * 1024 * 1024),
            max_steps=_env_int("TRINETRA_MAX_STEPS", 8),
            max_followup_rounds=_env_int("TRINETRA_MAX_FOLLOWUP_ROUNDS", 2),
            max_evidence_items=_env_int("TRINETRA_MAX_EVIDENCE_ITEMS", 500),
            max_text_chars=_env_int("TRINETRA_MAX_TEXT_CHARS", 4096),
            max_tool_output_chars=_env_int("TRINETRA_MAX_TOOL_OUTPUT_CHARS", 65536),
            approval_mode=(_env("TRINETRA_APPROVAL_MODE", "interactive") or "interactive").lower(),
            terminal_enabled=_env_bool("TRINETRA_TERMINAL_ENABLED", True),
            terminal_requires_approval=_env_bool("TRINETRA_TERMINAL_REQUIRES_APPROVAL", True),
            video_detector_url=_env("TRINETRA_VIDEO_DETECTOR_URL"),
            video_detector_token=_env("TRINETRA_VIDEO_DETECTOR_TOKEN"),
            video_detector_model=_env("TRINETRA_VIDEO_DETECTOR_MODEL", "trinetra-video-detector") or "trinetra-video-detector",
            video_detector_timeout_seconds=_env_float("TRINETRA_VIDEO_DETECTOR_TIMEOUT_SECONDS", 45.0),
            video_detector_max_frames=_env_int("TRINETRA_VIDEO_DETECTOR_MAX_FRAMES", 4),
            video_detector_max_frame_bytes=_env_int("TRINETRA_VIDEO_DETECTOR_MAX_FRAME_BYTES", 2 * 1024 * 1024),
            user_agent=_env("TRINETRA_USER_AGENT", "TrinetraInvestigationAgent/1.0") or "TrinetraInvestigationAgent/1.0",
        )

    def validate(self) -> None:
        if self.approval_mode not in {"auto", "interactive", "deny"}:
            raise ConfigurationError("TRINETRA_APPROVAL_MODE must be auto, interactive or deny")
        if not 2 <= self.max_steps <= 24:
            raise ConfigurationError("TRINETRA_MAX_STEPS must be between 2 and 24")
        if not 0 <= self.max_followup_rounds <= 8:
            raise ConfigurationError("TRINETRA_MAX_FOLLOWUP_ROUNDS must be between 0 and 8")
        if self.max_file_bytes < 1:
            raise ConfigurationError("TRINETRA_MAX_FILE_BYTES must be positive")
        if self.sandbox_investigation_timeout_seconds < 5:
            raise ConfigurationError("TRINETRA_SANDBOX_INVESTIGATION_TIMEOUT_SECONDS is too small")
        if self.sandbox_poll_seconds <= 0:
            raise ConfigurationError("TRINETRA_SANDBOX_POLL_SECONDS must be positive")
        if self.sandbox_timeout_seconds <= 0:
            raise ConfigurationError("TRINETRA_SANDBOX_TIMEOUT_SECONDS must be positive")
        if self.llm_timeout_seconds <= 0:
            raise ConfigurationError("TRINETRA_LLM_TIMEOUT_SECONDS must be positive")
        if self.max_text_chars < 256:
            raise ConfigurationError("TRINETRA_MAX_TEXT_CHARS is too small")
        if self.max_tool_output_chars < 1024:
            raise ConfigurationError("TRINETRA_MAX_TOOL_OUTPUT_CHARS is too small")
        if self.video_detector_max_frames < 1:
            raise ConfigurationError("TRINETRA_VIDEO_DETECTOR_MAX_FRAMES must be positive")
        for name, value in (
            ("TRINETRA_LLM_BASE_URL", self.llm_base_url),
            ("TRINETRA_SANDBOX_URL", self.sandbox_url),
        ):
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ConfigurationError(f"{name} must be an HTTP or HTTPS URL")
        if self.video_detector_url is not None:
            parsed = urlsplit(self.video_detector_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ConfigurationError("TRINETRA_VIDEO_DETECTOR_URL must be an HTTP or HTTPS URL")
        if self.sandbox_token is not None and len(self.sandbox_token) < 32:
            raise ConfigurationError("TRINETRA_SANDBOX_TOKEN must be at least 32 characters")
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.history_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_api_key and self.llm_model)
