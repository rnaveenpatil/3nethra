from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FilePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class InvestigationOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    take_screenshot: bool = True
    capture_html: bool = True
    capture_console: bool = True
    allow_downloads: bool = False
    analyze_media: bool = False
    extract_video_frames: bool = False
    full_page_screenshot: bool = False
    max_redirects: int = Field(default=5, ge=0, le=10)
    timeout_seconds: int = Field(default=120, ge=5, le=600)


class CreateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["url", "file"]
    url: str | None = Field(default=None, max_length=4096)
    file: FilePayload | None = None
    options: InvestigationOptions = Field(default_factory=InvestigationOptions)

    @model_validator(mode="after")
    def validate_payload(self) -> "CreateSessionRequest":
        if self.kind == "url":
            if not self.url or self.file is not None:
                raise ValueError("url kind requires url and no file")
        elif self.kind == "file":
            if self.file is None or self.url is not None:
                raise ValueError("file kind requires file and no url")
        return self


class ArtifactInfo(BaseModel):
    name: str
    size: int
    sha256: str
    content_type: str


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
    request_id: str | None = None


class SessionStatus(BaseModel):
    id: str
    kind: str
    status: str
    created_at: str
    updated_at: str
    expires_at: str
    started_at: str | None = None
    completed_at: str | None = None
    phase: str = "created"
    progress: int = 0
    error: ErrorDetail | None = None
    evidence_available: bool = False
    artifacts: list[ArtifactInfo] = Field(default_factory=list)


class SessionCreated(BaseModel):
    id: str
    status: str
    created_at: str
    expires_at: str


class SessionList(BaseModel):
    sessions: list[SessionStatus]


class InvestigationAccepted(BaseModel):
    id: str
    status: str


class TerminationResult(BaseModel):
    id: str
    status: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
