from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SEVERITIES = ("info", "low", "medium", "high", "critical")
SENSITIVE_KEYS = re.compile(
    r"(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|"
    r"authorization|cookie|session|credential|signature|signing[_\-]?key)",
    re.IGNORECASE,
)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, limit: int = 4096) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    text = CONTROL_CHARS.sub("", text)
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def safe_value(value: Any, *, limit: int = 4096, depth: int = 0, max_depth: int = 8) -> Any:
    if depth > max_depth:
        return "[truncated:depth]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return safe_text(value, limit)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {
            "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "preview": safe_text(raw[:256], 256),
        }
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= 200:
                result["__truncated__"] = True
                break
            key = safe_text(raw_key, 128)
            if not key:
                continue
            result[key] = "[REDACTED]" if SENSITIVE_KEYS.search(key) else safe_value(
                raw_value,
                limit=limit,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            safe_value(item, limit=limit, depth=depth + 1, max_depth=max_depth)
            for index, item in enumerate(value)
            if index < 500
        ]
    return safe_text(value, limit)


@dataclass
class EvidenceItem:
    source: str
    category: str
    title: str
    severity: str
    confidence: float
    description: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    code: str | None = None
    untrusted: bool = True
    evidence_id: str = ""
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError("invalid evidence severity")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.source = safe_text(self.source, 128)
        self.category = safe_text(self.category, 128)
        self.title = safe_text(self.title, 256)
        self.description = safe_text(self.description, 2048)
        self.code = safe_text(self.code, 128) if self.code else None
        if not self.evidence_id:
            digest = hashlib.sha256(
                f"{self.source}|{self.category}|{self.title}|{self.code}".encode("utf-8")
            ).hexdigest()[:12]
            self.evidence_id = f"ev-{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "source": self.source,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "code": self.code,
            "untrusted": self.untrusted,
            "data": safe_value(self.data),
            "created_at": self.created_at,
        }


@dataclass
class InvestigationStep:
    index: int
    phase: str
    tool: str
    status: str
    summary: str
    started_at: str = field(default_factory=utc_now)
    duration_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "phase": safe_text(self.phase, 64),
            "tool": safe_text(self.tool, 128),
            "status": safe_text(self.status, 64),
            "summary": safe_text(self.summary, 1024),
            "started_at": self.started_at,
            "duration_ms": int(self.duration_ms),
            "error": safe_text(self.error, 1024) if self.error else None,
        }


@dataclass
class CoverageRecord:
    name: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": safe_text(self.detail, 512)}


@dataclass
class ArtifactRecord:
    name: str
    size: int
    sha256: str
    content_type: str
    local_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": int(self.size),
            "sha256": self.sha256,
            "content_type": self.content_type,
        }


class EvidenceLedger:
    def __init__(self, *, max_items: int = 500, text_limit: int = 4096) -> None:
        self.max_items = max(1, max_items)
        self.text_limit = max(256, text_limit)
        self._items: list[EvidenceItem] = []
        self._steps: list[InvestigationStep] = []
        self._coverage: dict[str, CoverageRecord] = {}
        self._warnings: list[str] = []
        self._artifacts: list[ArtifactRecord] = []
        self._errors: list[dict[str, str]] = []

    @property
    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._items)

    @property
    def steps(self) -> tuple[InvestigationStep, ...]:
        return tuple(self._steps)

    @property
    def warnings(self) -> tuple[str, ...]:
        return tuple(self._warnings)

    @property
    def artifacts(self) -> tuple[ArtifactRecord, ...]:
        return tuple(self._artifacts)

    @property
    def errors(self) -> tuple[dict[str, str], ...]:
        return tuple(self._errors)

    @property
    def coverage(self) -> dict[str, CoverageRecord]:
        return dict(self._coverage)

    def add(
        self,
        *,
        source: str,
        category: str,
        title: str,
        severity: str,
        confidence: float,
        description: str = "",
        data: dict[str, Any] | None = None,
        code: str | None = None,
        untrusted: bool = True,
    ) -> EvidenceItem | None:
        if len(self._items) >= self.max_items:
            if "evidence_item_limit" not in self._warnings:
                self._warnings.append("evidence_item_limit")
            return None
        item = EvidenceItem(
            source=source,
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            data=safe_value(data or {}, limit=self.text_limit),
            code=code,
            untrusted=untrusted,
        )
        if any(existing.evidence_id == item.evidence_id for existing in self._items):
            return None
        self._items.append(item)
        return item

    def add_step(
        self,
        *,
        phase: str,
        tool: str,
        status: str,
        summary: str,
        duration_ms: int = 0,
        error: str | None = None,
    ) -> InvestigationStep:
        step = InvestigationStep(
            index=len(self._steps) + 1,
            phase=phase,
            tool=tool,
            status=status,
            summary=safe_text(summary, 1024),
            duration_ms=max(0, int(duration_ms)),
            error=safe_text(error, 1024) if error else None,
        )
        self._steps.append(step)
        return step

    def mark_coverage(self, name: str, status: str, detail: str = "") -> None:
        self._coverage[name] = CoverageRecord(name=name, status=status, detail=safe_text(detail, 512))

    def warn(self, message: str) -> None:
        text = safe_text(message, 512)
        if text and text not in self._warnings:
            self._warnings.append(text)

    def error(self, stage: str, message: str) -> None:
        entry = {"stage": safe_text(stage, 128), "message": safe_text(message, 1024)}
        if entry not in self._errors:
            self._errors.append(entry)

    def add_artifact(self, artifact: ArtifactRecord) -> None:
        if any(existing.sha256 == artifact.sha256 and existing.name == artifact.name for existing in self._artifacts):
            return
        self._artifacts.append(
            ArtifactRecord(
                name=safe_text(artifact.name, 255),
                size=max(0, int(artifact.size)),
                sha256=safe_text(artifact.sha256, 64),
                content_type=safe_text(artifact.content_type, 128),
                local_path=artifact.local_path,
            )
        )

    def coverage_status(self, name: str) -> str:
        record = self._coverage.get(name)
        return record.status if record else "missing"

    def all_coverage_ok(self, required: Iterable[str]) -> bool:
        return all(self.coverage_status(name) == "ok" for name in required)

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self._items],
            "steps": [step.to_dict() for step in self._steps],
            "coverage": [record.to_dict() for record in self._coverage.values()],
            "warnings": list(self._warnings),
            "artifacts": [artifact.to_dict() for artifact in self._artifacts],
            "errors": list(self._errors),
        }

    def llm_summary(self, max_items: int = 40) -> dict[str, Any]:
        ordered = sorted(
            self._items,
            key=lambda item: (SEVERITIES.index(item.severity), item.confidence),
            reverse=True,
        )
        selected = [
            {
                "source": item.source,
                "category": item.category,
                "title": item.title,
                "severity": item.severity,
                "confidence": round(item.confidence, 3),
                "description": item.description,
                "code": item.code,
                "data": item.data,
            }
            for item in ordered[:max_items]
        ]
        return {
            "evidence": selected,
            "coverage": [record.to_dict() for record in self._coverage.values()],
            "warnings": self._warnings[:40],
            "errors": self._errors[:20],
            "steps": [step.to_dict() for step in self._steps[-20:]],
            "artifacts": [artifact.to_dict() for artifact in self._artifacts[:40]],
        }

    def json_size(self) -> int:
        return len(json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))
