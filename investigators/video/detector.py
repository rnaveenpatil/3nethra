from __future__ import annotations

import asyncio
import base64
import hashlib
from pathlib import Path
from typing import Any, Iterable

import httpx

from config.settings import Settings
from intelligence.evidence import ArtifactRecord


class DetectorError(RuntimeError):
    pass


class VideoDetector:
    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._owns_client = client is None
        headers = {"Accept": "application/json", "User-Agent": settings.user_agent}
        if settings.video_detector_token:
            headers["Authorization"] = f"Bearer {settings.video_detector_token}"
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.video_detector_timeout_seconds),
            follow_redirects=False,
        )
        self._headers = headers

    @property
    def enabled(self) -> bool:
        return bool(self.settings.video_detector_url)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def detect(self, frames: Iterable[ArtifactRecord], *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.enabled:
            raise DetectorError("video detector is not configured")
        payload_frames = []
        total = 0
        for frame in frames:
            if not frame.local_path:
                continue
            path = Path(frame.local_path)
            if not path.is_file() or path.is_symlink():
                continue
            raw = await asyncio.to_thread(path.read_bytes)
            if len(raw) > self.settings.video_detector_max_frame_bytes:
                continue
            total += len(raw)
            if len(payload_frames) >= self.settings.video_detector_max_frames:
                break
            payload_frames.append(
                {
                    "name": frame.name,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "content_base64": base64.b64encode(raw).decode("ascii"),
                }
            )
        if not payload_frames:
            raise DetectorError("no frame is available for the detector")
        if total > self.settings.video_detector_max_frame_bytes * self.settings.video_detector_max_frames:
            raise DetectorError("frames exceed the detector payload limit")
        payload = {
            "model": self.settings.video_detector_model,
            "frames": payload_frames,
            "metadata": metadata or {},
        }
        url = self.settings.video_detector_url
        if not url:
            raise DetectorError("video detector is not configured")
        try:
            response = await self._client.post(
                url,
                headers=self._headers,
                json=payload,
            )
        except httpx.TimeoutException as exc:
            raise DetectorError("video detector timed out") from exc
        except httpx.HTTPError as exc:
            raise DetectorError("video detector is unreachable") from exc
        if response.status_code >= 400:
            raise DetectorError(f"video detector failed with HTTP {response.status_code}")
        try:
            data = response.json()
        except (ValueError, TypeError) as exc:
            raise DetectorError("video detector returned malformed JSON") from exc
        if not isinstance(data, dict):
            raise DetectorError("video detector returned an invalid response")
        return self._normalize(data)

    def _normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        label = str(data.get("label") or data.get("verdict") or data.get("classification") or "").lower()
        if label in {"ai", "aigc", "ai_generated", "generated", "synthetic", "fake", "deepfake"}:
            label = "ai_generated"
        elif label in {"real", "authentic", "human", "genuine", "camera"}:
            label = "real"
        elif label not in {"uncertain", "unknown", ""}:
            raise DetectorError("video detector returned an unknown label")
        if not label:
            label = "uncertain"
        score_raw = data.get("ai_generated_score", data.get("score", data.get("probability")))
        score: float | None
        try:
            score = float(score_raw) if score_raw is not None else None
        except (TypeError, ValueError):
            raise DetectorError("video detector returned an invalid score")
        if score is not None and not 0.0 <= score <= 1.0:
            if 0.0 <= score <= 100.0:
                score = score / 100.0
            else:
                raise DetectorError("video detector score is out of range")
        if score is None:
            confidence_raw = data.get("confidence")
            try:
                confidence = float(confidence_raw) if confidence_raw is not None else None
            except (TypeError, ValueError):
                confidence = None
            if label == "ai_generated":
                score = confidence
            elif label == "real" and confidence is not None:
                score = 1.0 - confidence
        if score is None:
            score = 0.5
        if label == "real":
            ai_probability = 1.0 - score
        else:
            ai_probability = score
        if ai_probability > 1.0:
            ai_probability = 1.0
        if ai_probability < 0.0:
            ai_probability = 0.0
        if label == "real" and ai_probability >= 0.6:
            label = "uncertain"
        elif label == "ai_generated" and ai_probability <= 0.4:
            label = "uncertain"
        confidence = data.get("confidence")
        try:
            confidence_value = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence_value = None
        if confidence_value is not None and confidence_value > 1.0 and confidence_value <= 100.0:
            confidence_value = confidence_value / 100.0
        return {
            "label": label,
            "ai_probability": round(ai_probability, 4),
            "confidence": round(confidence_value, 4) if confidence_value is not None else None,
            "model": str(data.get("model", self.settings.video_detector_model))[:128],
        }
