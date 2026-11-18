from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from intelligence.evidence import ArtifactRecord, safe_text


def declared_frames(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    static = evidence.get("file")
    if not isinstance(static, dict):
        return []
    media = static.get("media")
    if not isinstance(media, dict):
        return []
    frames = media.get("frames")
    if not isinstance(frames, list):
        return []
    return [item for item in frames if isinstance(item, dict) and isinstance(item.get("name"), str)]


def select_frame_artifacts(
    evidence: dict[str, Any],
    artifacts: Iterable[ArtifactRecord],
    *,
    max_frames: int,
    max_bytes: int,
) -> list[ArtifactRecord]:
    declared = {safe_text(item.get("name"), 255) for item in declared_frames(evidence)}
    selected: list[ArtifactRecord] = []
    for artifact in artifacts:
        if artifact.name not in declared:
            continue
        if artifact.size <= 0 or artifact.size > max_bytes:
            continue
        if not artifact.content_type.startswith("image/"):
            continue
        if not artifact.local_path:
            continue
        if not Path(artifact.local_path).is_file():
            continue
        selected.append(artifact)
        if len(selected) >= max_frames:
            break
    if selected:
        return selected
    for artifact in artifacts:
        if artifact.size <= 0 or artifact.size > max_bytes:
            continue
        if not artifact.content_type.startswith("image/"):
            continue
        if not artifact.local_path or not Path(artifact.local_path).is_file():
            continue
        selected.append(artifact)
        if len(selected) >= max_frames:
            break
    return selected
