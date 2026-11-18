from __future__ import annotations

from typing import Any

from intelligence.evidence import EvidenceLedger, safe_text


def analyze_audio(ledger: EvidenceLedger, evidence: dict[str, Any]) -> dict[str, Any]:
    static = evidence.get("file")
    media = static.get("media") if isinstance(static, dict) and isinstance(static.get("media"), dict) else {}
    ffprobe = media.get("ffprobe") if isinstance(media.get("ffprobe"), dict) else {}
    metadata = ffprobe.get("metadata") if isinstance(ffprobe.get("metadata"), dict) else {}
    streams = metadata.get("streams") if isinstance(metadata.get("streams"), list) else []
    audio_streams = [
        {
            "codec": safe_text(stream.get("codec_name", ""), 64),
            "channels": stream.get("channels"),
            "sample_rate": stream.get("sample_rate"),
        }
        for stream in streams
        if isinstance(stream, dict) and stream.get("codec_type") == "audio"
    ]
    if not audio_streams:
        ledger.mark_coverage("audio_metadata", "not_applicable", "No audio stream was identified")
        return {"audio_streams": 0}
    ledger.mark_coverage("audio_metadata", "ok", f"{len(audio_streams)} audio stream(s)")
    ledger.add(
        source="sandbox.media",
        category="media",
        title="Audio stream metadata extracted",
        severity="info",
        confidence=0.8,
        description="Container metadata alone cannot establish whether audio was synthesized.",
        data={"streams": audio_streams[:10]},
        code="audio_metadata",
    )
    if ffprobe.get("timed_out"):
        ledger.warn("Audio metadata extraction timed out")
    return {"audio_streams": len(audio_streams), "streams": audio_streams}
