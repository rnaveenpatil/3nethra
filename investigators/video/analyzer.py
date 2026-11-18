from __future__ import annotations

from typing import Any, Iterable

from config.settings import Settings
from intelligence.evidence import ArtifactRecord, EvidenceLedger, safe_text

from .audio_analyzer import analyze_audio
from .detector import DetectorError, VideoDetector
from .frame_extractor import select_frame_artifacts

VIDEO_TYPES = {"mp4_video", "matroska", "avi_video", "flv_video", "mpeg_video", "ogg_media"}


class VideoInvestigator:
    required_coverage = ("file_analysis", "frame_extraction", "video_detector")

    def __init__(self, settings: Settings, *, detector: VideoDetector | None = None) -> None:
        self.settings = settings
        self.detector = detector or VideoDetector(settings)

    async def close(self) -> None:
        await self.detector.close()

    async def analyze(
        self,
        ledger: EvidenceLedger,
        evidence: dict[str, Any],
        *,
        artifacts: Iterable[ArtifactRecord] = (),
    ) -> dict[str, Any]:
        static = evidence.get("file") if isinstance(evidence, dict) else None
        if not isinstance(static, dict):
            ledger.mark_coverage("file_analysis", "failed", "Video file evidence is missing")
            ledger.add(
                source="video.analysis",
                category="coverage",
                title="Video evidence was malformed",
                severity="high",
                confidence=0.9,
                code="malformed_result",
            )
            return {"analyzed": False, "reason": "missing_file_evidence"}
        ledger.mark_coverage("file_analysis", "ok", "Video container inspection completed")
        file_type = safe_text(static.get("file_type", ""), 64)
        if file_type not in VIDEO_TYPES:
            ledger.mark_coverage("frame_extraction", "failed", "File is not a recognized video container")
            ledger.mark_coverage("video_detector", "unavailable", "Authenticity detection requires a video")
            ledger.warn(f"Submitted file type is {file_type or 'unknown'}, not a recognized video")
            ledger.add(
                source="video.analysis",
                category="media",
                title="File does not appear to be a supported video",
                severity="medium",
                confidence=0.7,
                data={"file_type": file_type},
                code="unsupported_media",
            )
            return {"analyzed": False, "reason": "unsupported_media", "file_type": file_type}

        media = static.get("media") if isinstance(static.get("media"), dict) else {}
        ffprobe = media.get("ffprobe") if isinstance(media.get("ffprobe"), dict) else {}
        metadata = ffprobe.get("metadata") if isinstance(ffprobe.get("metadata"), dict) else {}
        format_info = metadata.get("format") if isinstance(metadata.get("format"), dict) else {}
        streams = metadata.get("streams") if isinstance(metadata.get("streams"), list) else []
        video_streams = [
            {
                "codec": safe_text(stream.get("codec_name", ""), 64),
                "width": stream.get("width"),
                "height": stream.get("height"),
                "duration": stream.get("duration"),
                "bit_rate": stream.get("bit_rate"),
            }
            for stream in streams
            if isinstance(stream, dict) and stream.get("codec_type") == "video"
        ]
        duration = safe_text(format_info.get("duration", ""), 64)
        if video_streams:
            ledger.add(
                source="sandbox.media",
                category="media",
                title="Video stream metadata extracted",
                severity="info",
                confidence=0.8,
                description="Container and stream metadata do not by themselves prove authentic or synthetic origin.",
                data={
                    "file_type": file_type,
                    "duration_seconds": duration,
                    "format": safe_text(format_info.get("format_name", ""), 128),
                    "streams": video_streams[:10],
                },
                code="video_metadata",
            )
        else:
            ledger.warn("No video stream metadata was extracted")

        audio = analyze_audio(ledger, evidence)
        frames_declared = media.get("frames") if isinstance(media.get("frames"), list) else []
        if frames_declared:
            ledger.mark_coverage("frame_extraction", "ok", f"{len(frames_declared)} frame artifact(s)")
        else:
            ledger.mark_coverage("frame_extraction", "partial", "No frames were extracted")
            ledger.warn("No video frames were available for authenticity analysis")
        for warning in media.get("warnings", [])[:10] if isinstance(media.get("warnings"), list) else []:
            ledger.warn(safe_text(warning, 512))

        frames = select_frame_artifacts(
            evidence,
            artifacts,
            max_frames=self.settings.video_detector_max_frames,
            max_bytes=self.settings.video_detector_max_frame_bytes,
        )
        if not self.detector.enabled:
            ledger.mark_coverage("video_detector", "unavailable", "No authenticity detector is configured")
            ledger.add(
                source="video.detector",
                category="coverage",
                title="AI-video detector is not configured",
                severity="info",
                confidence=0.9,
                description="No authenticity model was available, so synthetic origin cannot be certified.",
                data={"frames_available": len(frames)},
                code="detector_unavailable",
            )
            return {
                "analyzed": True,
                "file_type": file_type,
                "video_streams": len(video_streams),
                "audio_streams": audio.get("audio_streams", 0),
                "frames": len(frames_declared),
                "detector": "unavailable",
            }
        if not frames:
            ledger.mark_coverage("video_detector", "unavailable", "No usable frames were available")
            ledger.add(
                source="video.detector",
                category="coverage",
                title="No frames were available for the detector",
                severity="info",
                confidence=0.9,
                description="The configured authenticity detector could not be used.",
                data={"frames_available": 0},
                code="detector_unavailable",
            )
            return {
                "analyzed": True,
                "file_type": file_type,
                "video_streams": len(video_streams),
                "audio_streams": audio.get("audio_streams", 0),
                "frames": len(frames_declared),
                "detector": "no_frames",
            }
        try:
            result = await self.detector.detect(
                frames,
                metadata={
                    "content_type": "video",
                    "duration_seconds": duration,
                    "streams": video_streams[:5],
                },
            )
        except DetectorError as exc:
            ledger.mark_coverage("video_detector", "unavailable", safe_text(str(exc), 256))
            ledger.warn("Authenticity detector did not produce a result")
            ledger.add(
                source="video.detector",
                category="coverage",
                title="Authenticity detector was unavailable",
                severity="info",
                confidence=0.9,
                description="No detector result was produced, so synthetic origin cannot be certified.",
                data={"frames_submitted": len(frames)},
                code="detector_unavailable",
            )
            return {
                "analyzed": True,
                "file_type": file_type,
                "video_streams": len(video_streams),
                "audio_streams": audio.get("audio_streams", 0),
                "frames": len(frames_declared),
                "detector": "error",
            }
        ledger.mark_coverage("video_detector", "ok", "Authenticity detector returned a result")
        probability = float(result.get("ai_probability", 0.5))
        confidence = result.get("confidence")
        evidence_confidence = float(confidence) if isinstance(confidence, (int, float)) else max(0.45, abs(probability - 0.5) + 0.5)
        label = result.get("label", "uncertain")
        if label == "ai_generated" or probability >= 0.75:
            severity = "high" if probability >= 0.85 else "medium"
            ledger.add(
                source="video.detector",
                category="authenticity",
                title="Authenticity detector indicates synthetic media",
                severity=severity,
                confidence=min(0.95, evidence_confidence),
                description="The configured detector reported an AI-generated signal. This is probabilistic evidence, not proof.",
                data=result,
                code="ai_generated_media",
            )
        elif label == "real" or probability <= 0.25:
            ledger.add(
                source="video.detector",
                category="authenticity",
                title="Authenticity detector found no synthetic signal",
                severity="info",
                confidence=min(0.9, evidence_confidence),
                description="The detector did not find an AI-generated signal, but this does not prove authenticity.",
                data=result,
                code="authenticity_signal",
            )
        else:
            ledger.mark_coverage("video_detector", "partial", "Authenticity detector was inconclusive")
            ledger.add(
                source="video.detector",
                category="authenticity",
                title="Authenticity detector was inconclusive",
                severity="info",
                confidence=0.5,
                description="The detector did not provide a clear authenticity signal.",
                data=result,
                code="detector_inconclusive",
            )
        return {
            "analyzed": True,
            "file_type": file_type,
            "video_streams": len(video_streams),
            "audio_streams": audio.get("audio_streams", 0),
            "frames": len(frames_declared),
            "detector": result,
        }
