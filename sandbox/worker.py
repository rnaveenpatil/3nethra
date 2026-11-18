from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import math
import os
import re
import resource
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import time
import traceback
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import network_policy, security

WORK_DIR = Path("/work")
INPUT_DIR = WORK_DIR / "input"
INPUT_PATH = INPUT_DIR / "input.bin"
EVIDENCE_DIR = WORK_DIR / "evidence"
TASK_PATH = WORK_DIR / "task.json"
STATUS_PATH = WORK_DIR / "status.json"
RESULTS_PATH = EVIDENCE_DIR / "results.json"

MAX_TASK_BYTES = 128 * 1024
MAX_STRING_EVIDENCE = 16384
MAX_HTML_ARTIFACT = 4 * 1024 * 1024
MAX_TEXT_PREVIEW = 8192
MAX_BROWSER_RESPONSES = 300
MAX_BROWSER_REQUESTS = 500
MAX_CONSOLE_MESSAGES = 200
MAX_BLOCKED_REQUESTS = 100
MAX_EXTRACTED_STRINGS = 400
MAX_URLS = 200
MAX_IPS = 200
MAX_DOWNLOADS = 3
DEFAULT_LIMITS = {
    "max_http_body_bytes": 2 * 1024 * 1024,
    "max_download_bytes": 10 * 1024 * 1024,
    "max_evidence_bytes": 64 * 1024 * 1024,
    "max_artifact_bytes": 16 * 1024 * 1024,
    "max_artifacts": 32,
}
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 TrinetraSandbox/1.0"
)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]{3,2048}", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(event: str, **fields: object) -> None:
    payload = {"event": event, "ts": _utc_now(), **fields}
    try:
        print(json.dumps(security.sanitize_evidence(payload), separators=(",", ":"), ensure_ascii=False), flush=True)
    except Exception:
        pass


def _set_status(phase: str, progress: int, detail: str = "") -> None:
    payload = {
        "phase": security.sanitize_text(phase, 64),
        "progress": max(0, min(100, int(progress))),
        "detail": security.sanitize_text(detail, 512),
        "updated_at": _utc_now(),
    }
    try:
        security.write_json_atomic(STATUS_PATH, payload)
    except Exception:
        pass
    _emit("status", phase=payload["phase"], progress=payload["progress"], detail=payload["detail"])


def _prepare_workdir() -> None:
    os.umask(0o077)
    WORK_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    INPUT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    for directory in (WORK_DIR, INPUT_DIR, EVIDENCE_DIR):
        try:
            directory.chmod(0o700)
        except OSError:
            pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except (ValueError, OSError):
        pass
    limit = int(os.getenv("SANDBOX_WORKER_FILE_LIMIT", str(96 * 1024 * 1024)))
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    except (ValueError, OSError):
        pass


def _wait_for_task(path: Path, timeout: float = 20.0) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        except OSError as exc:
            raise RuntimeError("task file cannot be opened") from exc
        try:
            with os.fdopen(descriptor, "rb") as handle:
                data = handle.read(MAX_TASK_BYTES + 1)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if len(data) > MAX_TASK_BYTES:
            raise RuntimeError("task file is too large")
        return data
    raise RuntimeError("task file did not arrive")


def _load_task() -> dict[str, object]:
    raw = _wait_for_task(TASK_PATH)
    try:
        task = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("task file is not valid JSON") from exc
    if not isinstance(task, dict):
        raise RuntimeError("task must be an object")
    allowed = {"schema_version", "session_id", "kind", "url", "input", "options", "limits"}
    if set(task) - allowed:
        raise RuntimeError("task contains unsupported fields")
    if task.get("schema_version") != 1:
        raise RuntimeError("unsupported task schema")
    if task.get("kind") not in {"url", "file"}:
        raise RuntimeError("unsupported task kind")
    if not isinstance(task.get("session_id"), str) or not task["session_id"]:
        raise RuntimeError("task session id is missing")
    options = task.get("options")
    if not isinstance(options, dict):
        raise RuntimeError("task options are invalid")
    limits = task.get("limits")
    if not isinstance(limits, dict):
        raise RuntimeError("task limits are invalid")
    return task


def _bool_option(options: dict[str, object], key: str, default: bool) -> bool:
    value = options.get(key, default)
    return value if isinstance(value, bool) else default


def _int_option(options: dict[str, object], key: str, default: int, low: int, high: int) -> int:
    value = options.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(low, min(high, value))


def _normalized_options(raw: dict[str, object]) -> dict[str, object]:
    return {
        "take_screenshot": _bool_option(raw, "take_screenshot", True),
        "capture_html": _bool_option(raw, "capture_html", True),
        "capture_console": _bool_option(raw, "capture_console", True),
        "allow_downloads": _bool_option(raw, "allow_downloads", False),
        "analyze_media": _bool_option(raw, "analyze_media", False),
        "extract_video_frames": _bool_option(raw, "extract_video_frames", False),
        "full_page_screenshot": _bool_option(raw, "full_page_screenshot", False),
        "max_redirects": _int_option(raw, "max_redirects", 5, 0, 10),
        "timeout_seconds": _int_option(raw, "timeout_seconds", 120, 5, 300),
    }


def _normalized_limits(raw: dict[str, object]) -> dict[str, int]:
    result = dict(DEFAULT_LIMITS)
    for key, default in DEFAULT_LIMITS.items():
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            continue
        result[key] = min(value, default * 4)
    result["max_artifact_bytes"] = min(result["max_artifact_bytes"], result["max_evidence_bytes"])
    return result


class ArtifactWriter:
    def __init__(self, root: Path, max_bytes: int, max_artifacts: int) -> None:
        self.root = root
        self.max_bytes = max_bytes
        self.max_artifacts = max_artifacts
        self.artifacts: list[dict[str, object]] = []

    def write(self, name: str, data: bytes) -> dict[str, object] | None:
        if len(self.artifacts) >= self.max_artifacts:
            return None
        if len(data) > self.max_bytes:
            return None
        safe_name = security.sanitize_filename(name)
        target = self.root / safe_name
        if target.parent != self.root:
            return None
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        metadata = {
            "name": safe_name,
            "size": len(data),
            "sha256": security.sha256_bytes(data),
            "content_type": security.artifact_content_type(safe_name, data[:16]),
        }
        self.artifacts.append(metadata)
        return metadata


def _truncate_text(value: str, limit: int = MAX_TEXT_PREVIEW) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _safe_error(exc: BaseException) -> dict[str, str]:
    return {
        "type": type(exc).__name__,
        "message": security.sanitize_text(str(exc), 1024),
    }


def _magic_type(prefix: bytes) -> str:
    if prefix.startswith(b"MZ"):
        return "windows_executable"
    if prefix.startswith(b"\x7fELF"):
        return "elf_executable"
    if prefix[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "mach_o"
    if prefix.startswith(b"%PDF"):
        return "pdf"
    if prefix.startswith(b"PK\x03\x04") or prefix.startswith(b"PK\x05\x06") or prefix.startswith(b"PK\x07\x08"):
        return "zip"
    if prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole_compound"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png_image"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    if prefix.startswith(b"GIF87a") or prefix.startswith(b"GIF89a"):
        return "gif_image"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WEBP":
        return "webp_image"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WAVE":
        return "wav_audio"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"AVI ":
        return "avi_video"
    if prefix[4:8] == b"ftyp":
        return "mp4_video"
    if prefix.startswith(b"\x1a\x45\xdf\xa3"):
        return "matroska"
    if prefix.startswith(b"OggS"):
        return "ogg_media"
    if prefix.startswith(b"ID3") or prefix.startswith(b"\xff\xfb"):
        return "mpeg_audio"
    if prefix.startswith(b"fLaC"):
        return "flac_audio"
    if prefix.startswith(b"FLV\x01"):
        return "flv_video"
    if prefix.startswith(b"\x00\x00\x01\xba") or prefix.startswith(b"\x00\x00\x01\xb3"):
        return "mpeg_video"
    if prefix.startswith(b"#!"):
        return "script"
    return "unknown"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return round(-sum((count / total) * math.log2(count / total) for count in counts if count), 4)


def _extract_strings(data: bytes, limit: int = MAX_EXTRACTED_STRINGS) -> list[str]:
    sample = data[: 8 * 1024 * 1024]
    patterns = [re.findall(rb"[\x20-\x7e]{4,}", sample), re.findall(rb"(?:[\x20-\x7e]\x00){4,}", sample)]
    result: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for raw in pattern:
            text = raw.decode("latin-1", "replace").replace("\x00", "")
            text = security.sanitize_text(text, 256)
            if text and text not in seen:
                seen.add(text)
                result.append(text)
                if len(result) >= limit:
                    return result
    return result


def _extract_urls(strings: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for text in strings:
        for match in URL_RE.findall(text):
            sanitized = security.sanitize_url(match, 2048)
            if sanitized not in seen:
                seen.add(sanitized)
                result.append(sanitized)
                if len(result) >= MAX_URLS:
                    return result
    return result


def _extract_ips(strings: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for text in strings:
        for match in IP_RE.findall(text):
            try:
                address = str(network_policy._parse_ip(match))
            except ValueError:
                continue
            if address not in seen:
                seen.add(address)
                result.append(address)
                if len(result) >= MAX_IPS:
                    return result
    return result


def _parse_pe(data: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    try:
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if offset + 24 > len(data):
            return result
        signature = data[offset : offset + 4]
        if signature != b"PE\x00\x00":
            return result
        machine, sections, timestamp = struct.unpack_from("<HHI", data, offset + 4)
        optional_magic = struct.unpack_from("<H", data, offset + 24)[0]
        result["machine"] = hex(machine)
        result["sections"] = sections
        result["timestamp"] = timestamp
        result["optional_header_magic"] = hex(optional_magic)
        if optional_magic == 0x10B:
            subsystem = struct.unpack_from("<H", data, offset + 24 + 68)[0]
            result["subsystem"] = subsystem
    except (struct.error, IndexError):
        pass
    return result


def _parse_elf(data: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    try:
        ei_class = data[4]
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"
        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        result["class"] = "64" if ei_class == 2 else "32"
        result["type"] = e_type
        result["machine"] = e_machine
    except (struct.error, IndexError):
        pass
    return result


def _archive_info(data: bytes) -> dict[str, object] | None:
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return None
    result: dict[str, object] = {"entries": [], "entry_count": 0, "total_uncompressed": 0}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            result["entry_count"] = len(infos)
            total = 0
            for info in infos[:200]:
                name = security.sanitize_text(info.filename, 512)
                total += max(0, info.file_size)
                result["entries"].append(
                    {
                        "name": name,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                        "encrypted": bool(info.flag_bits & 0x1),
                        "path_traversal": name.startswith("/") or ".." in name.split("/"),
                    }
                )
            result["total_uncompressed"] = total
            result["truncated"] = len(infos) > 200
    except (zipfile.BadZipFile, OSError):
        return None
    return result


def _static_file_analysis(task: dict[str, object], options: dict[str, object], limits: dict[str, int], writer: ArtifactWriter) -> dict[str, object]:
    input_info = task.get("input") if isinstance(task.get("input"), dict) else {}
    filename = security.sanitize_filename(str(input_info.get("filename", "input.bin")))
    data = INPUT_PATH.read_bytes()
    prefix = data[:64]
    file_type = _magic_type(prefix)
    strings = _extract_strings(data)
    indicators: list[str] = []
    if file_type in {"windows_executable", "elf_executable", "mach_o"}:
        indicators.append("executable_binary")
    if file_type in {"script"} or filename.lower().endswith((".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".py", ".hta")):
        indicators.append("script_content")
    if file_type in {"pdf"}:
        indicators.append("pdf_document")
    if file_type in {"zip", "ole_compound"}:
        indicators.append("archive_or_office_document")
    lower_strings = "\n".join(strings).lower()
    for keyword in ("powershell", "wscript.shell", "cmd.exe", "javascript:", "eval(", "frombase64string", "document.write", "macro", "autoopen", "document_open"):
        if keyword in lower_strings:
            indicators.append(f"keyword:{keyword}")
    if b"/JavaScript" in data or b"/OpenAction" in data or b"/Launch" in data:
        indicators.append("pdf_active_content")
    if b"VBA" in data or b"AutoOpen" in data:
        indicators.append("office_macro_indicator")
    urls = _extract_urls(strings)
    ips = _extract_ips(strings)
    if urls:
        indicators.append("embedded_urls")
    if ips:
        indicators.append("embedded_ip_addresses")
    executable: dict[str, object] = {}
    if file_type == "windows_executable":
        executable = _parse_pe(data)
    elif file_type == "elf_executable":
        executable = _parse_elf(data)
    media: dict[str, object] = {}
    if (options["analyze_media"] or options["extract_video_frames"]) and file_type in {
        "mp4_video", "matroska", "avi_video", "flv_video", "mpeg_video", "ogg_media", "wav_audio", "mpeg_audio", "flac_audio",
    }:
        media = _media_analysis(writer, bool(options["extract_video_frames"]), limits)
    return {
        "filename": filename,
        "size": len(data),
        "hashes": security.hash_bytes(data),
        "file_type": file_type,
        "entropy": _entropy(data),
        "indicators": sorted(set(indicators)),
        "strings": strings,
        "urls": urls,
        "ip_addresses": ips,
        "executable": executable,
        "archive": _archive_info(data),
        "media": media,
        "executed": False,
    }


def _media_analysis(writer: ArtifactWriter, extract_frames: bool, limits: dict[str, int]) -> dict[str, object]:
    result: dict[str, object] = {"ffprobe": None, "frames": [], "warnings": []}
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        result["warnings"].append("ffprobe is unavailable")
        return result
    probe = security.run_limited_process(
        [
            ffprobe, "-v", "error", "-show_format", "-show_streams", "-of", "json",
            "-i", str(INPUT_PATH),
        ],
        timeout=15,
        cwd="/tmp",
        max_output=512 * 1024,
        cpu_seconds=10,
        address_space=512 * 1024 * 1024,
        file_size=16 * 1024 * 1024,
    )
    parsed: dict[str, object] = {}
    try:
        candidate = json.loads(probe["stdout"])
        if isinstance(candidate, dict):
            streams = []
            for stream in candidate.get("streams", [])[:20] if isinstance(candidate.get("streams"), list) else []:
                if not isinstance(stream, dict):
                    continue
                streams.append(
                    {
                        "codec_type": stream.get("codec_type"),
                        "codec_name": stream.get("codec_name"),
                        "width": stream.get("width"),
                        "height": stream.get("height"),
                        "duration": stream.get("duration"),
                        "bit_rate": stream.get("bit_rate"),
                        "channels": stream.get("channels"),
                        "sample_rate": stream.get("sample_rate"),
                    }
                )
            format_info = candidate.get("format") if isinstance(candidate.get("format"), dict) else {}
            parsed = {
                "streams": streams,
                "format": {
                    "format_name": format_info.get("format_name"),
                    "duration": format_info.get("duration"),
                    "size": format_info.get("size"),
                    "bit_rate": format_info.get("bit_rate"),
                },
            }
    except (json.JSONDecodeError, TypeError):
        result["warnings"].append("ffprobe output could not be parsed")
    result["ffprobe"] = {
        "returncode": probe["returncode"],
        "timed_out": probe["timed_out"],
        "stderr": _truncate_text(probe["stderr"], 2048),
        "metadata": parsed,
    }
    if not extract_frames:
        return result
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        result["warnings"].append("ffmpeg is unavailable")
        return result
    with tempfile.TemporaryDirectory(prefix="trinetra-frames-", dir="/tmp") as temporary:
        output = Path(temporary) / "frame_%03d.jpg"
        run = security.run_limited_process(
            [
                ffmpeg, "-v", "error", "-y", "-i", str(INPUT_PATH),
                "-vf", "fps=1/5,scale=640:-2", "-frames:v", "6",
                "-f", "image2", str(output),
            ],
            timeout=45,
            cwd="/tmp",
            max_output=128 * 1024,
            cpu_seconds=30,
            address_space=768 * 1024 * 1024,
            file_size=32 * 1024 * 1024,
        )
        result["ffmpeg"] = {
            "returncode": run["returncode"],
            "timed_out": run["timed_out"],
            "stderr": _truncate_text(run["stderr"], 2048),
        }
        for frame in sorted(Path(temporary).glob("frame_*.jpg")):
            try:
                data = frame.read_bytes()
            except OSError:
                continue
            if len(data) > limits["max_artifact_bytes"]:
                continue
            if not data.startswith(b"\xff\xd8\xff"):
                continue
            metadata = writer.write(f"frame_{frame.stem.split('_')[-1]}.jpg", data)
            if metadata:
                result["frames"].append(metadata)
    return result


async def _tls_metadata(host: str, port: int) -> dict[str, object]:
    def probe() -> dict[str, object]:
        result: dict[str, object] = {}
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=8) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    result["verified"] = True
                    result["version"] = tls.version()
                    result["cipher"] = tls.cipher()[0] if tls.cipher() else None
        except ssl.SSLCertVerificationError as exc:
            result["verified"] = False
            result["verification_error"] = security.sanitize_text(getattr(exc, "verify_message", str(exc)), 512)
        except (OSError, ssl.SSLError) as exc:
            result["verified"] = False
            result["error"] = security.sanitize_text(str(exc), 512)
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=8) as raw:
                with unverified.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls:
                    result.setdefault("version", tls.version())
                    result.setdefault("cipher", tls.cipher()[0] if tls.cipher() else None)
                    der = tls.getpeercert(True)
        except (OSError, ssl.SSLError) as exc:
            result.setdefault("certificate_error", security.sanitize_text(str(exc), 512))
            return result
        if not der:
            return result
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            certificate = x509.load_der_x509_certificate(der)
            result["subject"] = certificate.subject.rfc4514_string()
            result["issuer"] = certificate.issuer.rfc4514_string()
            result["serial_number"] = hex(certificate.serial_number)
            result["not_before"] = certificate.not_valid_before_utc.isoformat()
            result["not_after"] = certificate.not_valid_after_utc.isoformat()
            result["sha256_fingerprint"] = certificate.fingerprint(hashes.SHA256()).hex()
        except Exception:
            result["certificate"] = {"der_sha256": security.sha256_bytes(der), "length": len(der)}
        return result

    try:
        return await asyncio.wait_for(asyncio.to_thread(probe), timeout=12)
    except Exception as exc:
        return {"error": security.sanitize_text(str(exc), 512)}


def _is_ip(host: str) -> bool:
    try:
        network_policy._parse_ip(host)
        return True
    except ValueError:
        return False


async def _http_probe(url: str, options: dict[str, object], limits: dict[str, int], writer: ArtifactWriter) -> dict[str, object]:
    import httpx

    result: dict[str, object] = {
        "redirect_chain": [],
        "requested_url": security.sanitize_url(url),
        "final": None,
        "warnings": [],
        "downloads": [],
        "tls": {},
    }
    current = url
    redirects = 0
    tls_cache: dict[tuple[str, int], dict[str, object]] = {}
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(20.0, connect=10.0),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        },
    ) as client:
        while True:
            try:
                validated = await asyncio.wait_for(network_policy.resolve_and_validate_url(current), timeout=15)
            except Exception as exc:
                result["warnings"].append({"stage": "validate", "error": _safe_error(exc)})
                result["final"] = {"url": security.sanitize_url(current), "blocked": True}
                break
            entry: dict[str, object] = {
                "url": security.sanitize_url(validated.url),
                "host": validated.host,
                "port": validated.port,
                "addresses": list(validated.addresses),
                "redirect": redirects > 0,
            }
            if validated.scheme == "https":
                key = (validated.host, validated.port)
                if key not in tls_cache:
                    tls_cache[key] = await _tls_metadata(validated.host, validated.port)
                entry["tls"] = tls_cache[key]
            try:
                request = client.build_request("GET", validated.url)
                response = await client.send(request, stream=True)
            except Exception as exc:
                entry["error"] = _safe_error(exc)
                result["redirect_chain"].append(entry)
                result["final"] = {"url": validated.url, "error": _safe_error(exc)}
                break
            entry["status"] = response.status_code
            entry["reason"] = response.reason_phrase
            entry["headers"] = security.sanitize_headers(response.headers)
            entry["content_type"] = security.sanitize_text(response.headers.get("content-type", ""), 256)
            try:
                length_header = response.headers.get("content-length")
                entry["content_length"] = int(length_header) if length_header and length_header.isdigit() else None
            except ValueError:
                entry["content_length"] = None
            location = response.headers.get("location")
            content_type = (response.headers.get("content-type") or "").lower()
            is_redirect = response.status_code in {301, 302, 303, 307, 308} and bool(location)
            body_allowed = (
                content_type.startswith(("text/", "application/json", "application/javascript", "application/xml", "application/xhtml"))
                or options["allow_downloads"]
            )
            body = b""
            truncated = False
            if body_allowed:
                limit = limits["max_download_bytes"] if options["allow_downloads"] and not is_redirect else limits["max_http_body_bytes"]
                try:
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > limit:
                            body = body[:limit]
                            truncated = True
                            break
                except Exception as exc:
                    entry["body_error"] = _safe_error(exc)
            entry["body_size"] = len(body)
            entry["body_truncated"] = truncated
            if body:
                entry["body_sha256"] = security.sha256_bytes(body)
                if content_type.startswith(("text/", "application/json", "application/javascript", "application/xml")):
                    entry["body_preview"] = _truncate_text(body.decode("utf-8", "replace"))
                if options["allow_downloads"] and not is_redirect and not content_type.startswith(("text/", "application/json", "application/javascript", "application/xml")):
                    filename = security.sanitize_filename(_download_name(response.headers, validated.url))
                    artifact = writer.write(f"download_{len(result['downloads']) + 1}_{filename}", body)
                    if artifact:
                        result["downloads"].append(artifact)
            await response.aclose()
            result["redirect_chain"].append(entry)
            if is_redirect and location:
                redirects += 1
                if redirects > int(options["max_redirects"]):
                    result["warnings"].append({"stage": "redirect", "error": "redirect limit exceeded"})
                    break
                try:
                    next_url = urljoin(validated.url, location)
                    network_policy.validate_url(next_url)
                except network_policy.NetworkPolicyError as exc:
                    result["warnings"].append({"stage": "redirect", "error": exc.message, "location": security.sanitize_url(location)})
                    result["final"] = {"url": validated.url, "redirect_blocked": True}
                    break
                current = next_url
                continue
            result["final"] = {
                "url": security.sanitize_url(validated.url),
                "status": response.status_code,
                "content_type": entry["content_type"],
                "body_size": len(body),
                "body_truncated": truncated,
            }
            break
    return result


def _download_name(headers: object, url: str) -> str:
    disposition = ""
    try:
        disposition = headers.get("content-disposition", "") if hasattr(headers, "get") else ""
    except Exception:
        disposition = ""
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', disposition, re.IGNORECASE)
    if match:
        return match.group(1)
    name = urlsplit(url).path.rsplit("/", 1)[-1] or "download.bin"
    return name


async def _browser_probe(url: str, options: dict[str, object], limits: dict[str, int], writer: ArtifactWriter) -> dict[str, object]:
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        from playwright.async_api import async_playwright
    except Exception as exc:
        return {"available": False, "error": _safe_error(exc), "warnings": ["playwright is unavailable"]}
    result: dict[str, object] = {
        "available": True,
        "requested_url": security.sanitize_url(url),
        "final_url": None,
        "title": "",
        "screenshot": None,
        "html_artifact": None,
        "responses": [],
        "blocked_requests": [],
        "console": [],
        "page_errors": [],
        "request_count": 0,
        "links": [],
        "forms": [],
        "scripts": {"inline_count": 0, "external": []},
        "resources": [],
        "javascript": {},
        "downloads": [],
        "warnings": [],
    }
    responses = result["responses"]
    blocked_requests = result["blocked_requests"]
    console = result["console"]
    page_errors = result["page_errors"]
    links = result["links"]
    forms = result["forms"]
    external_scripts = result["scripts"]["external"]
    resources = result["resources"]
    downloads = result["downloads"]
    dns_cache: dict[str, tuple[float, bool]] = {}
    download_tasks: set[asyncio.Task] = set()
    request_count = 0
    blocked_count = 0

    async def validate_browser_url(target: str) -> None:
        parsed = urlsplit(target)
        scheme = parsed.scheme.lower()
        if scheme in {"data", "blob", "about"}:
            return
        if scheme not in {"http", "https"}:
            raise network_policy.NetworkPolicyError("invalid_scheme", "browser request scheme is not allowed")
        host = (parsed.hostname or "").lower()
        now = time.monotonic()
        cached = dns_cache.get(host)
        if cached is not None and cached[0] > now:
            if not cached[1]:
                raise network_policy.NetworkPolicyError("forbidden_destination", "browser destination was blocked")
            return
        try:
            await asyncio.wait_for(network_policy.resolve_and_validate_url(target), timeout=10)
            dns_cache[host] = (now + 30, True)
        except Exception:
            dns_cache[host] = (now + 30, False)
            raise

    async def route_handler(route: object) -> None:
        nonlocal request_count, blocked_count
        request = route.request
        request_count += 1
        result["request_count"] = request_count
        if request_count > MAX_BROWSER_REQUESTS:
            if blocked_count < MAX_BLOCKED_REQUESTS:
                blocked_requests.append({"url": security.sanitize_url(request.url), "reason": "request limit exceeded"})
                blocked_count += 1
            await route.abort("blockedbyclient")
            return
        try:
            await validate_browser_url(request.url)
            await route.continue_()
        except Exception as exc:
            if blocked_count < MAX_BLOCKED_REQUESTS:
                blocked_requests.append({"url": security.sanitize_url(request.url), "reason": _safe_error(exc)["message"]})
                blocked_count += 1
            await route.abort("blockedbyclient")

    def response_handler(response: object) -> None:
        if len(responses) >= MAX_BROWSER_RESPONSES:
            return
        try:
            location = response.headers.get("location", "")
            responses.append(
                {
                    "url": security.sanitize_url(response.url),
                    "status": response.status,
                    "resource_type": response.request.resource_type,
                    "location": security.sanitize_url(location) if location else "",
                    "headers": security.sanitize_headers(response.headers),
                }
            )
        except Exception:
            return

    def console_handler(message: object) -> None:
        if options["capture_console"] and len(console) < MAX_CONSOLE_MESSAGES:
            try:
                console.append({"type": message.type, "text": security.sanitize_text(message.text, 2048)})
            except Exception:
                return

    def page_error_handler(error: object) -> None:
        if len(page_errors) < MAX_CONSOLE_MESSAGES:
            page_errors.append(security.sanitize_text(str(error), 2048))

    async def save_download(download: object) -> None:
        if len(downloads) >= MAX_DOWNLOADS:
            return
        try:
            suggested = security.sanitize_filename(download.suggested_filename)
            with tempfile.TemporaryDirectory(prefix="trinetra-download-", dir="/tmp") as temporary:
                path = Path(temporary) / suggested
                await download.save_as(str(path))
                if not path.exists() or path.is_symlink():
                    return
                size = path.stat().st_size
                if size <= 0 or size > limits["max_download_bytes"]:
                    return
                data = path.read_bytes()
            artifact = writer.write(f"download_{len(downloads) + 1}_{suggested}", data)
            if artifact:
                downloads.append(artifact)
        except Exception:
            return

    def download_handler(download: object) -> None:
        task = asyncio.create_task(save_download(download))
        download_tasks.add(task)
        task.add_done_callback(download_tasks.discard)

    async with async_playwright() as playwright:
        browser = None
        context = None
        try:
            browser = await playwright.chromium.launch(
                headless=True,
                timeout=30000,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-extensions",
                    "--disable-sync",
                    "--disable-features=Translate,OptimizationHints,MediaRouter,DnsOverHttps",
                    "--disable-breakpad",
                    "--metrics-recording-only",
                    "--no-first-run",
                    "--no-proxy-server",
                    "--safebrowsing-disable-auto-update",
                    "--js-flags=--max-old-space-size=256",
                ],
            )
            context = await browser.new_context(
                accept_downloads=bool(options["allow_downloads"]),
                ignore_https_errors=True,
                java_script_enabled=True,
                service_workers="block",
                user_agent=USER_AGENT,
                locale="en-US",
                timezone_id="UTC",
                viewport={"width": 1280, "height": 800},
                color_scheme="light",
                reduced_motion="reduce",
            )
            page = await context.new_page()
            await context.route("**/*", route_handler)
            page.on("response", response_handler)
            page.on("console", console_handler)
            page.on("pageerror", page_error_handler)
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
            if options["allow_downloads"]:
                page.on("download", download_handler)
            _set_status("browser", 55)
            remaining = max(5.0, float(options["timeout_seconds"]) - 30.0)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=int(min(45.0, remaining) * 1000))
            except PlaywrightTimeoutError:
                result["warnings"].append("navigation timed out")
            except PlaywrightError as exc:
                result["warnings"].append(security.sanitize_text(str(exc), 1024))
            try:
                await page.wait_for_timeout(1500)
            except Exception:
                pass
            result["final_url"] = security.sanitize_url(page.url)
            try:
                result["title"] = security.sanitize_text(await page.title(), 512)
            except Exception:
                result["title"] = ""
            if options["take_screenshot"]:
                _set_status("browser_screenshot", 65)
                with tempfile.TemporaryDirectory(prefix="trinetra-shot-", dir="/tmp") as temporary:
                    shot_path = Path(temporary) / "screenshot.png"
                    try:
                        await page.screenshot(path=str(shot_path), full_page=bool(options["full_page_screenshot"]), type="png")
                        if shot_path.exists() and not shot_path.is_symlink():
                            data = shot_path.read_bytes()
                            if len(data) <= limits["max_artifact_bytes"] and data.startswith(b"\x89PNG\r\n\x1a\n"):
                                result["screenshot"] = writer.write("screenshot.png", data)
                    except Exception as exc:
                        result["warnings"].append(security.sanitize_text(f"screenshot failed: {exc}", 512))
            html_text = ""
            if options["capture_html"]:
                try:
                    html_text = await page.content()
                except Exception as exc:
                    result["warnings"].append(security.sanitize_text(f"html capture failed: {exc}", 512))
                if html_text:
                    encoded = html_text.encode("utf-8", "replace")
                    if len(encoded) > MAX_HTML_ARTIFACT:
                        encoded = encoded[:MAX_HTML_ARTIFACT]
                    artifact = writer.write("page.html", encoded)
                    result["html_artifact"] = artifact
                    result["html_preview"] = _truncate_text(html_text)
                    result["javascript"] = {
                        "eval_usage": bool(re.search(r"\beval\s*\(", html_text)),
                        "function_constructor": bool(re.search(r"\bnew\s+Function\s*\(", html_text)),
                        "websocket_usage": bool(re.search(r"\bWebSocket\s*\(", html_text)),
                        "fetch_usage": bool(re.search(r"\bfetch\s*\(", html_text)),
                        "atob_usage": bool(re.search(r"\batob\s*\(", html_text)),
                        "inline_script_count": len(re.findall(r"<script(?:\s|>)", html_text, re.IGNORECASE)),
                        "form_count": len(re.findall(r"<form(?:\s|>)", html_text, re.IGNORECASE)),
                        "iframe_count": len(re.findall(r"<iframe(?:\s|>)", html_text, re.IGNORECASE)),
                    }
            try:
                links.extend(await page.eval_on_selector_all("a[href]", "els => els.slice(0,200).map(e => e.href)"))
                forms.extend(await page.eval_on_selector_all(
                    "form",
                    "els => els.slice(0,50).map(e => ({action: e.action, method: e.method, inputs: Array.from(e.querySelectorAll('input,select,textarea')).slice(0,50).map(i => ({type: i.type, name: i.name}))}))",
                ))
                external_scripts.extend(await page.eval_on_selector_all("script[src]", "els => els.slice(0,200).map(e => e.src)"))
                resources.extend(await page.evaluate("performance.getEntriesByType('resource').slice(0,500).map(e => e.name)"))
                result["scripts"]["inline_count"] = int(await page.evaluate("document.querySelectorAll('script:not([src])').length"))
                result["iframes"] = await page.eval_on_selector_all("iframe[src]", "els => els.slice(0,100).map(e => e.src)")
            except Exception:
                pass
            result["links"] = [security.sanitize_url(item) for item in links[:200] if isinstance(item, str)]
            result["resources"] = [security.sanitize_url(item) for item in resources[:500] if isinstance(item, str)]
            result["scripts"]["external"] = [security.sanitize_url(item) for item in external_scripts[:200] if isinstance(item, str)]
            result["forms"] = forms[:50]
            try:
                cookies = await context.cookies()
                result["browser_state"] = {"stored_objects": len(cookies)}
            except Exception:
                result["browser_state"] = {"stored_objects": 0}
            if download_tasks:
                await asyncio.wait(list(download_tasks), timeout=10)
        except Exception as exc:
            result["warnings"].append(security.sanitize_text(f"browser error: {exc}", 1024))
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass
    return result


async def _investigate_url(task: dict[str, object], options: dict[str, object], limits: dict[str, int], writer: ArtifactWriter) -> dict[str, object]:
    raw_url = task.get("url")
    if not isinstance(raw_url, str) or not raw_url:
        raise RuntimeError("url task is missing a URL")
    evidence: dict[str, object] = {
        "kind": "url",
        "outcome": "unknown",
        "target": {"url": security.sanitize_url(raw_url)},
        "dns": {},
        "http": {},
        "browser": {},
        "warnings": [],
        "errors": [],
    }
    try:
        validated = network_policy.validate_url(raw_url)
    except network_policy.NetworkPolicyError as exc:
        evidence["outcome"] = "blocked"
        evidence["errors"].append({"stage": "url_validation", "code": exc.code, "message": exc.message})
        return evidence
    evidence["target"] = {
        "url": security.sanitize_url(validated.url),
        "scheme": validated.scheme,
        "host": validated.host,
        "port": validated.port,
    }
    _set_status("resolving", 10)
    try:
        addresses = await asyncio.wait_for(
            network_policy.resolve_and_validate_host(validated.host, validated.port),
            timeout=15,
        )
        evidence["dns"] = {"status": "ok", "addresses": list(addresses)}
    except Exception as exc:
        evidence["outcome"] = "blocked"
        evidence["dns"] = {"status": "blocked", "error": _safe_error(exc)}
        return evidence
    _set_status("http", 25)
    try:
        evidence["http"] = await _http_probe(validated.url, options, limits, writer)
    except Exception as exc:
        evidence["errors"].append({"stage": "http", "error": _safe_error(exc)})
    _set_status("browser", 45)
    try:
        evidence["browser"] = await _browser_probe(validated.url, options, limits, writer)
    except Exception as exc:
        evidence["errors"].append({"stage": "browser", "error": _safe_error(exc)})
    http_result = evidence.get("http") if isinstance(evidence.get("http"), dict) else {}
    browser_result = evidence.get("browser") if isinstance(evidence.get("browser"), dict) else {}
    if http_result.get("final") or browser_result.get("final_url"):
        evidence["outcome"] = "completed"
    elif http_result.get("warnings") or browser_result.get("warnings"):
        evidence["outcome"] = "completed_with_errors"
    else:
        evidence["outcome"] = "completed"
    return evidence


async def _investigate_file(task: dict[str, object], options: dict[str, object], limits: dict[str, int], writer: ArtifactWriter) -> dict[str, object]:
    if not INPUT_PATH.is_file() or INPUT_PATH.is_symlink():
        raise RuntimeError("uploaded file is missing")
    _set_status("analyzing_file", 20)
    static = await asyncio.to_thread(_static_file_analysis, task, options, limits, writer)
    _set_status("analyzing_file", 80)
    return {
        "kind": "file",
        "outcome": "completed",
        "file": static,
        "warnings": static.get("media", {}).get("warnings", []) if isinstance(static.get("media"), dict) else [],
        "errors": [],
    }


async def _investigate(task: dict[str, object]) -> dict[str, object]:
    options = _normalized_options(task["options"] if isinstance(task.get("options"), dict) else {})
    limits = _normalized_limits(task["limits"] if isinstance(task.get("limits"), dict) else {})
    writer = ArtifactWriter(EVIDENCE_DIR, limits["max_artifact_bytes"], limits["max_artifacts"])
    started = _utc_now()
    _set_status("validating", 5)
    if task["kind"] == "url":
        evidence = await _investigate_url(task, options, limits, writer)
    else:
        evidence = await _investigate_file(task, options, limits, writer)
    evidence["schema_version"] = 1
    evidence["session_id"] = task["session_id"]
    evidence["started_at"] = started
    evidence["completed_at"] = _utc_now()
    evidence["options"] = options
    evidence["limits"] = limits
    evidence["artifacts"] = writer.artifacts
    evidence["engine"] = {"worker": "trinetra-sandbox", "version": "1.0", "python": sys.version.split()[0]}
    return evidence


def _write_results(evidence: dict[str, object], max_bytes: int) -> None:
    sanitized = security.sanitize_evidence(evidence, max_string=MAX_STRING_EVIDENCE)
    encoded = security.json_bytes(sanitized)
    if len(encoded) > max_bytes:
        sanitized = {
            "schema_version": 1,
            "session_id": evidence.get("session_id"),
            "status": "failed",
            "outcome": "failed",
            "started_at": evidence.get("started_at"),
            "completed_at": evidence.get("completed_at"),
            "error": {"code": "evidence_limit", "message": "evidence exceeded the configured limit"},
            "artifacts": evidence.get("artifacts", []),
        }
        encoded = security.json_bytes(sanitized)
    temporary = RESULTS_PATH.with_name("results.json.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, RESULTS_PATH)


def main() -> int:
    _prepare_workdir()
    _set_status("starting", 1)
    task: dict[str, object] | None = None
    try:
        task = _load_task()
        max_bytes = _normalized_limits(task["limits"] if isinstance(task.get("limits"), dict) else {})["max_evidence_bytes"]
        evidence = asyncio.run(_investigate(task))
        status = "completed" if evidence.get("outcome") in {"completed", "completed_with_errors"} else "blocked"
        evidence["status"] = status
        _set_status("writing_evidence", 90)
        _write_results(evidence, max_bytes)
        _set_status("completed", 100)
        return 0
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        failure = {
            "schema_version": 1,
            "session_id": task.get("session_id") if isinstance(task, dict) else None,
            "status": "failed",
            "outcome": "failed",
            "started_at": _utc_now(),
            "completed_at": _utc_now(),
            "error": _safe_error(exc),
        }
        try:
            _write_results(failure, 1024 * 1024)
        except Exception:
            pass
        _set_status("failed", 100, detail=security.sanitize_text(str(exc), 512))
        print(security.sanitize_text(traceback.format_exc(), 8192), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
