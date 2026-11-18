from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import tarfile
import time
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Mapping

REDACTED = "[REDACTED]"
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|"
    r"authorization|cookie|session[_\-]?id|credential|client[_\-]?secret|refresh[_\-]?token)",
    re.IGNORECASE,
)
SENSITIVE_QUERY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|"
    r"authorization|cookie|session|credential|signature|sig|key)",
    re.IGNORECASE,
)
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}
IMAGE_MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}
TEXT_MIME_BY_EXT = {
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".html": "text/plain; charset=utf-8",
    ".htm": "text/plain; charset=utf-8",
    ".json": "text/plain; charset=utf-8",
    ".csv": "text/plain; charset=utf-8",
    ".js": "text/plain; charset=utf-8",
    ".css": "text/plain; charset=utf-8",
}


class SecurityError(Exception):
    pass


class EvidenceLimitError(SecurityError):
    pass


def token_matches(provided: str | None, expected: str | None) -> bool:
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_filename(name: str, fallback: str = "input.bin") -> str:
    text = str(name or "")
    base = text.replace("\\", "/").split("/")[-1]
    base = "".join(ch for ch in base if 32 <= ord(ch) < 127 and ch not in '<>:"/\\|?*')
    base = base.strip(" .")
    if not base or base in {".", ".."}:
        base = fallback
    if len(base) > 128:
        stem, dot, suffix = base.rpartition(".")
        if dot and len(suffix) <= 16:
            base = stem[: 128 - len(suffix) - 1] + "." + suffix
        else:
            base = base[:128]
    if not SAFE_NAME_RE.fullmatch(base):
        base = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip(" ._") or fallback
    if not SAFE_NAME_RE.fullmatch(base):
        base = fallback
    return base


def require_safe_artifact_name(name: str) -> str:
    if not name or "\\" in name or name.startswith("/"):
        raise SecurityError("invalid artifact name")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SecurityError("invalid artifact name")
    for part in path.parts:
        if not SAFE_NAME_RE.fullmatch(part):
            raise SecurityError("invalid artifact name")
    if len(name) > 255:
        raise SecurityError("artifact name is too long")
    return path.as_posix()


def sanitize_text(value: Any, max_length: int = 65536) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    text = CONTROL_RE.sub("", text)
    if len(text) > max_length:
        text = text[:max_length] + "...[truncated]"
    return text


def sanitize_log(value: Any, max_length: int = 32768) -> str:
    return sanitize_text(value, max_length=max_length)


def sanitize_url(url: Any, max_length: int = 4096) -> str:
    text = sanitize_text(url, max_length=max_length * 2)
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return text[:max_length]
    if not parsed.netloc:
        return text[:max_length]
    host = parsed.hostname or ""
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += ":" + REDACTED
        netloc = userinfo + "@" + netloc
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted_query = urllib.parse.urlencode(
        [
            (key, REDACTED if SENSITIVE_QUERY_RE.search(key) else value)
            for key, value in query_pairs
        ],
        doseq=True,
    )
    result = urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, redacted_query, parsed.fragment))
    return result[:max_length]


def sanitize_headers(headers: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> dict[str, str]:
    if not headers:
        return {}
    items = headers.items() if isinstance(headers, Mapping) else headers
    result: dict[str, str] = {}
    for index, (raw_key, raw_value) in enumerate(items):
        if index >= 100:
            break
        key = sanitize_text(raw_key, max_length=128).strip()
        if not key:
            continue
        if key.lower() in SENSITIVE_HEADERS or SENSITIVE_KEY_RE.search(key):
            result[key] = REDACTED
        else:
            result[key] = sanitize_text(raw_value, max_length=4096)
    return result


def sanitize_evidence(
    value: Any,
    *,
    max_string: int = 65536,
    max_depth: int = 12,
    max_items: int = 20000,
) -> Any:
    counter = [0]

    def walk(item: Any, depth: int) -> Any:
        counter[0] += 1
        if counter[0] > max_items:
            raise EvidenceLimitError("evidence contains too many items")
        if depth > max_depth:
            return "[truncated:depth]"
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, int):
            return item
        if isinstance(item, float):
            return item if math.isfinite(item) else None
        if isinstance(item, str):
            if item.startswith(("http://", "https://")):
                return sanitize_url(item, max_length=max_string)
            return sanitize_text(item, max_length=max_string)
        if isinstance(item, (bytes, bytearray, memoryview)):
            raw = bytes(item)
            return {
                "encoding": "base64",
                "length": len(raw),
                "sha256": sha256_bytes(raw),
                "preview": base64.b64encode(raw[:256]).decode("ascii"),
            }
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for index, (raw_key, raw_value) in enumerate(item.items()):
                if index >= 500:
                    result["__truncated__"] = True
                    break
                key = sanitize_text(raw_key, max_length=256)
                if not key:
                    continue
                if SENSITIVE_KEY_RE.search(key):
                    result[key] = REDACTED
                else:
                    result[key] = walk(raw_value, depth + 1)
            return result
        if isinstance(item, (list, tuple, set, frozenset)):
            result_list = []
            for index, raw_value in enumerate(item):
                if index >= 2000:
                    result_list.append("[truncated:list]")
                    break
                result_list.append(walk(raw_value, depth + 1))
            return result_list
        return sanitize_text(item, max_length=max_string)

    return walk(value, 0)


def json_bytes(value: Any, max_bytes: int | None = None) -> bytes:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False, default=str).encode("utf-8")
    if max_bytes is not None and len(encoded) > max_bytes:
        raise EvidenceLimitError("serialized evidence exceeds limit")
    return encoded


def write_json_atomic(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False, default=str).encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass


def _normalize_tar_name(name: str) -> str:
    if not name or "\x00" in name:
        raise SecurityError("invalid tar member")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise SecurityError("absolute tar member")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path = PurePosixPath(normalized)
    if not path.parts:
        raise SecurityError("empty tar member")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SecurityError("tar path traversal")
    return path.as_posix()


def safe_extract_tar(
    source: BinaryIO | bytes,
    destination: Path,
    *,
    max_bytes: int,
    max_files: int = 128,
) -> dict[str, Any]:
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists():
        destination.chmod(0o700)
    fileobj: BinaryIO
    if isinstance(source, (bytes, bytearray)):
        fileobj = io.BytesIO(bytes(source))
        mode = "r:"
    else:
        fileobj = source
        mode = "r|"
    extracted: list[str] = []
    total_bytes = 0
    try:
        with tarfile.open(fileobj=fileobj, mode=mode) as archive:
            for member in archive:
                if len(extracted) >= max_files:
                    raise EvidenceLimitError("too many evidence files")
                relative = _normalize_tar_name(member.name)
                if relative in extracted:
                    raise SecurityError("duplicate evidence file")
                target = destination.joinpath(relative)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    extracted.append(relative)
                    continue
                if not member.isfile():
                    raise SecurityError("unsupported evidence member type")
                if member.size < 0 or member.size > max_bytes:
                    raise EvidenceLimitError("evidence file is too large")
                total_bytes += member.size
                if total_bytes > max_bytes:
                    raise EvidenceLimitError("evidence archive is too large")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source_handle = archive.extractfile(member)
                if source_handle is None:
                    raise SecurityError("invalid evidence member")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                written = 0
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        while True:
                            chunk = source_handle.read(1024 * 256)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > member.size or written > max_bytes:
                                raise EvidenceLimitError("evidence member exceeds declared size")
                            handle.write(chunk)
                except Exception:
                    try:
                        target.unlink()
                    except OSError:
                        pass
                    raise
                extracted.append(relative)
    except (tarfile.TarError, OSError) as exc:
        if isinstance(exc, SecurityError):
            raise
        raise SecurityError("invalid evidence archive") from exc
    return {"files": extracted, "bytes": total_bytes}



def read_stream_bounded(source: Any, max_bytes: int, chunk_size: int = 256 * 1024) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
        if len(raw) > max_bytes:
            raise EvidenceLimitError("stream exceeds the configured limit")
        return raw
    chunks: list[bytes] = []
    total = 0
    read = getattr(source, "read", None)
    if callable(read):
        iterator = iter(lambda: read(chunk_size), b"")
    else:
        iterator = iter(source)
    for chunk in iterator:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise SecurityError("stream returned a non-bytes chunk")
        data = bytes(chunk)
        total += len(data)
        if total > max_bytes:
            raise EvidenceLimitError("stream exceeds the configured limit")
        chunks.append(data)
    return b"".join(chunks)

def build_tar(files: Mapping[str, bytes], *, uid: int = 0, gid: int = 0) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for raw_name, data in files.items():
            name = PurePosixPath(raw_name).as_posix()
            relative = _normalize_tar_name(name)
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o600
            info.uid = uid
            info.gid = gid
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def artifact_content_type(name: str, data_prefix: bytes = b"") -> str:
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in IMAGE_MIME_BY_EXT:
        if suffix == ".png" and data_prefix.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if suffix in {".jpg", ".jpeg"} and data_prefix.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if suffix == ".webp" and data_prefix.startswith(b"RIFF") and data_prefix[8:12] == b"WEBP":
            return "image/webp"
        return "application/octet-stream"
    return TEXT_MIME_BY_EXT.get(suffix, "application/octet-stream")


def read_prefix(path: Path, length: int = 16) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(descriptor, length)
    finally:
        os.close(descriptor)


def detect_media_prefix(prefix: bytes) -> str:
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith(b"RIFF") and prefix[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def _set_limits(
    *,
    cpu_seconds: int,
    address_space: int | None,
    file_size: int,
    process_count: int,
    open_files: int,
) -> None:
    import resource

    os.setsid()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    resource.setrlimit(resource.RLIMIT_NPROC, (process_count, process_count))
    resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
    if address_space is not None:
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))


def run_limited_process(
    argv: list[str],
    *,
    timeout: float,
    cwd: str | Path,
    max_output: int = 256 * 1024,
    cpu_seconds: int = 20,
    address_space: int | None = 512 * 1024 * 1024,
    file_size: int = 32 * 1024 * 1024,
    process_count: int = 64,
    open_files: int = 64,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(argv, list) or not argv or not all(isinstance(part, str) and part for part in argv):
        raise SecurityError("invalid process command")
    base_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if env:
        base_env.update({str(key): str(value) for key, value in env.items()})
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=base_env,
        start_new_session=True,
        preexec_fn=lambda: _set_limits(
            cpu_seconds=cpu_seconds,
            address_space=address_space,
            file_size=file_size,
            process_count=process_count,
            open_files=open_files,
        ),
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    duration = time.monotonic() - started
    return {
        "argv": [sanitize_text(part, max_length=512) for part in argv],
        "returncode": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(duration, 3),
        "stdout": stdout[:max_output].decode("utf-8", "replace"),
        "stderr": stderr[:max_output].decode("utf-8", "replace"),
        "stdout_truncated": len(stdout) > max_output,
        "stderr_truncated": len(stderr) > max_output,
    }


def ensure_within(base: Path, candidate: Path) -> Path:
    base_resolved = Path(base).resolve()
    candidate_resolved = Path(candidate).resolve()
    if base_resolved != candidate_resolved and base_resolved not in candidate_resolved.parents:
        raise SecurityError("path escapes its root")
    return candidate_resolved


def permission_bits(path: Path) -> int:
    return stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
