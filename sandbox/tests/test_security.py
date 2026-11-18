from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from sandbox import security


def _tar_with(members: list[tuple[str, bytes, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            info.mode = 0o600
            if kind == "file":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload.decode()
                archive.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
    return buffer.getvalue()


def test_safe_tar_round_trip(tmp_path: Path) -> None:
    archive = security.build_tar({"page.html": b"hello", "input/input.bin": b"data"})
    result = security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024)
    assert result["bytes"] == 9
    assert (tmp_path / "out" / "page.html").read_bytes() == b"hello"
    assert (tmp_path / "out" / "input" / "input.bin").read_bytes() == b"data"


def test_tar_traversal_is_rejected(tmp_path: Path) -> None:
    archive = _tar_with([("../escape", "file", b"bad")])
    with pytest.raises(security.SecurityError):
        security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024)
    assert not (tmp_path / "escape").exists()


def test_absolute_tar_member_is_rejected(tmp_path: Path) -> None:
    archive = _tar_with([("/etc/passwd", "file", b"bad")])
    with pytest.raises(security.SecurityError):
        security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024)


def test_symlink_tar_member_is_rejected(tmp_path: Path) -> None:
    archive = _tar_with([("link", "symlink", b"/etc/passwd")])
    with pytest.raises(security.SecurityError):
        security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024)
    assert not (tmp_path / "out" / "link").exists()


def test_tar_size_limit_is_enforced(tmp_path: Path) -> None:
    archive = _tar_with([("large", "file", b"x" * 2048)])
    with pytest.raises(security.EvidenceLimitError):
        security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024)


def test_tar_file_count_limit_is_enforced(tmp_path: Path) -> None:
    archive = _tar_with([(f"file-{index}", "file", b"x") for index in range(4)])
    with pytest.raises(security.EvidenceLimitError):
        security.safe_extract_tar(archive, tmp_path / "out", max_bytes=1024, max_files=3)


def test_filename_sanitization() -> None:
    assert security.sanitize_filename("../../etc/passwd") == "passwd"
    assert security.sanitize_filename("..\\..\\windows\\system32\\x.dll") == "x.dll"
    assert security.sanitize_filename("") == "input.bin"
    assert "/" not in security.sanitize_filename("a/b/c.txt")


def test_evidence_redaction() -> None:
    sanitized = security.sanitize_evidence(
        {
            "url": "https://example.com/?token=abcdef&q=1",
            "headers": {"Authorization": "Bearer secret", "Content-Type": "text/html"},
            "nested": {"password": "hunter2", "value": 1},
        }
    )
    assert "abcdef" not in sanitized["url"]
    assert sanitized["headers"]["Authorization"] == security.REDACTED
    assert sanitized["nested"]["password"] == security.REDACTED
    assert sanitized["nested"]["value"] == 1


def test_text_control_characters_are_removed() -> None:
    assert security.sanitize_text("a\x00b\x1bc") == "abc"


def test_token_matching() -> None:
    assert security.token_matches("a" * 32, "a" * 32)
    assert not security.token_matches("a" * 31, "a" * 32)
    assert not security.token_matches(None, "a" * 32)


def test_artifact_content_types() -> None:
    assert security.artifact_content_type("page.html", b"<html>") == "text/plain; charset=utf-8"
    assert security.artifact_content_type("screenshot.png", b"\x89PNG\r\n\x1a\n") == "image/png"
    assert security.artifact_content_type("payload.bin", b"MZ") == "application/octet-stream"
    assert security.artifact_content_type("fake.png", b"<html>") == "application/octet-stream"


def test_artifact_name_validation() -> None:
    assert security.require_safe_artifact_name("page.html") == "page.html"
    for name in ("../x", "/etc/passwd", "a/../../b", ""):
        with pytest.raises(security.SecurityError):
            security.require_safe_artifact_name(name)
