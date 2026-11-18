from __future__ import annotations

import asyncio
import os
import shutil
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

FLAG_ALLOWLIST: dict[str, set[str]] = {
    "file": {"-b", "-i", "-k", "-L", "--mime-type", "--mime-encoding", "--brief"},
    "sha256sum": {"-b", "-t", "--binary", "--text"},
    "strings": {"-a", "--all"},
    "exiftool": {"-j", "-json", "-s", "-S", "-G", "-n", "-q", "-qQ", "-a", "-u", "-g"},
    "identify": {"-verbose"},
    "pdfinfo": {"-meta", "-js", "-url", "-dests", "-box"},
    "ffprobe": {"-v", "-show_format", "-show_streams", "-of", "-i", "-hide_banner", "-loglevel"},
}
VALUE_FLAGS: dict[str, dict[str, set[str]]] = {
    "ffprobe": {
        "-v": {"error", "warning", "info", "quiet"},
        "-loglevel": {"error", "warning", "info", "quiet"},
        "-of": {"json", "default"},
    },
    "strings": {},
}
NUMERIC_VALUE_FLAGS = {
    "strings": {"-n"},
}


class TerminalError(RuntimeError):
    pass


@dataclass
class TerminalResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class ReadonlyTerminal:
    def __init__(self, workspace: Path, *, timeout_seconds: float = 15.0, max_output: int = 65536) -> None:
        self.workspace = Path(workspace).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_output = max(1024, max_output)
        self.temp = self.workspace / ".terminal-tmp"
        self.temp.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _validate_path(self, value: str) -> Path:
        if not value or "\x00" in value:
            raise TerminalError("invalid path argument")
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise TerminalError("path does not exist inside the workspace") from exc
        if resolved != self.workspace and self.workspace not in resolved.parents:
            raise TerminalError("path escapes the workspace")
        return resolved

    def validate(self, command: Iterable[str]) -> tuple[list[str], list[str]]:
        args = [str(item) for item in command]
        if not args or len(args) > 32:
            raise TerminalError("invalid command length")
        if any(not item or len(item) > 1024 or "\x00" in item or "\n" in item or "\r" in item for item in args):
            raise TerminalError("invalid command argument")
        binary = Path(args[0]).name
        if binary not in FLAG_ALLOWLIST:
            raise TerminalError("command is not allowed")
        executable = shutil.which(binary)
        if executable is None:
            raise TerminalError("command is unavailable on this host")
        allowed_flags = FLAG_ALLOWLIST[binary]
        value_flags = VALUE_FLAGS.get(binary, {})
        numeric_flags = NUMERIC_VALUE_FLAGS.get(binary, set())
        paths: list[Path] = []
        normalized = [executable]
        index = 1
        while index < len(args):
            arg = args[index]
            if arg == "--":
                index += 1
                while index < len(args):
                    path = self._validate_path(args[index])
                    if not path.is_file():
                        raise TerminalError("terminal input must be a regular file")
                    paths.append(path)
                    normalized.append(str(path))
                    index += 1
                break
            if arg.startswith("-"):
                if arg not in allowed_flags:
                    raise TerminalError("command flag is not allowed")
                normalized.append(arg)
                if arg in value_flags:
                    if index + 1 >= len(args):
                        raise TerminalError("command flag is missing a value")
                    value = args[index + 1]
                    if value not in value_flags[arg]:
                        raise TerminalError("command flag value is not allowed")
                    normalized.append(value)
                    index += 2
                    continue
                if arg in numeric_flags:
                    if index + 1 >= len(args) or not args[index + 1].isdigit():
                        raise TerminalError("command flag requires a numeric value")
                    value = int(args[index + 1])
                    if not 1 <= value <= 1024:
                        raise TerminalError("numeric command value is out of range")
                    normalized.append(str(value))
                    index += 2
                    continue
                index += 1
                continue
            path = self._validate_path(arg)
            if not path.is_file():
                raise TerminalError("terminal input must be a regular file")
            paths.append(path)
            normalized.append(str(path))
            index += 1
        if not paths:
            raise TerminalError("command requires a workspace file")
        return normalized, [str(path) for path in paths]

    async def run(self, command: Iterable[str]) -> TerminalResult:
        argv, paths = self.validate(command)
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.temp),
            "TMPDIR": str(self.temp),
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        }
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.workspace),
            env=environment,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = await process.communicate()
        return TerminalResult(
            command=[Path(argv[0]).name, *argv[1:]],
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout[: self.max_output].decode("utf-8", "replace"),
            stderr=stderr[: self.max_output].decode("utf-8", "replace"),
            timed_out=timed_out,
        )
