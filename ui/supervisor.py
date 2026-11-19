from __future__ import annotations

import asyncio
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Awaitable, Callable

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "sandbox" / "docker" / "Dockerfile.worker"
MANAGER_LOG = ROOT / "storage" / "sandbox-manager.log"

LogCallback = Callable[[str], None]
AuthorizeCallback = Callable[[], Awaitable[str | None]]


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


class SandboxSupervisor:
    def __init__(self) -> None:
        self.root = ROOT
        self.python = os.getenv("TRINETRA_PYTHON") or sys.executable
        self.base_url = (os.getenv("TRINETRA_SANDBOX_URL") or "http://127.0.0.1:8765").rstrip("/")
        self.image = os.getenv("SANDBOX_WORKER_IMAGE") or "trinetra-sandbox-worker:latest"
        self.manager_log = Path(os.getenv("TRINETRA_MANAGER_LOG", str(MANAGER_LOG)))
        self.manager_pid: int | None = None
        self._docker_prefix: list[str] | None = None
        self._sudo_ready = os.geteuid() == 0
        self._sudo_password: str | None = None
        self._start_lock = asyncio.Lock()

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health_sync)

    def _health_sync(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/healthz", timeout=2) as response:
                return response.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    async def _exec(
        self,
        command: list[str],
        *,
        timeout: float = 30.0,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(self.root),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            return 127, str(exc)
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return 124, "command timed out"
        return process.returncode or 0, output.decode("utf-8", "replace")

    async def _stream(
        self,
        command: list[str],
        *,
        log: LogCallback | None = None,
        env: dict[str, str] | None = None,
    ) -> int:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(self.root),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            if log:
                log(str(exc))
            return 127
        if process.stdout is not None:
            async for raw in process.stdout:
                text = raw.decode("utf-8", "replace").rstrip()
                if text and log:
                    log(text[:500])
        return await process.wait()

    async def _sudo_available(self) -> bool:
        if self._sudo_ready:
            return True
        code, _ = await self._exec(["sudo", "-n", "true"], timeout=5)
        self._sudo_ready = code == 0
        return self._sudo_ready

    async def _sudo_validate(self, password: str) -> bool:
        if not password or "\n" in password or "\r" in password:
            return False
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-S",
                "-v",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError:
            return False
        try:
            await asyncio.wait_for(process.communicate((password + "\n").encode("utf-8")), timeout=20)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False
        self._sudo_ready = process.returncode == 0
        if self._sudo_ready:
            self._sudo_password = password
        return self._sudo_ready

    async def _authorize(
        self,
        authorize: AuthorizeCallback | None,
        log: LogCallback | None = None,
    ) -> bool:
        if await self._sudo_available():
            return True
        if authorize is None:
            return False
        password = await authorize()
        if not password:
            if log:
                log("sudo password was canceled")
            return False
        if await self._sudo_validate(password):
            return True
        if log:
            log("sudo password was rejected")
        return False

    async def _docker(self, authorize: AuthorizeCallback | None, log: LogCallback | None = None) -> list[str] | None:
        if self._docker_prefix is not None:
            return self._docker_prefix
        code, _ = await self._exec(["docker", "info"], timeout=10)
        if code == 0:
            self._docker_prefix = ["docker"]
            return self._docker_prefix
        if await self._authorize(authorize, log):
            code, _ = await self._exec(["sudo", "-n", "docker", "info"], timeout=10)
            if code == 0:
                self._docker_prefix = ["sudo", "-n", "docker"]
                return self._docker_prefix
        if log:
            log("Docker daemon is not reachable")
        return None

    async def _start_docker(self, authorize: AuthorizeCallback | None, log: LogCallback | None = None) -> list[str] | None:
        if log:
            log("Starting Docker daemon...")
        if os.geteuid() == 0:
            command = ["systemctl", "start", "docker"]
        else:
            if not await self._authorize(authorize, log):
                return None
            command = ["sudo", "-n", "systemctl", "start", "docker"]
        code, output = await self._exec(command, timeout=45)
        if code != 0 and log:
            log(output.strip()[:500] or "Docker daemon could not be started")
        for _ in range(20):
            code, _ = await self._exec(["docker", "info"], timeout=5)
            if code == 0:
                self._docker_prefix = ["docker"]
                return self._docker_prefix
            code, _ = await self._exec(["sudo", "-n", "docker", "info"], timeout=5)
            if code == 0:
                self._docker_prefix = ["sudo", "-n", "docker"]
                return self._docker_prefix
            await asyncio.sleep(0.5)
        return None

    async def _ensure_image(self, docker: list[str], log: LogCallback | None = None) -> bool:
        code, _ = await self._exec([*docker, "image", "inspect", self.image], timeout=10)
        if code == 0:
            return True
        if log:
            log(f"Building worker image {self.image}...")
        code = await self._stream(
            [
                *docker,
                "build",
                "--pull",
                "--file",
                str(DOCKERFILE),
                "--tag",
                self.image,
                str(self.root / "sandbox"),
            ],
            log=log,
        )
        if code != 0:
            if log:
                log("Worker image build failed")
            return False
        return True

    async def _wait_health(self, timeout: float = 35.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self.health():
                return True
            await asyncio.sleep(0.5)
        return False

    def _manager_env(self) -> dict[str, str]:
        env = dict(os.environ)
        for key in ("TRINETRA_LLM_API_KEY", "TRINETRA_LLM_BASE_URL", "TRINETRA_LLM_MODEL"):
            env.pop(key, None)
        return env

    def _log_tail(self, limit: int = 2000) -> str:
        try:
            data = self.manager_log.read_bytes()
        except OSError:
            return ""
        return data[-limit:].decode("utf-8", "replace").strip()

    async def ensure_started(
        self,
        *,
        log: LogCallback | None = None,
        authorize: AuthorizeCallback | None = None,
    ) -> tuple[bool, str]:
        async with self._start_lock:
            return await self._ensure_started(log=log, authorize=authorize)

    async def _ensure_started(
        self,
        *,
        log: LogCallback | None = None,
        authorize: AuthorizeCallback | None = None,
    ) -> tuple[bool, str]:
        if await self.health():
            return True, "Sandbox manager is running"
        docker = await self._docker(authorize, log)
        if docker is None:
            docker = await self._start_docker(authorize, log)
        if docker is None:
            return False, "Docker is unavailable or cannot be started"
        if not await self._ensure_image(docker, log):
            return False, "Worker image is unavailable"
        if os.geteuid() != 0 and not await self._authorize(authorize, log):
            return False, "sudo authorization is required to start the sandbox"
        self.manager_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        command = [
            self.python,
            "-m",
            "uvicorn",
            "sandbox.manager:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
            "--workers",
            "1",
        ]
        sudo_password = self._sudo_password if os.geteuid() != 0 else None
        if os.geteuid() != 0:
            if sudo_password:
                command = ["sudo", "-S", "-E", *command]
            else:
                command = ["sudo", "-n", "-E", *command]
        if log:
            log("Starting sandbox manager...")
        try:
            handle = self.manager_log.open("ab")
        except OSError as exc:
            return False, f"cannot open manager log: {exc}"
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(self.root),
                env=self._manager_env(),
                stdin=asyncio.subprocess.PIPE if sudo_password else None,
                stdout=handle,
                stderr=handle,
                start_new_session=True,
            )
            if sudo_password and process.stdin is not None:
                try:
                    process.stdin.write((sudo_password + "\n").encode("utf-8"))
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    process.stdin.close()
        finally:
            handle.close()
            self._sudo_password = None
        self.manager_pid = process.pid
        if await self._wait_health():
            if log:
                log(f"Sandbox manager ready (PID {process.pid})")
            return True, "Sandbox manager started"
        tail = self._log_tail()
        if log and tail:
            log(tail)
        return False, "Sandbox manager did not become healthy"
