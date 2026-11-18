from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from sandbox import config, network_policy
from sandbox.manager import DockerSandboxRuntime

RUN = os.getenv("TRINETRA_RUN_DOCKER_TESTS") == "1"
IMAGE = os.getenv("TRINETRA_WORKER_IMAGE", "trinetra-sandbox-worker:latest")

pytestmark = pytest.mark.skipif(not RUN, reason="set TRINETRA_RUN_DOCKER_TESTS=1 to run Docker isolation tests")


def _docker_types() -> object:
    docker = pytest.importorskip("docker")
    from docker import types

    return docker, types


def test_worker_container_configuration_is_hardened(tmp_path: Path) -> None:
    docker, types = _docker_types()
    settings = replace(
        config.Settings(),
        api_token="t" * 48,
        enable_host_firewall=False,
        allow_unsafe_network=True,
        manage_orphans=False,
        evidence_root=tmp_path,
    )
    runtime = DockerSandboxRuntime(settings)
    runtime.types = types
    kwargs = runtime._worker_kwargs("a" * 32, "trinetra-test", "172.31.0.1")
    assert kwargs["read_only"] is True
    assert kwargs["privileged"] is False
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["cap_add"] == []
    assert kwargs["user"].startswith("10001:")
    assert kwargs["pids_limit"] == settings.worker_pids
    assert kwargs["mem_limit"] == settings.worker_memory_bytes
    assert kwargs["memswap_limit"] == settings.worker_memory_bytes
    assert kwargs["volumes"] == ["/work"]
    assert kwargs["devices"] == []
    assert kwargs["network"] == "trinetra-test"
    assert kwargs["dns"] == []
    assert "no-new-privileges:true" in kwargs["security_opt"]
    assert any("seccomp=" in item for item in kwargs["security_opt"])
    assert "/var/run/docker.sock" not in json.dumps(kwargs)
    assert "/var/run/docker.sock" not in json.dumps(kwargs.get("volumes", {}))
    assert docker is not None


def _require_net_admin() -> None:
    if os.geteuid() != 0:
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as handle:
                caps = next(line for line in handle if line.startswith("CapEff:"))
            if not int(caps.split()[1], 16) & (1 << 12):
                pytest.skip("CAP_NET_ADMIN is required")
        except Exception:
            pytest.skip("CAP_NET_ADMIN is required")


def _host_listener() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 0))
    listener.listen(5)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def accept_loop() -> None:
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
                connection.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return listener, port


def test_network_isolation_blocks_private_and_host_destinations(tmp_path: Path) -> None:
    _require_net_admin()
    docker, types = _docker_types()
    network_policy_module = pytest.importorskip("dns")
    assert network_policy_module is not None
    client = docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=60, version="auto")
    try:
        client.ping()
        client.images.get(IMAGE)
    except Exception as exc:
        client.close()
        pytest.skip(f"Docker worker image is not available: {exc}")
    settings = replace(
        config.Settings(),
        api_token="t" * 48,
        worker_image=IMAGE,
        enable_host_firewall=True,
        allow_unsafe_network=False,
        manage_orphans=False,
        evidence_root=tmp_path,
    )
    runtime = DockerSandboxRuntime(settings)
    runtime.client = client
    runtime.docker = docker
    runtime.types = types
    session_id = f"it{int(time.time())}"
    import asyncio

    network = None
    container = None
    isolation = None
    resolver = None
    resolver_loop = None
    resolver_thread = None
    listener = None
    try:
        network = client.networks.create(
            f"trinetra-it-{session_id}",
            driver="bridge",
            enable_ipv6=False,
            options={
                "com.docker.network.bridge.enable_icc": "false",
                "com.docker.network.bridge.enable_ip_masquerade": "true",
            },
            labels={"trinetra.sandbox.managed": "true", "trinetra.sandbox.session": session_id},
        )
        network.reload()
        ipam = network.attrs["IPAM"]["Config"][0]
        subnet = ipam["Subnet"]
        gateway = ipam["Gateway"]
        isolation = network_policy.HostNetworkIsolation(
            session_id=session_id,
            subnet=subnet,
            gateway=gateway,
            resolver_port=settings.dns_port,
        )
        isolation.install()
        resolver = network_policy.FilteringDNSResolver(
            [gateway],
            port=settings.dns_port,
            upstreams=settings.dns_upstreams,
        )
        resolver_loop = asyncio.new_event_loop()
        resolver_thread = threading.Thread(target=resolver_loop.run_forever, daemon=True)
        resolver_thread.start()
        asyncio.run_coroutine_threadsafe(resolver.start(), resolver_loop).result(10)
        listener, host_port = _host_listener()
        script = f"""
import json, socket
result = {{}}
for name, host, port in [
    ("metadata", "169.254.169.254", 80),
    ("loopback", "127.0.0.1", 22),
    ("private", "10.0.0.1", 22),
    ("host_gateway", {json.dumps(gateway)}, {host_port}),
]:
    try:
        connection = socket.create_connection((host, port), timeout=2)
        connection.close()
        result[name] = "connected"
    except Exception as exc:
        result[name] = type(exc).__name__
try:
    result["dns"] = socket.gethostbyname("example.com")
except Exception as exc:
    result["dns"] = type(exc).__name__
print(json.dumps(result))
"""
        kwargs = runtime._worker_kwargs(session_id, network.name, gateway)
        kwargs["command"] = ["python", "-c", script]
        kwargs["name"] = f"trinetra-it-worker-{session_id}"
        container = client.containers.create(**kwargs)
        container.start()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            container.reload()
            if not container.attrs["State"]["Running"]:
                break
            time.sleep(0.25)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", "replace")
        lines = [line for line in logs.strip().splitlines() if line.strip()]
        assert lines, logs
        result = json.loads(lines[-1])
        assert result["metadata"] != "connected"
        assert result["loopback"] != "connected"
        assert result["private"] != "connected"
        assert result["host_gateway"] != "connected"
        assert container.attrs["HostConfig"]["PortBindings"] in ({}, None)
        assert container.attrs["HostConfig"]["ReadonlyRootfs"] is True
    finally:
        if listener is not None:
            listener.close()
        if container is not None:
            try:
                container.remove(force=True, v=True)
            except Exception:
                pass
        if resolver is not None and resolver_loop is not None:
            try:
                asyncio.run_coroutine_threadsafe(resolver.stop(), resolver_loop).result(10)
            except Exception:
                pass
        if resolver_loop is not None:
            try:
                resolver_loop.call_soon_threadsafe(resolver_loop.stop)
            except Exception:
                pass
        if isolation is not None:
            try:
                isolation.remove()
            except Exception:
                pass
        if network is not None:
            try:
                network.remove()
            except Exception:
                pass
        client.close()
