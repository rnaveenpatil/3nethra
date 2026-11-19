from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

try:
    import dns.asyncresolver
    import dns.exception
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
except Exception:
    dns = None


FORBIDDEN_V4: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "non-routable"),
    ("10.0.0.0/8", "private network"),
    ("100.64.0.0/10", "carrier-grade NAT"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local or cloud metadata"),
    ("172.16.0.0/12", "private network"),
    ("192.0.0.0/24", "reserved network"),
    ("192.0.2.0/24", "documentation network"),
    ("192.88.99.0/24", "6to4 relay network"),
    ("192.168.0.0/16", "private network"),
    ("198.18.0.0/15", "benchmarking network"),
    ("198.51.100.0/24", "documentation network"),
    ("203.0.113.0/24", "documentation network"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved network"),
    ("255.255.255.255/32", "broadcast"),
)

FORBIDDEN_V6: tuple[tuple[str, str], ...] = (
    ("::/96", "IPv4-compatible IPv6"),
    ("::1/128", "loopback"),
    ("::ffff:0:0/96", "IPv4-mapped IPv6"),
    ("64:ff9b::/96", "NAT64 IPv4 translation"),
    ("64:ff9b:1::/48", "local NAT64 IPv4 translation"),
    ("100::/64", "discard network"),
    ("2001::/32", "Teredo tunnel"),
    ("2001:20::/28", "ORCHIDv2"),
    ("2001:db8::/32", "documentation network"),
    ("2002::/16", "6to4 tunnel"),
    ("fc00::/7", "unique local address"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast"),
)

CLOUD_METADATA_ADDRESSES = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
}

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.for.mac.host.internal",
    "docker.for.win.localhost",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
}

FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".home",
    ".home.arpa",
    ".corp",
    ".invalid",
    ".test",
    ".example",
    ".svc",
    ".cluster.local",
)

FORBIDDEN_NETWORKS_V4 = tuple((ipaddress.ip_network(network), reason) for network, reason in FORBIDDEN_V4)
FORBIDDEN_NETWORKS_V6 = tuple((ipaddress.ip_network(network), reason) for network, reason in FORBIDDEN_V6)

HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NetworkPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(value)


def is_forbidden_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    try:
        address = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else _parse_ip(str(value))
    except ValueError:
        return "invalid address"
    text = str(address)
    if text in CLOUD_METADATA_ADDRESSES:
        return "cloud metadata endpoint"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return "IPv4-mapped IPv6 address"
    networks = FORBIDDEN_NETWORKS_V4 if isinstance(address, ipaddress.IPv4Address) else FORBIDDEN_NETWORKS_V6
    for network, reason in networks:
        if address.version == network.version and address in network:
            return reason
    if address.is_unspecified:
        return "unspecified address"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved address"
    if address.is_private:
        return "private address"
    if not address.is_global:
        return "not globally routable"
    return None


def validate_resolved_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in addresses:
        try:
            address = _parse_ip(str(raw))
        except ValueError as exc:
            raise NetworkPolicyError("invalid_dns_answer", "DNS returned an invalid address") from exc
        reason = is_forbidden_ip(address)
        if reason is not None:
            raise NetworkPolicyError("forbidden_destination", f"DNS resolution points to a forbidden destination: {reason}")
        text = str(address)
        if text not in seen:
            seen.add(text)
            normalized.append(text)
    if not normalized:
        raise NetworkPolicyError("dns_failure", "DNS resolution returned no addresses")
    return tuple(normalized)


def validate_hostname(host: str) -> str:
    if not isinstance(host, str):
        raise NetworkPolicyError("invalid_url", "Host is not a string")
    host = host.strip().lower().rstrip(".")
    if not host or len(host) > 253:
        raise NetworkPolicyError("invalid_url", "Host is invalid")
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) == 127 for ch in host):
        raise NetworkPolicyError("invalid_url", "Host contains invalid characters")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetworkPolicyError("invalid_url", "Host cannot be encoded") from exc
    if ascii_host in FORBIDDEN_HOSTNAMES:
        raise NetworkPolicyError("forbidden_hostname", "Hostname is not allowed")
    if any(ascii_host.endswith(suffix) for suffix in FORBIDDEN_HOST_SUFFIXES):
        raise NetworkPolicyError("forbidden_hostname", "Hostname suffix is not allowed")
    if "." not in ascii_host:
        raise NetworkPolicyError("forbidden_hostname", "Single-label hostnames are not allowed")
    labels = ascii_host.split(".")
    if any(not label or not HOSTNAME_LABEL_RE.fullmatch(label) for label in labels):
        raise NetworkPolicyError("invalid_url", "Hostname label is invalid")
    return ascii_host


def _resolve_sync(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise NetworkPolicyError("dns_failure", "DNS resolution failed") from exc
    addresses = [info[4][0] for info in infos]
    return validate_resolved_addresses(addresses)


def validate_url(
    url: str,
    *,
    resolve: bool = False,
    allow_ports: Sequence[int] = (80, 443),
    max_length: int = 4096,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> ValidatedURL:
    if not isinstance(url, str):
        raise NetworkPolicyError("invalid_url", "URL is not a string")
    if not url or len(url) > max_length:
        raise NetworkPolicyError("invalid_url", "URL length is invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in url):
        raise NetworkPolicyError("invalid_url", "URL contains whitespace or control characters")
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise NetworkPolicyError("invalid_url", "URL cannot be parsed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise NetworkPolicyError("invalid_scheme", "Only HTTP and HTTPS URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkPolicyError("invalid_url", "URLs containing credentials are not allowed")
    host = parsed.hostname
    if not host:
        raise NetworkPolicyError("invalid_url", "URL has no host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkPolicyError("invalid_url", "URL port is invalid") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in allow_ports:
        raise NetworkPolicyError("forbidden_port", "Destination port is not allowed")
    addresses: tuple[str, ...] = ()
    ip_literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip_literal = _parse_ip(host)
    except ValueError:
        ip_literal = None
    if ip_literal is not None:
        reason = is_forbidden_ip(ip_literal)
        if reason is not None:
            raise NetworkPolicyError("forbidden_destination", f"Destination address is not allowed: {reason}")
        addresses = (str(ip_literal),)
        normalized_host = str(ip_literal)
    else:
        normalized_host = validate_hostname(host)
        if resolve:
            if resolver is not None:
                addresses = validate_resolved_addresses(resolver(normalized_host, port))
            else:
                addresses = _resolve_sync(normalized_host, port)
    netloc = normalized_host
    if ":" in normalized_host and not normalized_host.startswith("["):
        netloc = f"[{normalized_host}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    normalized_url = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return ValidatedURL(normalized_url, scheme, normalized_host, port, addresses)


async def resolve_and_validate_host(host: str, port: int) -> tuple[str, ...]:
    return await asyncio.to_thread(_resolve_sync, host, port)


async def resolve_and_validate_url(url: str, **kwargs: Any) -> ValidatedURL:
    validated = validate_url(url, resolve=False, **kwargs)
    if validated.addresses:
        return validated
    addresses = await resolve_and_validate_host(validated.host, validated.port)
    return ValidatedURL(validated.url, validated.scheme, validated.host, validated.port, addresses)


def validate_redirect(base_url: str, location: str, **kwargs: Any) -> ValidatedURL:
    if not isinstance(location, str) or not location or len(location) > 4096:
        raise NetworkPolicyError("invalid_redirect", "Redirect target is invalid")
    target = urllib.parse.urljoin(base_url, location)
    return validate_url(target, **kwargs)


def _answer_rrsets(record: Any) -> Iterable[Any]:
    response = getattr(record, "response", None)
    rrsets = getattr(response, "answer", None)
    if rrsets:
        return rrsets
    return getattr(record, "answer", None) or []


def extract_dns_addresses(record: Any) -> tuple[str, ...]:
    addresses: list[str] = []
    for part in _answer_rrsets(record):
        rdtype = getattr(part, "rdtype", None)
        if rdtype not in {dns.rdatatype.A if dns else 1, dns.rdatatype.AAAA if dns else 28}:
            continue
        for item in part:
            addresses.append(str(item.address))
    return tuple(addresses)


def validate_dns_answer(record: Any) -> tuple[str, ...]:
    addresses = extract_dns_addresses(record)
    if not addresses:
        return ()
    return validate_resolved_addresses(addresses)


class FilteringDNSResolver:
    def __init__(
        self,
        bind_addresses: Sequence[str],
        *,
        port: int,
        upstreams: Sequence[str],
        max_ttl: int = 60,
        timeout: float = 5.0,
        logger: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if dns is None:
            raise RuntimeError("dnspython is required for the filtering DNS resolver")
        self.bind_addresses = tuple(bind_addresses)
        self.port = port
        self.upstreams = tuple(upstreams)
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.logger = logger
        self._servers: list[asyncio.AbstractServer] = []
        self._transports: list[asyncio.DatagramTransport] = []
        self._cache: dict[tuple[str, int], tuple[float, bytes]] = {}
        self._semaphore = asyncio.Semaphore(64)
        self._closed = False
        for upstream in self.upstreams:
            reason = is_forbidden_ip(upstream)
            if reason is not None:
                raise NetworkPolicyError("invalid_upstream", f"DNS upstream is not public: {reason}")

    def _log(self, event: str, **fields: Any) -> None:
        if self.logger is None:
            return
        try:
            self.logger({"event": event, **fields})
        except Exception:
            pass

    async def start(self) -> None:
        try:
            for address in self.bind_addresses:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: self._UDPProtocol(self),
                    local_addr=(address, self.port),
                )
                self._transports.append(transport)
                server = await asyncio.start_server(
                    self._handle_tcp_client,
                    host=address,
                    port=self.port,
                    reuse_address=True,
                )
                self._servers.append(server)
        except Exception:
            await self.stop()
            raise
        self._log("dns_started", addresses=list(self.bind_addresses), port=self.port)

    async def stop(self) -> None:
        self._closed = True
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await server.wait_closed()
            except Exception:
                pass
        for transport in self._transports:
            try:
                transport.close()
            except Exception:
                pass
        self._servers.clear()
        self._transports.clear()
        self._cache.clear()

    async def _resolve_upstream(self, name: str, rdtype: int) -> Any:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = list(self.upstreams)
        resolver.timeout = min(3.0, self.timeout)
        resolver.lifetime = self.timeout
        resolver.retry_servfail = False
        return await resolver.resolve(name, rdtype, raise_on_no_answer=False, search=False)

    async def _build_response(self, request: Any) -> Any:
        if len(request.question) != 1:
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.FORMERR)
            return response
        question = request.question[0]
        name = question.name.to_text().lower().rstrip(".")
        rdtype = question.rdtype
        response = dns.message.make_response(request)
        response.flags |= dns.flags.RA
        if rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            response.set_rcode(dns.rcode.NOTIMP)
            return response
        try:
            validate_hostname(name)
        except NetworkPolicyError:
            response.set_rcode(dns.rcode.REFUSED)
            return response
        cache_key = (name, rdtype)
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and cached[0] > now:
            try:
                response = dns.message.from_wire(cached[1])
                response.id = request.id
                return response
            except Exception:
                self._cache.pop(cache_key, None)
        try:
            upstream_response = await self._resolve_upstream(name, rdtype)
        except dns.resolver.NXDOMAIN:
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response
        except dns.resolver.NoAnswer:
            return response
        except (dns.exception.Timeout, dns.exception.DNSException):
            response.set_rcode(dns.rcode.SERVFAIL)
            return response
        try:
            validate_dns_answer(upstream_response)
        except NetworkPolicyError as exc:
            self._log("dns_blocked", name=name, rdtype=rdtype, reason=exc.message)
            response.set_rcode(dns.rcode.REFUSED)
            return response
        min_ttl = self.max_ttl
        for rrset in _answer_rrsets(upstream_response):
            copied = copy.deepcopy(rrset)
            copied.ttl = max(0, min(int(copied.ttl), self.max_ttl))
            min_ttl = min(min_ttl, copied.ttl)
            if copied.rdtype in {dns.rdatatype.CNAME, dns.rdatatype.A, dns.rdatatype.AAAA}:
                response.answer.append(copied)
        wire = response.to_wire()
        if len(self._cache) > 1024:
            self._cache.clear()
        self._cache[cache_key] = (now + max(1, min_ttl), wire)
        self._log("dns_resolved", name=name, rdtype=rdtype)
        return response

    async def _handle_udp_datagram(self, data: bytes, address: tuple[str, int], transport: asyncio.DatagramTransport) -> None:
        if self._closed or len(data) > 4096 or len(data) < 12:
            return
        async with self._semaphore:
            try:
                request = dns.message.from_wire(data)
                response = await self._build_response(request)
                wire = self._safe_wire(response, request)
                transport.sendto(wire, address)
            except Exception:
                return

    def _safe_wire(self, response: Any, request: Any) -> bytes:
        try:
            return response.to_wire(max_size=1232)
        except dns.exception.TooBig:
            response.flags |= dns.flags.TC
            response.answer.clear()
            response.authority.clear()
            response.additional.clear()
            try:
                return response.to_wire(max_size=512)
            except Exception:
                minimal = dns.message.make_response(request)
                minimal.flags |= dns.flags.TC | dns.flags.RA
                return minimal.to_wire()

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            prefix = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            length = int.from_bytes(prefix, "big")
            if length < 12 or length > 65535:
                return
            data = await asyncio.wait_for(reader.readexactly(length), timeout=5)
            async with self._semaphore:
                request = dns.message.from_wire(data)
                response = await self._build_response(request)
                wire = response.to_wire(max_size=65535)
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    class _UDPProtocol(asyncio.DatagramProtocol):
        def __init__(self, owner: "FilteringDNSResolver") -> None:
            self.owner = owner
            self.transport: asyncio.DatagramTransport | None = None

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
            if self.transport is None:
                return
            asyncio.create_task(self.owner._handle_udp_datagram(data, address, self.transport))

        def error_received(self, exc: Exception) -> None:
            return


class HostNetworkIsolation:
    def __init__(
        self,
        *,
        session_id: str,
        subnet: str,
        gateway: str,
        resolver_port: int,
        iptables_bin: str | None = None,
        enabled: bool = True,
        allow_unsafe: bool = False,
        dry_run: bool = False,
        logger: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.session_id = session_id
        token = "".join(ch for ch in session_id.lower() if ch.isalnum())[:12]
        if not token:
            token = "session"
        self.subnet = ipaddress.ip_network(subnet, strict=False)
        self.gateway = str(ipaddress.ip_address(gateway))
        self.resolver_port = resolver_port
        self.iptables = iptables_bin or shutil.which("iptables")
        self.enabled = enabled
        self.allow_unsafe = allow_unsafe
        self.dry_run = dry_run
        self.logger = logger
        self.filter_chain = f"TSB-{token}"
        self.input_chain = f"TSBI-{token}"
        self.nat_pre_chain = f"TSNP-{token}"
        self.nat_out_chain = f"TSNO-{token}"
        self.comment = f"trinetra:{token}"
        self.commands: list[list[str]] = []
        self._installed = False

    def _log(self, event: str, **fields: Any) -> None:
        if self.logger is None:
            return
        try:
            self.logger({"event": event, **fields})
        except Exception:
            pass

    def _run(self, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes] | None:
        command = [self.iptables or "iptables", "-w", "5", *args]
        self.commands.append(command)
        if self.dry_run:
            return None
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if check and result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace")[:512]
            raise NetworkPolicyError("firewall_failure", f"iptables command failed: {message}")
        return result

    @staticmethod
    def _has_net_admin() -> bool:
        if os.geteuid() == 0:
            return True
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("CapEff:"):
                        mask = int(line.split()[1], 16)
                        return bool(mask & (1 << 12))
        except Exception:
            return False
        return False

    def verify(self) -> None:
        if not self.enabled:
            if not self.allow_unsafe:
                raise NetworkPolicyError("firewall_disabled", "Host network firewall is disabled")
            self._log("firewall_unsafe", session_id=self.session_id)
            return
        if self.dry_run:
            return
        if not self.iptables:
            raise NetworkPolicyError("firewall_unavailable", "iptables is required")
        if not self._has_net_admin():
            raise NetworkPolicyError("firewall_privileges", "CAP_NET_ADMIN is required for network isolation")
        self._run(["-L", "DOCKER-USER", "-n"], check=True)
        self._run(["-t", "nat", "-L", "OUTPUT", "-n"], check=True)

    def _filter_rules(self) -> list[list[str]]:
        rules: list[list[str]] = [["-N", self.filter_chain]]
        rules.append(["-A", self.filter_chain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        for network, _reason in FORBIDDEN_NETWORKS_V4:
            rules.append(["-A", self.filter_chain, "-d", str(network), "-j", "DROP"])
        rules.append(["-A", self.filter_chain, "-p", "tcp", "--dport", "80", "-j", "ACCEPT"])
        rules.append(["-A", self.filter_chain, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"])
        rules.append(["-A", self.filter_chain, "-j", "DROP"])
        return rules

    def _input_rules(self) -> list[list[str]]:
        return [
            ["-N", self.input_chain],
            ["-A", self.input_chain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["-A", self.input_chain, "-p", "udp", "--dport", str(self.resolver_port), "-j", "ACCEPT"],
            ["-A", self.input_chain, "-p", "tcp", "--dport", str(self.resolver_port), "-j", "ACCEPT"],
            ["-A", self.input_chain, "-j", "DROP"],
        ]

    def _nat_rules(self) -> list[list[str]]:
        return [
            ["-t", "nat", "-N", self.nat_pre_chain],
            [
                "-t", "nat", "-A", self.nat_pre_chain, "-s", str(self.subnet), "-d", self.gateway,
                "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{self.gateway}:{self.resolver_port}",
            ],
            [
                "-t", "nat", "-A", self.nat_pre_chain, "-s", str(self.subnet), "-d", self.gateway,
                "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{self.gateway}:{self.resolver_port}",
            ],
            ["-t", "nat", "-A", self.nat_pre_chain, "-j", "RETURN"],
            ["-t", "nat", "-N", self.nat_out_chain],
            [
                "-t", "nat", "-A", self.nat_out_chain, "-d", self.gateway,
                "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{self.gateway}:{self.resolver_port}",
            ],
            [
                "-t", "nat", "-A", self.nat_out_chain, "-d", self.gateway,
                "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{self.gateway}:{self.resolver_port}",
            ],
            ["-t", "nat", "-A", self.nat_out_chain, "-j", "RETURN"],
        ]

    def install(self) -> None:
        self.verify()
        if not self.enabled:
            self._installed = True
            return
        try:
            for rule in self._filter_rules():
                self._run(rule)
            for rule in self._input_rules():
                self._run(rule)
            for rule in self._nat_rules():
                self._run(rule)
            self._run([
                "-I", "DOCKER-USER", "1", "-s", str(self.subnet),
                "-m", "comment", "--comment", self.comment, "-j", self.filter_chain,
            ])
            self._run([
                "-I", "DOCKER-USER", "1", "-d", str(self.subnet),
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "comment", "--comment", self.comment, "-j", "DROP",
            ])
            self._run([
                "-I", "INPUT", "1", "-s", str(self.subnet),
                "-m", "comment", "--comment", self.comment, "-j", self.input_chain,
            ])
            self._run([
                "-t", "nat", "-I", "PREROUTING", "1", "-s", str(self.subnet),
                "-m", "comment", "--comment", self.comment, "-j", self.nat_pre_chain,
            ])
            self._run([
                "-t", "nat", "-I", "OUTPUT", "1", "-d", self.gateway,
                "-m", "comment", "--comment", self.comment, "-j", self.nat_out_chain,
            ])
            self._installed = True
            self._log("firewall_installed", session_id=self.session_id, subnet=str(self.subnet), gateway=self.gateway)
        except Exception:
            self.remove()
            raise

    def remove(self) -> None:
        if self.dry_run:
            self._installed = False
            return
        if not self.iptables:
            return
        deletions = [
            ["-D", "DOCKER-USER", "-s", str(self.subnet), "-m", "comment", "--comment", self.comment, "-j", self.filter_chain],
            ["-D", "DOCKER-USER", "-d", str(self.subnet), "-m", "conntrack", "--ctstate", "NEW", "-m", "comment", "--comment", self.comment, "-j", "DROP"],
            ["-D", "INPUT", "-s", str(self.subnet), "-m", "comment", "--comment", self.comment, "-j", self.input_chain],
            ["-t", "nat", "-D", "PREROUTING", "-s", str(self.subnet), "-m", "comment", "--comment", self.comment, "-j", self.nat_pre_chain],
            ["-t", "nat", "-D", "OUTPUT", "-d", self.gateway, "-m", "comment", "--comment", self.comment, "-j", self.nat_out_chain],
        ]
        for rule in deletions:
            try:
                self._run(rule, check=False)
            except Exception:
                pass
        for args in (
            ["-F", self.filter_chain],
            ["-X", self.filter_chain],
            ["-F", self.input_chain],
            ["-X", self.input_chain],
            ["-t", "nat", "-F", self.nat_pre_chain],
            ["-t", "nat", "-X", self.nat_pre_chain],
            ["-t", "nat", "-F", self.nat_out_chain],
            ["-t", "nat", "-X", self.nat_out_chain],
        ):
            try:
                self._run(args, check=False)
            except Exception:
                pass
        self._installed = False
        self._log("firewall_removed", session_id=self.session_id)
