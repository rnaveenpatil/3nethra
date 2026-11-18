from __future__ import annotations

from types import SimpleNamespace

import pytest

from sandbox import network_policy


class FakeAnswer:
    def __init__(self, rdtype: int, addresses: list[str]) -> None:
        self.rdtype = rdtype
        self.addresses = addresses

    def __iter__(self):
        return iter([SimpleNamespace(address=address) for address in self.addresses])


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::1",
    ],
)
def test_forbidden_addresses(address: str) -> None:
    assert network_policy.is_forbidden_ip(address) is not None


@pytest.mark.parametrize("address", ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_addresses(address: str) -> None:
    assert network_policy.is_forbidden_ip(address) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://localhost/",
        "http://metadata.google.internal/",
        "http://host.docker.internal/",
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://user:pass@example.com/",
        "http://example.com:22/",
    ],
)
def test_url_rejections(url: str) -> None:
    with pytest.raises(network_policy.NetworkPolicyError):
        network_policy.validate_url(url)


def test_url_accepts_public_destination() -> None:
    validated = network_policy.validate_url("https://example.com/path?q=1")
    assert validated.host == "example.com"
    assert validated.port == 443
    assert validated.url.startswith("https://example.com/")


def test_resolution_rejects_any_private_address() -> None:
    def resolver(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "127.0.0.1"]

    with pytest.raises(network_policy.NetworkPolicyError):
        network_policy.validate_url("https://example.com/", resolve=True, resolver=resolver)


def test_resolution_accepts_only_public_addresses() -> None:
    def resolver(host: str, port: int) -> list[str]:
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    validated = network_policy.validate_url("https://example.com/", resolve=True, resolver=resolver)
    assert len(validated.addresses) == 2


def test_redirect_to_private_destination_is_blocked() -> None:
    with pytest.raises(network_policy.NetworkPolicyError):
        network_policy.validate_redirect("https://example.com/", "http://127.0.0.1/admin")


def test_relative_redirect_is_validated() -> None:
    validated = network_policy.validate_redirect("https://example.com/a/b", "../c")
    assert validated.url == "https://example.com/c"


def test_dns_answer_validation() -> None:
    dns = pytest.importorskip("dns")
    rrset = FakeAnswer(dns.rdatatype.A, ["93.184.216.34"])
    record = SimpleNamespace(answer=[rrset])
    assert network_policy.validate_dns_answer(record) == ("93.184.216.34",)


def test_dns_answer_with_private_address_is_blocked() -> None:
    dns = pytest.importorskip("dns")
    rrset = FakeAnswer(dns.rdatatype.A, ["10.0.0.5"])
    with pytest.raises(network_policy.NetworkPolicyError):
        network_policy.validate_dns_answer(SimpleNamespace(answer=[rrset]))


def test_resolver_rejects_private_upstream() -> None:
    pytest.importorskip("dns")
    with pytest.raises(network_policy.NetworkPolicyError):
        network_policy.FilteringDNSResolver(["127.0.0.1"], port=15353, upstreams=["127.0.0.1"])


def test_firewall_rules_enforce_egress_and_dns() -> None:
    pytest.importorskip("dns")
    isolation = network_policy.HostNetworkIsolation(
        session_id="abcdef1234567890",
        subnet="172.30.0.0/16",
        gateway="172.30.0.1",
        resolver_port=15353,
        dry_run=True,
    )
    filter_rules = isolation._filter_rules()
    nat_rules = isolation._nat_rules()
    flattened_filter = [" ".join(rule) for rule in filter_rules]
    flattened_nat = [" ".join(rule) for rule in nat_rules]
    assert any("--dport 80 -j ACCEPT" in rule for rule in flattened_filter)
    assert any("--dport 443 -j ACCEPT" in rule for rule in flattened_filter)
    assert any("169.254.0.0/16 -j DROP" in rule for rule in flattened_filter)
    assert any("-j DROP" in rule for rule in flattened_filter if "ACCEPT" not in rule)
    assert any("--to-destination 172.30.0.1:15353" in rule for rule in flattened_nat)
    input_rules = [" ".join(rule) for rule in isolation._input_rules()]
    assert any("--dport 15353 -j ACCEPT" in rule for rule in input_rules)
    assert any(rule.endswith("-j DROP") for rule in input_rules)
