from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from intelligence.evidence import EvidenceLedger, safe_text, safe_value

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "click",
    "link",
    "country",
    "stream",
    "download",
    "review",
    "win",
    "loan",
    "mom",
    "rest",
    "cam",
    "buzz",
}


def _target(evidence: dict[str, Any]) -> dict[str, Any]:
    target = evidence.get("target")
    return target if isinstance(target, dict) else {}


def _host(target: dict[str, Any]) -> str:
    host = safe_text(target.get("host", ""), 255).strip().lower().rstrip(".")
    if host:
        return host
    url = safe_text(target.get("url", ""), 4096)
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def analyze_dns(ledger: EvidenceLedger, evidence: dict[str, Any]) -> None:
    target = _target(evidence)
    host = _host(target)
    dns = evidence.get("dns")
    if not isinstance(dns, dict):
        ledger.mark_coverage("dns", "failed", "DNS evidence is missing")
        ledger.warn("DNS evidence was not available from the sandbox")
        return
    status = safe_text(dns.get("status", ""), 64)
    if status == "ok":
        addresses = dns.get("addresses")
        addresses = [safe_text(item, 64) for item in addresses[:20]] if isinstance(addresses, list) else []
        if addresses:
            ledger.mark_coverage("dns", "ok", f"{len(addresses)} address records")
            ledger.add(
                source="sandbox.dns",
                category="infrastructure",
                title="Host resolved to network addresses",
                severity="info",
                confidence=0.9,
                description="DNS resolution succeeded inside the isolated sandbox.",
                data={"host": host, "addresses": addresses},
                code="dns_resolved",
                untrusted=True,
            )
        else:
            ledger.mark_coverage("dns", "partial", "DNS result contained no addresses")
            ledger.warn("DNS resolution returned no addresses")
    elif status == "blocked":
        error = dns.get("error")
        code = safe_text(error.get("code", ""), 128) if isinstance(error, dict) else ""
        message = safe_text(error.get("message", ""), 512) if isinstance(error, dict) else ""
        ledger.mark_coverage("dns", "blocked", message or "DNS destination was blocked")
        ledger.add(
            source="sandbox.dns",
            category="network",
            title="Destination was blocked by network policy",
            severity="high",
            confidence=0.9,
            description="The sandbox refused the destination, which can indicate SSRF, private addressing or an unsafe scheme.",
            data={"host": host, "policy_code": code, "message": message},
            code="private_destination_blocked",
        )
    else:
        ledger.mark_coverage("dns", "failed", "DNS status was not successful")
        ledger.warn("DNS resolution did not complete")

    if not host:
        return
    if "xn--" in host:
        ledger.add(
            source="url.structure",
            category="domain",
            title="Internationalized or punycode domain",
            severity="medium",
            confidence=0.75,
            description="Punycode can be used for visually deceptive domains.",
            data={"host": host},
            code="punycode_domain",
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        ledger.add(
            source="url.structure",
            category="domain",
            title="URL uses a raw IP address",
            severity="low",
            confidence=0.6,
            description="A raw IP address is less common for legitimate public services.",
            data={"host": host, "version": address.version},
            code="ip_literal",
        )
    labels = host.split(".")
    if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
        ledger.add(
            source="url.structure",
            category="domain",
            title="Domain uses a frequently abused top-level domain",
            severity="low",
            confidence=0.55,
            description="This top-level domain appears frequently in abuse reporting, but is not inherently malicious.",
            data={"host": host, "tld": labels[-1]},
            code="suspicious_tld",
        )
    if len(host) > 60 or len(labels) > 5:
        ledger.add(
            source="url.structure",
            category="domain",
            title="Unusually long or deeply nested hostname",
            severity="low",
            confidence=0.5,
            description="Long hostnames can be used to obscure the registered domain.",
            data={"host": host, "labels": len(labels)},
            code="complex_hostname",
        )
    url = safe_text(target.get("url", ""), 4096)
    try:
        parsed = urlsplit(url)
    except ValueError:
        return
    if parsed.username or parsed.password:
        ledger.add(
            source="url.structure",
            category="credential",
            title="URL contains embedded credentials",
            severity="high",
            confidence=0.85,
            description="User information in a URL can be used to impersonate a destination or expose credentials.",
            data={"host": host},
            code="embedded_credentials",
        )
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        ledger.add(
            source="url.structure",
            category="protocol",
            title="Non-web URL scheme",
            severity="medium",
            confidence=0.8,
            description="The URL uses a scheme outside HTTP and HTTPS.",
            data={"scheme": safe_text(parsed.scheme, 32)},
            code="unexpected_scheme",
        )
    ledger.add(
        source="url.structure",
        category="metadata",
        title="URL structure summarized",
        severity="info",
        confidence=1.0,
        data=safe_value({"url": url, "host": host, "scheme": target.get("scheme"), "port": target.get("port")}),
        code="url_summary",
    )
