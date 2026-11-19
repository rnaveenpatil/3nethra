from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from intelligence.evidence import EvidenceLedger, safe_text

EXECUTABLE_SUFFIXES = (
    ".exe",
    ".dll",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".jar",
    ".apk",
    ".deb",
    ".rpm",
    ".dmg",
    ".pkg",
    ".elf",
    ".bin",
)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _origin(url: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        return scheme, (parsed.hostname or "").lower(), port
    except ValueError:
        return "", "", None


def analyze_http(ledger: EvidenceLedger, evidence: dict[str, Any]) -> None:
    http = evidence.get("http")
    if not isinstance(http, dict):
        ledger.mark_coverage("http", "failed", "HTTP evidence is missing")
        ledger.warn("HTTP evidence was not available from the sandbox")
        return
    chain = http.get("redirect_chain")
    chain = [item for item in chain if isinstance(item, dict)] if isinstance(chain, list) else []
    final = http.get("final") if isinstance(http.get("final"), dict) else {}
    responded = [item for item in chain if isinstance(item.get("status"), int)]
    if responded:
        ledger.mark_coverage("http", "ok", f"{len(responded)} HTTP responses")
    elif final.get("blocked") or final.get("redirect_blocked"):
        detail = "HTTP destination was blocked by network policy"
        ledger.mark_coverage("http", "blocked", detail)
        ledger.warn(detail)
    elif final.get("resolution_failed") or final.get("error"):
        detail = "HTTP request could not be completed"
        ledger.mark_coverage("http", "failed", detail)
        ledger.warn(detail)
        error = final.get("error") if isinstance(final.get("error"), dict) else {}
        ledger.add(
            source="sandbox.http",
            category="network",
            title="HTTP request did not complete",
            severity="info",
            confidence=0.4,
            description="The HTTP probe could not reach the target; this is not evidence of malicious intent.",
            data={
                "url": safe_text(final.get("url", ""), 4096),
                "error": safe_text(error.get("message", ""), 512),
                "code": safe_text(error.get("code", ""), 128),
            },
            code="http_request_failed",
        )
    else:
        ledger.mark_coverage("http", "failed", "No HTTP response was recorded")
        ledger.warn("No HTTP response was captured")
        return

    if len(chain) > 1:
        ledger.add(
            source="sandbox.http",
            category="redirect",
            title="HTTP redirect chain observed",
            severity="low" if len(chain) <= 3 else "medium",
            confidence=0.8,
            description="The target redirected through multiple locations.",
            data={
                "hops": len(chain) - 1,
                "chain": [
                    {
                        "url": safe_text(item.get("url", ""), 2048),
                        "status": item.get("status"),
                        "location": safe_text((item.get("headers") or {}).get("location", ""), 2048)
                        if isinstance(item.get("headers"), dict)
                        else "",
                    }
                    for item in chain[:10]
                ],
            },
            code="suspicious_redirect" if len(chain) > 2 else "redirect_chain",
        )
    for item in chain:
        status = item.get("status")
        headers = item.get("headers") if isinstance(item.get("headers"), dict) else {}
        location = safe_text(headers.get("location", ""), 2048)
        current = safe_text(item.get("url", ""), 4096)
        ledger.add(
            source="sandbox.http",
            category="network",
            title=f"HTTP network response: {current}",
            severity="info",
            confidence=0.9,
            data={
                "url": current,
                "host": safe_text(item.get("host", ""), 255),
                "port": item.get("port"),
                "addresses": item.get("addresses"),
                "status": status,
                "reason": safe_text(item.get("reason", ""), 128),
                "content_type": safe_text(item.get("content_type", ""), 256),
                "content_length": item.get("content_length"),
                "body_size": item.get("body_size"),
                "body_truncated": item.get("body_truncated"),
                "location": location,
                "error": safe_text(item.get("error", ""), 512) if item.get("error") else "",
            },
            code="http_network_response",
        )
        if location:
            target_host = _host(location)
            current_host = _host(current)
            if target_host and current_host and target_host != current_host:
                ledger.add(
                    source="sandbox.http",
                    category="redirect",
                    title="Redirect crosses to a different host",
                    severity="low",
                    confidence=0.65,
                    description="Cross-host redirects are common, but can also move users to attacker-controlled infrastructure.",
                    data={"from": current_host, "to": target_host, "status": status},
                    code="cross_host_redirect",
                )
            try:
                parsed_location = urlsplit(location)
            except ValueError:
                parsed_location = None
            if parsed_location is not None and parsed_location.username:
                ledger.add(
                    source="sandbox.http",
                    category="credential",
                    title="Redirect contains embedded credentials",
                    severity="high",
                    confidence=0.85,
                    description="A redirect URL embeds user information that may be used for deception.",
                    data={"location_host": target_host},
                    code="embedded_credentials",
                )
            if target_host:
                try:
                    ipaddress.ip_address(target_host)
                    is_ip = True
                except ValueError:
                    is_ip = False
                if is_ip:
                    ledger.add(
                        source="sandbox.http",
                        category="redirect",
                        title="Redirect targets a raw IP address",
                        severity="medium",
                        confidence=0.7,
                        description="Redirecting to a raw IP can bypass domain reputation controls.",
                        data={"from": current_host, "to": target_host},
                        code="redirect_to_ip",
                    )
        tls = item.get("tls") if isinstance(item.get("tls"), dict) else {}
        if safe_text(item.get("url", ""), 4096).lower().startswith("https://") and tls.get("verified") is False:
            ledger.add(
                source="sandbox.http",
                category="tls",
                title="TLS certificate verification failed",
                severity="medium",
                confidence=0.8,
                description="The HTTPS endpoint presented a certificate that failed normal verification.",
                data={
                    "host": safe_text(item.get("host", ""), 255),
                    "error": safe_text(tls.get("verification_error") or tls.get("error") or tls.get("certificate_error"), 512),
                    "issuer": safe_text(tls.get("issuer", ""), 512),
                    "not_after": safe_text(tls.get("not_after", ""), 64),
                },
                code="tls_verification_failed",
            )
        if isinstance(status, int) and 400 <= status <= 599:
            ledger.add(
                source="sandbox.http",
                category="http",
                title="Server returned an HTTP error status",
                severity="low",
                confidence=0.6,
                description="Error responses can indicate dead infrastructure or access filtering.",
                data={"url": current, "status": status, "reason": safe_text(item.get("reason", ""), 128)},
                code="http_error_status",
            )

    final_url = safe_text(final.get("url", ""), 4096)
    if final_url.lower().startswith("http://"):
        ledger.add(
            source="sandbox.http",
            category="tls",
            title="Final page uses unencrypted HTTP",
            severity="medium",
            confidence=0.75,
            description="Traffic to the final destination is not protected by TLS.",
            data={"url": final_url},
            code="insecure_transport",
        )
    if final.get("redirect_blocked"):
        ledger.add(
            source="sandbox.http",
            category="redirect",
            title="Redirect was blocked by sandbox policy",
            severity="medium",
            confidence=0.85,
            description="A redirect attempted to reach a destination rejected by network policy.",
            data={"url": safe_text(final.get("url", ""), 4096)},
            code="blocked_request",
        )
    if final.get("blocked"):
        error = final.get("error") if isinstance(final.get("error"), dict) else {}
        ledger.add(
            source="sandbox.http",
            category="network",
            title="Final HTTP destination was blocked",
            severity="medium",
            confidence=0.8,
            description="The sandbox blocked the final HTTP destination.",
            data={
                "url": safe_text(final.get("url", ""), 4096),
                "policy_code": safe_text(error.get("code", ""), 128),
                "message": safe_text(error.get("message", ""), 512),
            },
            code="blocked_request",
        )
    for download in http.get("downloads", [])[:10] if isinstance(http.get("downloads"), list) else []:
        if not isinstance(download, dict):
            continue
        name = safe_text(download.get("name", ""), 255)
        content_type = safe_text(download.get("content_type", ""), 128)
        if name.lower().endswith(EXECUTABLE_SUFFIXES) or "executable" in content_type:
            ledger.add(
                source="sandbox.http",
                category="download",
                title="URL served an executable download",
                severity="high",
                confidence=0.75,
                description="The URL made an executable file available for download.",
                data={"name": name, "content_type": content_type, "sha256": download.get("sha256")},
                code="executable_content",
            )
    ledger.add(
        source="sandbox.http",
        category="metadata",
        title="HTTP response summarized",
        severity="info",
        confidence=1.0,
        data={
            "final_url": final_url,
            "final_status": final.get("status"),
            "content_type": safe_text(final.get("content_type", ""), 256),
            "redirects": max(0, len(chain) - 1),
        },
        code="http_summary",
    )
