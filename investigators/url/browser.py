from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from intelligence.evidence import EvidenceLedger, safe_text

SUSPICIOUS_JS_TERMS = ("eval(", "new function", "atob(", "fromcharcode", "unescape(", "document.write")


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


def analyze_browser(ledger: EvidenceLedger, evidence: dict[str, Any]) -> None:
    browser = evidence.get("browser")
    if not isinstance(browser, dict):
        ledger.mark_coverage("browser", "unavailable", "Browser evidence is missing")
        ledger.add(
            source="sandbox.browser",
            category="coverage",
            title="Browser analysis unavailable",
            severity="info",
            confidence=0.9,
            description="The sandbox did not return browser evidence.",
            code="browser_unavailable",
        )
        return
    if browser.get("available") is False:
        ledger.mark_coverage("browser", "unavailable", "Browser engine was not available")
        ledger.add(
            source="sandbox.browser",
            category="coverage",
            title="Browser engine unavailable",
            severity="info",
            confidence=0.9,
            description="Rendered-page checks could not be performed.",
            data={"error": safe_text(browser.get("error", ""), 512)},
            code="browser_unavailable",
        )
        return
    warnings = browser.get("warnings") if isinstance(browser.get("warnings"), list) else []
    if warnings:
        ledger.mark_coverage("browser", "partial", safe_text(warnings[0], 256))
        for warning in warnings[:5]:
            ledger.add(
                source="sandbox.browser",
                category="coverage",
                title="Browser warning",
                severity="info",
                confidence=0.8,
                description=safe_text(warning, 512),
                code="browser_warning",
            )
    else:
        ledger.mark_coverage("browser", "ok", "Rendered-page analysis completed")

    final_url = safe_text(browser.get("final_url", ""), 4096)
    title = safe_text(browser.get("title", ""), 512)
    if final_url:
        ledger.add(
            source="sandbox.browser",
            category="page",
            title="Rendered page identified",
            severity="info",
            confidence=0.9,
            data={"final_url": final_url, "title": title},
            code="page_summary",
        )
    forms = browser.get("forms") if isinstance(browser.get("forms"), list) else []
    target = evidence.get("target") if isinstance(evidence.get("target"), dict) else {}
    target_origin = _origin(final_url or safe_text(target.get("url", ""), 4096))
    for form in forms[:20]:
        if not isinstance(form, dict):
            continue
        inputs = form.get("inputs") if isinstance(form.get("inputs"), list) else []
        input_types = {
            safe_text(item.get("type", ""), 32).lower()
            for item in inputs
            if isinstance(item, dict)
        }
        action = safe_text(form.get("action", ""), 2048)
        action_origin = _origin(action)
        if "password" in input_types:
            cross_origin = bool(action_origin[1] and target_origin[1] and action_origin != target_origin)
            if cross_origin or action.lower().startswith("javascript:"):
                ledger.add(
                    source="sandbox.browser",
                    category="credential",
                    title="Password form submits to another origin",
                    severity="high",
                    confidence=0.8,
                    description="A rendered password form sends data somewhere other than the visited origin.",
                    data={"action": action, "page": final_url, "method": safe_text(form.get("method", ""), 16)},
                    code="credential_harvesting",
                )
            else:
                ledger.add(
                    source="sandbox.browser",
                    category="credential",
                    title="Rendered page contains a password form",
                    severity="low",
                    confidence=0.55,
                    description="Password collection alone is not malicious, but should be validated against the expected service.",
                    data={"action": action, "page": final_url},
                    code="credential_form",
                )
        if action.lower().startswith("javascript:"):
            ledger.add(
                source="sandbox.browser",
                category="page",
                title="Form action uses JavaScript",
                severity="medium",
                confidence=0.7,
                description="A form submits through inline JavaScript, which can obscure the effective destination.",
                data={"action": action},
                code="javascript_form",
            )

    javascript = browser.get("javascript") if isinstance(browser.get("javascript"), dict) else {}
    risky = [name for name in ("eval_usage", "function_constructor", "atob_usage", "websocket_usage") if javascript.get(name)]
    if risky:
        ledger.add(
            source="sandbox.browser",
            category="javascript",
            title="Page uses potentially obfuscating JavaScript features",
            severity="low" if len(risky) < 2 else "medium",
            confidence=0.6,
            description="These JavaScript features appear in benign applications but are also common in obfuscated payloads.",
            data={"features": risky},
            code="suspicious_javascript",
        )
    iframe_count = 0
    try:
        iframe_count = int(javascript.get("iframe_count", 0))
    except (TypeError, ValueError):
        iframe_count = 0
    if iframe_count:
        ledger.add(
            source="sandbox.browser",
            category="page",
            title="Page embeds iframes",
            severity="low",
            confidence=0.45,
            description="Embedded frames can conceal third-party content.",
            data={"iframes": iframe_count},
            code="iframe_usage",
        )
    blocked = browser.get("blocked_requests") if isinstance(browser.get("blocked_requests"), list) else []
    if blocked:
        ledger.add(
            source="sandbox.browser",
            category="network",
            title="Browser requests were blocked by policy",
            severity="low",
            confidence=0.6,
            description="The page attempted to contact a destination rejected by sandbox policy.",
            data={"blocked": blocked[:10]},
            code="blocked_request",
        )
    page_errors = browser.get("page_errors") if isinstance(browser.get("page_errors"), list) else []
    if page_errors:
        ledger.add(
            source="sandbox.browser",
            category="page",
            title="Page generated JavaScript errors",
            severity="info",
            confidence=0.5,
            description="Script errors can indicate broken or intentionally evasive content.",
            data={"errors": page_errors[:5]},
            code="page_error",
        )
    scripts = browser.get("scripts") if isinstance(browser.get("scripts"), dict) else {}
    external_scripts = scripts.get("external") if isinstance(scripts.get("external"), list) else []
    insecure_scripts = [item for item in external_scripts if safe_text(item, 2048).lower().startswith("http://")]
    if insecure_scripts:
        ledger.add(
            source="sandbox.browser",
            category="tls",
            title="Page loads scripts over unencrypted HTTP",
            severity="medium",
            confidence=0.7,
            description="Third-party scripts over HTTP can be modified in transit.",
            data={"scripts": [safe_text(item, 2048) for item in insecure_scripts[:10]]},
            code="insecure_transport",
        )
    html_preview = safe_text(browser.get("html_preview", ""), 4096).lower()
    terms = [term for term in SUSPICIOUS_JS_TERMS if term in html_preview]
    if len(terms) >= 3:
        ledger.add(
            source="sandbox.browser",
            category="javascript",
            title="Page HTML contains multiple suspicious script patterns",
            severity="medium",
            confidence=0.6,
            description="Multiple obfuscation-related patterns were present in the captured page.",
            data={"terms": terms},
            code="suspicious_javascript",
        )
