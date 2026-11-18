from __future__ import annotations

from typing import Any

from intelligence.evidence import EvidenceLedger, safe_text

EXECUTABLE_TYPES = {"windows_executable", "elf_executable", "mach_o"}
HIGH_RISK_KEYWORDS = {
    "powershell": "PowerShell execution reference",
    "wscript.shell": "Windows Script Host execution reference",
    "cmd.exe": "Command shell execution reference",
    "frombase64string": "Base64 decoding reference",
    "eval(": "Dynamic code evaluation reference",
    "document.write": "Dynamic document injection",
    "autoopen": "Office auto-execution macro",
    "document_open": "Office document execution macro",
}
DOUBLE_EXTENSIONS = {
    ".pdf.exe",
    ".doc.exe",
    ".docx.exe",
    ".jpg.exe",
    ".png.exe",
    ".txt.exe",
    ".pdf.scr",
    ".jpg.scr",
    ".pdf.js",
}


class FileInvestigator:
    required_coverage = ("file_analysis",)

    def analyze(self, ledger: EvidenceLedger, evidence: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(evidence, dict):
            ledger.mark_coverage("file_analysis", "failed", "File evidence was malformed")
            ledger.add(
                source="file.analysis",
                category="coverage",
                title="File evidence was malformed",
                severity="high",
                confidence=0.9,
                code="malformed_result",
            )
            return {"analyzed": False, "reason": "malformed_evidence"}
        if safe_text(evidence.get("kind", ""), 32) not in {"", "file"}:
            ledger.mark_coverage("file_analysis", "failed", "Unexpected evidence type")
            ledger.add(
                source="file.analysis",
                category="coverage",
                title="Unexpected evidence type",
                severity="high",
                confidence=0.9,
                data={"kind": safe_text(evidence.get("kind", ""), 32)},
                code="malformed_result",
            )
            return {"analyzed": False, "reason": "unexpected_kind"}
        static = evidence.get("file")
        if not isinstance(static, dict):
            ledger.mark_coverage("file_analysis", "failed", "Static file analysis is missing")
            ledger.warn("Sandbox returned no static file analysis")
            return {"analyzed": False, "reason": "missing_file_evidence"}
        ledger.mark_coverage("file_analysis", "ok", "Static file inspection completed")

        filename = safe_text(static.get("filename", ""), 255)
        file_type = safe_text(static.get("file_type", ""), 64)
        size = static.get("size")
        hashes = static.get("hashes") if isinstance(static.get("hashes"), dict) else {}
        entropy = static.get("entropy")
        ledger.add(
            source="sandbox.file",
            category="metadata",
            title="File metadata summarized",
            severity="info",
            confidence=1.0,
            data={
                "filename": filename,
                "size": size,
                "file_type": file_type,
                "entropy": entropy,
                "hashes": hashes,
            },
            code="file_metadata",
        )
        lower_name = filename.lower()
        if any(lower_name.endswith(extension) for extension in DOUBLE_EXTENSIONS):
            ledger.add(
                source="file.analysis",
                category="filename",
                title="File uses a deceptive double extension",
                severity="high",
                confidence=0.85,
                description="Double extensions are commonly used to disguise executable content.",
                data={"filename": filename},
                code="double_extension",
            )
        if file_type in EXECUTABLE_TYPES:
            ledger.add(
                source="sandbox.file",
                category="executable",
                title="File is an executable binary",
                severity="medium",
                confidence=0.8,
                description="Executable content is expected only when the sender or context justifies it.",
                data={
                    "file_type": file_type,
                    "executable": static.get("executable"),
                    "size": size,
                    "hashes": hashes,
                },
                code="executable_content",
            )
        try:
            entropy_value = float(entropy)
        except (TypeError, ValueError):
            entropy_value = 0.0
        if entropy_value >= 7.2 and file_type in EXECUTABLE_TYPES | {"zip", "ole_compound"}:
            ledger.add(
                source="file.analysis",
                category="obfuscation",
                title="File has very high entropy",
                severity="medium",
                confidence=0.65,
                description="High entropy can indicate compression or encryption, but is not proof of maliciousness.",
                data={"entropy": entropy_value, "file_type": file_type},
                code="high_entropy",
            )
        indicators = static.get("indicators") if isinstance(static.get("indicators"), list) else []
        indicator_set = {safe_text(item, 128) for item in indicators}
        if "script_content" in indicator_set:
            ledger.add(
                source="file.analysis",
                category="script",
                title="File contains script content",
                severity="low",
                confidence=0.7,
                description="Scripts can be benign, but should be reviewed before execution.",
                data={"filename": filename},
                code="script_content",
            )
        if "pdf_active_content" in indicator_set:
            ledger.add(
                source="file.analysis",
                category="document",
                title="PDF contains active content",
                severity="medium",
                confidence=0.75,
                description="Active PDF features can execute actions or contact remote resources.",
                data={"filename": filename},
                code="pdf_active_content",
            )
        if "office_macro_indicator" in indicator_set:
            ledger.add(
                source="file.analysis",
                category="document",
                title="Office document contains macro indicators",
                severity="high",
                confidence=0.75,
                description="Macros are a common malware delivery mechanism.",
                data={"filename": filename},
                code="office_macro_indicator",
            )
        lower_strings = {
            safe_text(item, 512).lower()
            for item in (static.get("strings") if isinstance(static.get("strings"), list) else [])
        }
        combined_strings = "\n".join(lower_strings)
        keyword_hits = [
            label
            for keyword, label in HIGH_RISK_KEYWORDS.items()
            if keyword in combined_strings
        ]
        if keyword_hits:
            severity = "high" if len(keyword_hits) >= 3 else "medium" if len(keyword_hits) >= 2 else "low"
            ledger.add(
                source="file.analysis",
                category="strings",
                title="File contains execution-related strings",
                severity=severity,
                confidence=0.65,
                description="Execution-related strings are suspicious in documents and data files, but can be legitimate in software.",
                data={"signals": keyword_hits[:10]},
                code="suspicious_keyword",
            )
        archive = static.get("archive") if isinstance(static.get("archive"), dict) else None
        if archive is not None:
            entries = archive.get("entries") if isinstance(archive.get("entries"), list) else []
            traversal = [entry for entry in entries if isinstance(entry, dict) and entry.get("path_traversal")]
            encrypted = [entry for entry in entries if isinstance(entry, dict) and entry.get("encrypted")]
            if traversal:
                ledger.add(
                    source="file.analysis",
                    category="archive",
                    title="Archive contains path traversal entries",
                    severity="high",
                    confidence=0.9,
                    description="Archive entries attempting to escape extraction directories are unsafe.",
                    data={"entries": [safe_text(entry.get("name", ""), 255) for entry in traversal[:10]]},
                    code="path_traversal",
                )
            if encrypted:
                ledger.add(
                    source="file.analysis",
                    category="archive",
                    title="Archive contains encrypted entries",
                    severity="medium",
                    confidence=0.6,
                    description="Encrypted archive contents cannot be inspected and can conceal malware.",
                    data={"encrypted_entries": len(encrypted)},
                    code="encrypted_archive",
                )
        urls = static.get("urls") if isinstance(static.get("urls"), list) else []
        ips = static.get("ip_addresses") if isinstance(static.get("ip_addresses"), list) else []
        if urls:
            ledger.add(
                source="file.analysis",
                category="network",
                title="File embeds URLs",
                severity="low",
                confidence=0.55,
                description="Embedded URLs may indicate network behavior or lure content.",
                data={"urls": [safe_text(item, 2048) for item in urls[:20]]},
                code="embedded_urls",
            )
        if ips:
            ledger.add(
                source="file.analysis",
                category="network",
                title="File embeds IP addresses",
                severity="low",
                confidence=0.5,
                description="Embedded IP addresses may indicate command-and-control or staging infrastructure.",
                data={"addresses": [safe_text(item, 64) for item in ips[:20]]},
                code="embedded_ip_addresses",
            )
        media = static.get("media") if isinstance(static.get("media"), dict) else {}
        media_warnings = media.get("warnings") if isinstance(media.get("warnings"), list) else []
        for warning in media_warnings[:5]:
            ledger.warn(safe_text(warning, 512))
        if static.get("executed"):
            ledger.add(
                source="file.analysis",
                category="execution",
                title="File was executed",
                severity="critical",
                confidence=0.95,
                description="The worker reported executing the submitted file, which violates sandbox policy.",
                code="unexpected_execution",
            )
        for warning in evidence.get("warnings", [])[:10] if isinstance(evidence.get("warnings"), list) else []:
            ledger.warn(safe_text(warning, 512))
        return {
            "analyzed": True,
            "filename": filename,
            "file_type": file_type,
            "indicators": sorted(indicator_set),
            "coverage": {"file_analysis": ledger.coverage_status("file_analysis")},
            "evidence_count": len(ledger.items),
        }
