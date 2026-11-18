from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from config.settings import Settings
from intelligence.evidence import EvidenceLedger, safe_text
from intelligence.report import InvestigationReport, build_report
from intelligence.risk_score import assess_risk
from investigators.file import FileInvestigator
from investigators.url import URLInvestigator
from investigators.video import VideoInvestigator
from storage.history import HistoryStore

from .approval import ApprovalBroker
from .planner import InvestigationPlan, Planner, PlanStep
from .reasoning import LLMError, ReasoningEngine
from .sandbox_client import SandboxClient
from .tool_manager import ToolManager, ToolResult

logger = logging.getLogger("trinetra.agent")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
UNSAFE_SAFE_CLAIM = re.compile(r"\b(safe|clean|benign|not malicious|no threat)\b", re.IGNORECASE)
UNSAFE_MALICIOUS_CLAIM = re.compile(r"\b(malicious|infected|compromised|malware)\b", re.IGNORECASE)
INVALID_URL_CHARS = re.compile(r"[\x00-\x1f\x7f\s]")
SENSITIVE_QUERY = re.compile(
    r"(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|"
    r"authorization|cookie|session|credential|signature|sig|key)",
    re.IGNORECASE,
)


class InvestigationError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InvestigationAgent:
    def __init__(
        self,
        settings: Settings,
        *,
        sandbox: SandboxClient | None = None,
        reasoning: ReasoningEngine | None = None,
        history: HistoryStore | None = None,
        url_investigator: URLInvestigator | None = None,
        file_investigator: FileInvestigator | None = None,
        video_investigator: VideoInvestigator | None = None,
    ) -> None:
        self.settings = settings
        self.sandbox = sandbox or SandboxClient(settings)
        self.reasoning = reasoning or ReasoningEngine(settings)
        self.history = history or HistoryStore(settings.history_path)
        self._owns_sandbox = sandbox is None
        self._owns_reasoning = reasoning is None
        self._closed = False
        self._history_ready = False
        self._url_investigator = url_investigator
        self._file_investigator = file_investigator
        self._video_investigator = video_investigator
        self._active_tools: ToolManager | None = None

    async def __aenter__(self) -> "InvestigationAgent":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._active_tools is not None:
            await self._active_tools.close()
            self._active_tools = None
        if self._owns_reasoning:
            await self.reasoning.close()
        if self._owns_sandbox:
            await self.sandbox.close()

    async def investigate_url(self, url: str) -> InvestigationReport:
        return await self.investigate(url, "url")

    async def investigate_file(self, path: str | Path) -> InvestigationReport:
        return await self.investigate(path, "file")

    async def investigate_video(self, path: str | Path) -> InvestigationReport:
        return await self.investigate(path, "video")

    async def investigate(self, target: str | Path, target_type: str) -> InvestigationReport:
        if target_type not in {"url", "file", "video"}:
            raise InvestigationError("target type must be url, file or video")
        validated = self._validate_target(target, target_type)
        started_at = _utc_now()
        ledger = EvidenceLedger(
            max_items=self.settings.max_evidence_items,
            text_limit=self.settings.max_text_chars,
        )
        report_target = self._display_target(validated, target_type)
        approval = ApprovalBroker(self.settings.approval_mode)
        tools = ToolManager(
            self.settings,
            target=validated,
            target_type=target_type,
            ledger=ledger,
            sandbox=self.sandbox,
            approval=approval,
            url_investigator=self._url_investigator,
            file_investigator=self._file_investigator,
            video_investigator=self._video_investigator,
        )
        self._active_tools = tools
        plan: InvestigationPlan | None = None
        status = "completed"
        fatal_error: str | None = None
        try:
            await self._ensure_history()
            planner = Planner(
                self.reasoning,
                available_tools={schema["name"] for schema in tools.schemas()},
                max_steps=self.settings.max_steps,
                max_followups=self.settings.max_followup_rounds,
            )
            planning_started = datetime.now(timezone.utc)
            plan = await planner.create_plan(
                target=report_target,
                target_type=target_type,
                tool_schemas=tools.schemas(),
            )
            ledger.add_step(
                phase="planning",
                tool="planner",
                status="ok",
                summary=f"Plan created from {plan.source}.",
                duration_ms=self._elapsed_ms(planning_started),
            )
            if plan.source == "fallback" and self.reasoning.enabled:
                ledger.warn("LLM planning failed; deterministic fallback plan was used")
            executed_keys: set[tuple[str, str]] = set()
            for step in plan.steps[: self.settings.max_steps]:
                await self._execute_step(ledger, tools, step, phase="plan", executed_keys=executed_keys)
                if self._fatal_tool_failure(tools, step.tool):
                    fatal_error = "sandbox_step_failed"
                    break
            if fatal_error is None:
                await self._followups(
                    ledger=ledger,
                    tools=tools,
                    planner=planner,
                    plan=plan,
                    target=report_target,
                    target_type=target_type,
                    executed_keys=executed_keys,
                )
        except Exception as exc:
            status = "failed"
            fatal_error = type(exc).__name__
            ledger.error("orchestrator", f"investigation aborted: {type(exc).__name__}")
            logger.exception("investigation_failed")
        finally:
            try:
                await tools.close()
            except Exception:
                ledger.warn("Tool cleanup did not complete cleanly")
            self._active_tools = None

        if status == "completed" and fatal_error is not None:
            status = "incomplete"
        required = self._required_coverage(target_type)
        for name in required:
            if name not in ledger.coverage:
                ledger.mark_coverage(name, "missing", "Required evidence was not collected")
        assessment = assess_risk(
            ledger,
            required_coverage=required,
            extra_reasons=[],
        )
        summary = await self._generate_summary(
            target=report_target,
            target_type=target_type,
            assessment=assessment,
            ledger=ledger,
        )
        if fatal_error is not None:
            ledger.warn(f"Investigation did not complete normally: {fatal_error}")
        report = build_report(
            target=report_target,
            target_type=target_type,
            started_at=started_at,
            assessment=assessment,
            ledger=ledger,
            summary=summary,
            status=status,
            sandbox_sessions=list(tools.session_ids),
            metadata={
                "engine": "trinetra-agent",
                "plan_source": plan.source if plan else None,
                "plan": plan.to_dict() if plan else None,
                "llm_enabled": self.reasoning.enabled,
                "llm_model": self.settings.llm_model if self.reasoning.enabled else None,
                "approvals": approval.history,
                "tool_results": {
                    name: result.to_dict()
                    for name, result in tools.last_results.items()
                },
                "fatal_error": fatal_error,
            },
        )
        try:
            await self.history.save(report)
        except Exception as exc:
            ledger.warn("Report could not be written to history")
            report = build_report(
                target=report_target,
                target_type=target_type,
                started_at=started_at,
                assessment=assessment,
                ledger=ledger,
                summary=summary,
                status=status,
                sandbox_sessions=list(tools.session_ids),
                metadata={
                    "engine": "trinetra-agent",
                    "history_error": type(exc).__name__,
                    "plan_source": plan.source if plan else None,
                    "llm_enabled": self.reasoning.enabled,
                    "fatal_error": fatal_error,
                },
            )
        return report

    async def _execute_step(
        self,
        ledger: EvidenceLedger,
        tools: ToolManager,
        step: PlanStep,
        *,
        phase: str,
        executed_keys: set[tuple[str, str]],
    ) -> ToolResult:
        key = (step.tool, self._args_key(step.arguments))
        if key in executed_keys:
            return ToolResult(False, "Duplicate step was skipped.", error_code="duplicate_step")
        executed_keys.add(key)
        started = datetime.now(timezone.utc)
        result = await tools.execute(step.tool, step.arguments)
        ledger.add_step(
            phase=phase,
            tool=step.tool,
            status="ok" if result.ok else "failed",
            summary=result.summary,
            duration_ms=self._elapsed_ms(started),
            error=result.error_code,
        )
        return result

    async def _followups(
        self,
        *,
        ledger: EvidenceLedger,
        tools: ToolManager,
        planner: Planner,
        plan: InvestigationPlan,
        target: str,
        target_type: str,
        executed_keys: set[tuple[str, str]],
    ) -> None:
        if self.settings.max_followup_rounds < 1 or not self.reasoning.enabled:
            return
        if not any(tool.startswith("analyze_") for tool in tools.completed_tools):
            return
        completed = list(tools.completed_tools)
        for round_index in range(self.settings.max_followup_rounds):
            actions = await planner.follow_up(
                target=target,
                target_type=target_type,
                evidence=ledger.llm_summary(),
                completed_tools=completed,
                tool_schemas=tools.schemas(),
            )
            if not actions:
                break
            for step in actions:
                result = await self._execute_step(
                    ledger,
                    tools,
                    step,
                    phase=f"followup_{round_index + 1}",
                    executed_keys=executed_keys,
                )
                if result.ok:
                    completed.append(step.tool)
                if self._fatal_tool_failure(tools, step.tool):
                    return
            if len(executed_keys) >= self.settings.max_steps + self.settings.max_followup_rounds:
                break

    def _fatal_tool_failure(self, tools: ToolManager, tool: str) -> bool:
        if not tool.startswith("sandbox_"):
            return False
        result = tools.last_results.get(tool)
        if result is None:
            return True
        return not result.ok

    def _required_coverage(self, target_type: str) -> list[str]:
        if target_type == "url":
            return list(URLInvestigator.required_coverage)
        if target_type == "video":
            return list(VideoInvestigator.required_coverage)
        return list(FileInvestigator.required_coverage)

    async def _generate_summary(
        self,
        *,
        target: str,
        target_type: str,
        assessment: Any,
        ledger: EvidenceLedger,
    ) -> str | None:
        if not self.reasoning.enabled:
            return None
        try:
            raw = await self.reasoning.narrate(
                target=target,
                target_type=target_type,
                verdict=assessment.verdict,
                risk_score=assessment.score,
                confidence=assessment.confidence,
                evidence=ledger.llm_summary(),
                deterministic_reasons=list(assessment.reasons),
            )
        except (LLMError, ValueError, TypeError) as exc:
            logger.info("summary_llm_failed", extra={"error_type": type(exc).__name__})
            return None
        summary = raw.get("summary")
        if not isinstance(summary, str):
            return None
        summary = CONTROL_CHARS.sub("", summary).strip()
        if not summary or len(summary) > 6000:
            return None
        if assessment.verdict == "MALICIOUS" and UNSAFE_SAFE_CLAIM.search(summary):
            return None
        if assessment.verdict == "SAFE" and UNSAFE_MALICIOUS_CLAIM.search(summary):
            return None
        if assessment.verdict == "INCONCLUSIVE" and re.search(r"\bis safe\b", summary, re.IGNORECASE):
            return None
        if assessment.verdict == "SUSPICIOUS" and re.search(r"\b(is safe|not malicious|no threat)\b", summary, re.IGNORECASE):
            return None
        return safe_text(summary, 6000)

    async def _ensure_history(self) -> None:
        if self._history_ready:
            return
        await self.history.initialize()
        self._history_ready = True

    def _validate_target(self, target: str | Path, target_type: str) -> str:
        if target_type == "url":
            value = str(target).strip()
            if not value or len(value) > 4096 or INVALID_URL_CHARS.search(value):
                raise InvestigationError("invalid URL")
            try:
                parsed = urlsplit(value)
            except ValueError as exc:
                raise InvestigationError("invalid URL") from exc
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise InvestigationError("URL must use http or https and include a host")
            try:
                parsed.port
            except ValueError as exc:
                raise InvestigationError("URL contains an invalid port") from exc
            return value
        path = Path(target).expanduser()
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            raise InvestigationError("file does not exist") from exc
        if path.is_symlink() or not path.is_file():
            raise InvestigationError("file must be a regular file")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise InvestigationError("file is not readable") from exc
        if size <= 0:
            raise InvestigationError("file is empty")
        if size > self.settings.max_file_bytes:
            raise InvestigationError("file exceeds the configured size limit")
        return str(path)

    def _display_target(self, target: str, target_type: str) -> str:
        if target_type != "url":
            return target
        try:
            parsed = urlsplit(target)
        except ValueError:
            return target
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        if parsed.username:
            host = f"{parsed.username}:[REDACTED]@{host}"
        try:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            query = urlencode(
                [
                    (key, "[REDACTED]" if SENSITIVE_QUERY.search(key) else value)
                    for key, value in query_pairs
                ],
                doseq=True,
            )
        except ValueError:
            query = parsed.query
        return urlunsplit((parsed.scheme, host, parsed.path, query, parsed.fragment))

    @staticmethod
    def _args_key(arguments: dict[str, Any]) -> str:
        try:
            import json

            return hashlib.sha256(
                json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            ).hexdigest()
        except Exception:
            return repr(arguments)

    @staticmethod
    def _elapsed_ms(started: datetime) -> int:
        return max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
