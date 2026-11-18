from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable

from .reasoning import LLMError, ReasoningEngine

logger = logging.getLogger("trinetra.planner")


@dataclass
class PlanStep:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "arguments": dict(self.arguments), "reason": self.reason}


@dataclass
class InvestigationPlan:
    goal: str
    steps: list[PlanStep]
    source: str = "fallback"

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "source": self.source,
            "steps": [step.to_dict() for step in self.steps],
        }

    @property
    def tools(self) -> list[str]:
        return [step.tool for step in self.steps]


class Planner:
    def __init__(
        self,
        reasoning: ReasoningEngine,
        *,
        available_tools: Iterable[str],
        max_steps: int,
        max_followups: int,
    ) -> None:
        self.reasoning = reasoning
        self.available_tools = set(available_tools)
        self.max_steps = max(1, max_steps)
        self.max_followups = max(0, max_followups)

    def fallback(self, target_type: str) -> InvestigationPlan:
        if target_type == "url":
            steps = [
                PlanStep(
                    tool="sandbox_url_investigation",
                    arguments={
                        "analyze_media": True,
                        "capture_html": True,
                        "capture_console": True,
                        "take_screenshot": True,
                    },
                    reason="Collect DNS, HTTP, redirect, page and media evidence in the sandbox.",
                ),
                PlanStep(tool="analyze_url_evidence", reason="Convert sandbox output into structured evidence."),
            ]
            goal = "Investigate a URL for phishing, malware, redirects and infrastructure risks."
        elif target_type == "video":
            steps = [
                PlanStep(
                    tool="sandbox_file_investigation",
                    arguments={
                        "analyze_media": True,
                        "extract_video_frames": True,
                        "allow_downloads": False,
                    },
                    reason="Inspect the submitted media in the isolated sandbox.",
                ),
                PlanStep(tool="analyze_video_evidence", reason="Assess metadata, frames and optional authenticity signals."),
            ]
            goal = "Assess an AI-generated-video suspicion using sandbox evidence and available detectors."
        else:
            steps = [
                PlanStep(
                    tool="sandbox_file_investigation",
                    arguments={"analyze_media": True, "allow_downloads": False},
                    reason="Inspect the submitted file in the isolated sandbox.",
                ),
                PlanStep(tool="analyze_file_evidence", reason="Convert sandbox output into structured evidence."),
            ]
            goal = "Investigate an untrusted file for malicious characteristics."
        return InvestigationPlan(goal=goal, steps=steps, source="fallback")

    async def create_plan(
        self,
        *,
        target: str,
        target_type: str,
        tool_schemas: list[dict[str, Any]],
    ) -> InvestigationPlan:
        fallback = self.fallback(target_type)
        if not self.reasoning.enabled:
            return fallback
        try:
            raw = await self.reasoning.plan(
                target=target,
                target_type=target_type,
                tools=tool_schemas,
            )
        except (LLMError, ValueError, TypeError) as exc:
            logger.warning("planner_llm_failed", extra={"error_type": type(exc).__name__})
            return fallback
        plan = self.from_llm(raw, target_type=target_type)
        if not plan.steps:
            return fallback
        plan.source = "llm"
        return plan

    def from_llm(self, raw: dict[str, Any], *, target_type: str) -> InvestigationPlan:
        goal = str(raw.get("goal", ""))[:500]
        steps = self._valid_steps(raw.get("steps"), remaining=self.max_steps)
        fallback = self.fallback(target_type)
        required_sandbox = fallback.steps[0] if fallback.steps else None
        required_analyzer = fallback.steps[-1] if len(fallback.steps) > 1 else None
        if required_sandbox is not None and required_sandbox.tool not in {step.tool for step in steps}:
            steps.insert(0, required_sandbox)
        if required_analyzer is not None and required_analyzer.tool not in {step.tool for step in steps}:
            steps.append(required_analyzer)
        if not goal:
            goal = fallback.goal
        steps = self._dedupe(steps)
        if len(steps) > self.max_steps:
            keep: list[PlanStep] = []
            if required_sandbox is not None:
                keep.append(required_sandbox)
            middle = [
                step
                for step in steps
                if step.tool not in {required_sandbox.tool if required_sandbox else "", required_analyzer.tool if required_analyzer else ""}
            ]
            keep.extend(middle[: max(0, self.max_steps - len(keep) - (1 if required_analyzer else 0))])
            if required_analyzer is not None:
                keep.append(required_analyzer)
            steps = self._dedupe(keep)
        return InvestigationPlan(goal=goal, steps=steps[: self.max_steps], source="llm")

    async def follow_up(
        self,
        *,
        target: str,
        target_type: str,
        evidence: dict[str, Any],
        completed_tools: list[str],
        tool_schemas: list[dict[str, Any]],
    ) -> list[PlanStep]:
        if not self.reasoning.enabled or self.max_followups < 1:
            return []
        try:
            raw = await self.reasoning.follow_up(
                target=target,
                target_type=target_type,
                evidence=evidence,
                tools=tool_schemas,
                completed_tools=completed_tools,
            )
        except (LLMError, ValueError, TypeError) as exc:
            logger.info("followup_llm_failed", extra={"error_type": type(exc).__name__})
            return []
        if bool(raw.get("stop", True)):
            return []
        steps = self._valid_steps(raw.get("actions"), remaining=self.max_followups)
        allowed = self._next_phase_tools(completed_tools)
        filtered = [step for step in steps if step.tool in allowed]
        return self._dedupe(filtered)[: self.max_followups]

    def _valid_steps(self, raw_steps: Any, *, remaining: int) -> list[PlanStep]:
        if not isinstance(raw_steps, list):
            return []
        result: list[PlanStep] = []
        for raw in raw_steps:
            if len(result) >= remaining:
                break
            if not isinstance(raw, dict):
                continue
            tool = str(raw.get("tool", "")).strip()
            if tool not in self.available_tools:
                continue
            arguments = raw.get("arguments")
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                continue
            if len(str(arguments)) > 4096:
                continue
            reason = str(raw.get("reason", ""))[:500]
            result.append(PlanStep(tool=tool, arguments=arguments, reason=reason))
        return result

    def _next_phase_tools(self, completed_tools: list[str]) -> set[str]:
        completed = set(completed_tools)
        if "analyze_url_evidence" in completed or "analyze_file_evidence" in completed or "analyze_video_evidence" in completed:
            return {"run_readonly_command"}
        if any(tool.startswith("sandbox_") for tool in completed):
            return {"analyze_url_evidence", "analyze_file_evidence", "analyze_video_evidence", "run_readonly_command"}
        return set(self.available_tools)

    @staticmethod
    def _dedupe(steps: list[PlanStep]) -> list[PlanStep]:
        seen: set[tuple[str, str]] = set()
        result: list[PlanStep] = []
        for step in steps:
            key = (step.tool, repr(sorted(step.arguments.items())))
            if key in seen:
                continue
            seen.add(key)
            result.append(step)
        return result
