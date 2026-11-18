from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace

from config.settings import ConfigurationError, Settings
from storage.history import HistoryStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trinetra",
        description="Defensive investigation agent for URLs, files and suspected AI-generated video.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("url", "Investigate a URL."),
        ("file", "Investigate a file."),
        ("video", "Assess a suspected AI-generated video."),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("target")
        command.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
        command.add_argument("--no-llm", action="store_true", help="Disable all LLM planning and narration.")
        command.add_argument(
            "--approval",
            choices=("auto", "interactive", "deny"),
            help="Override the configured approval mode for this run.",
        )

    history = subparsers.add_parser("history", help="List stored investigations.")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--type", choices=("url", "file", "video"), dest="target_type")
    history.add_argument("--verdict", choices=("SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"))
    history.add_argument("--pretty", action="store_true")

    show = subparsers.add_parser("show", help="Show a stored investigation report.")
    show.add_argument("report_id")
    show.add_argument("--pretty", action="store_true")
    return parser


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    if getattr(args, "approval", None):
        settings = replace(settings, approval_mode=args.approval)
    if getattr(args, "no_llm", False):
        settings = replace(settings, llm_api_key=None)
    settings.validate()
    return settings


async def _run_investigation(args: argparse.Namespace, target_type: str) -> int:
    from agent import InvestigationAgent

    settings = _settings(args)
    async with InvestigationAgent(settings) as agent:
        if target_type == "url":
            report = await agent.investigate_url(args.target)
        elif target_type == "video":
            report = await agent.investigate_video(args.target)
        else:
            report = await agent.investigate_file(args.target)
    print(report.to_json(indent=2 if args.pretty else None))
    return 0


async def _run_history(args: argparse.Namespace) -> int:
    settings = _settings(args)
    history = HistoryStore(settings.history_path)
    await history.initialize()
    reports = await history.list(limit=args.limit, target_type=args.target_type, verdict=args.verdict)
    print(json.dumps({"reports": reports}, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


async def _run_show(args: argparse.Namespace) -> int:
    settings = _settings(args)
    history = HistoryStore(settings.history_path)
    await history.initialize()
    report = await history.get(args.report_id)
    if report is None:
        print("report not found", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0


async def async_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"url", "file", "video"}:
        return await _run_investigation(args, args.command)
    if args.command == "history":
        return await _run_history(args)
    if args.command == "show":
        return await _run_show(args)
    parser.error("unknown command")
    return 2


def main(argv: list[str] | None = None) -> int:
    try:
        return asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (ConfigurationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
