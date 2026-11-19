from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    ProgressBar,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from storage.history import HistoryStore

from .supervisor import SandboxSupervisor, load_env_file

ROOT = Path(__file__).resolve().parent.parent
VERDICT_STYLES = {
    "SAFE": "bold green",
    "SUSPICIOUS": "bold yellow",
    "MALICIOUS": "bold red",
    "INCONCLUSIVE": "bold cyan",
}


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class SudoPasswordScreen(ModalScreen[str | None]):
    AUTO_FOCUS = "#sudo_password"
    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="sudo_dialog"):
            yield Label("Administrator password required", classes="dialog_title")
            yield Label("Type your sudo password below, then press Enter.")
            yield Input(password=True, placeholder="sudo password", id="sudo_password")
            with Horizontal(id="sudo_actions"):
                yield Button("Cancel", id="sudo_cancel")
                yield Button("Continue", id="sudo_ok", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#sudo_password", Input).focus()

    def _submit(self) -> None:
        value = self.query_one("#sudo_password", Input).value
        self.dismiss(value or None)

    @on(Input.Submitted, "#sudo_password")
    def _password_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self._submit()

    @on(Button.Pressed, "#sudo_ok")
    def _ok_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self._submit()

    @on(Button.Pressed, "#sudo_cancel")
    def _cancel_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TrinetraTUI(App[None]):
    TITLE = "Trinetra"
    SUB_TITLE = "Sandboxed investigation console"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+r", "refresh_history", "Refresh history"),
        ("ctrl+s", "start_sandbox", "Start sandbox"),
    ]

    CSS = """
    Screen {
        background: $surface;
    }

    #body {
        height: 1fr;
    }

    #sidebar {
        width: 42;
        min-width: 36;
        padding: 1;
        border: round $primary;
    }

    #content {
        width: 1fr;
        padding: 1;
    }

    #status {
        height: 3;
        border: round $secondary;
        padding: 0 1;
        content-align: left middle;
    }

    #verdict {
        height: 7;
        border: round $accent;
        padding: 0 1;
    }

    #risk {
        height: 1;
        margin: 0 0 1 0;
    }

    #run_row {
        height: 1;
        margin: 0 0 1 0;
    }

    #loading {
        width: 6;
        height: 1;
    }

    #run_status {
        height: 1;
        width: 1fr;
    }

    #activity {
        height: 1fr;
        border: round $primary;
        padding: 0 1;
    }

    #tables {
        height: 14;
        margin-top: 1;
    }

    #steps, #coverage, #evidence {
        height: 1fr;
    }

    #history {
        height: 1fr;
        min-height: 8;
        margin-top: 1;
    }

    .section {
        margin-top: 1;
        text-style: bold;
        color: $accent;
    }

    .actions {
        height: 3;
        margin-top: 1;
    }

    .actions Button {
        margin-right: 1;
    }

    #target {
        margin-top: 1;
    }

    #target_type {
        margin-top: 1;
    }

    #llm_row {
        height: 3;
        margin-top: 1;
    }

    #llm_row Label {
        width: 1fr;
        content-align: left middle;
    }

    SudoPasswordScreen {
        align: center middle;
    }

    #sudo_dialog {
        width: 68;
        height: auto;
        padding: 1 2;
        border: round $warning;
        background: $surface;
    }

    .dialog_title {
        text-style: bold;
        margin-bottom: 1;
    }

    #sudo_password {
        margin-top: 1;
    }

    #sudo_actions {
        height: 3;
        margin-top: 1;
        align: right middle;
    }

    #sudo_actions Button {
        margin-left: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.supervisor = SandboxSupervisor()
        self._busy = False
        self._auto_start = _truthy(os.getenv("TRINETRA_TUI_AUTO_START"), True)
        self._history_path = Path(os.getenv("TRINETRA_HISTORY_PATH", "storage/trinetra.db"))
        self._last_report: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Label("Target", classes="section")
                yield Input(
                    placeholder="https://example.com or /path/to/file",
                    id="target",
                )
                yield Select(
                    [("URL", "url"), ("File", "file"), ("Video", "video")],
                    value="url",
                    allow_blank=False,
                    id="target_type",
                )
                with Horizontal(id="llm_row"):
                    yield Switch(value=True, id="llm")
                    yield Label("Use LLM planner")
                with Horizontal(classes="actions"):
                    yield Button("Investigate", id="investigate", variant="primary")
                    yield Button("Start sandbox", id="start_sandbox")
                    yield Button("Refresh", id="refresh")
                yield Label("History", classes="section")
                yield DataTable(id="history", cursor_type="row")
            with Vertical(id="content"):
                yield Static("No investigation yet.", id="verdict")
                yield ProgressBar(total=100, show_eta=False, id="risk")
                with Horizontal(id="run_row"):
                    yield LoadingIndicator(id="loading")
                    yield Static("Idle", id="run_status")
                yield Static("", id="status")
                yield RichLog(id="activity", max_lines=2000, wrap=True)
                with TabbedContent(id="tables", initial="evidence_tab"):
                    with TabPane("Evidence", id="evidence_tab"):
                        yield DataTable(id="evidence", cursor_type="row")
                    with TabPane("Steps", id="steps_tab"):
                        yield DataTable(id="steps", cursor_type="row")
                    with TabPane("Coverage", id="coverage_tab"):
                        yield DataTable(id="coverage", cursor_type="row")
        yield Footer()

    async def on_mount(self) -> None:
        loading = self.query_one("#loading", LoadingIndicator)
        loading.display = False
        activity = self.query_one("#activity", RichLog)
        activity.write(Text("Trinetra console ready.", style="bold cyan"))
        self.query_one("#target", Input).focus()
        self._prepare_tables()
        self.run_worker(self._refresh_history(), group="history", exclusive=True)
        if self._auto_start:
            self.run_worker(self._bootstrap_sandbox(), group="sandbox", exclusive=True)
        else:
            self._set_status("Automatic sandbox startup is disabled", "yellow")
            self.run_worker(self._report_health(), group="health", exclusive=True)

    def _prepare_tables(self) -> None:
        steps = self.query_one("#steps", DataTable)
        steps.add_columns("Phase", "Tool", "Status", "ms")
        coverage = self.query_one("#coverage", DataTable)
        coverage.add_columns("Coverage", "Status", "Detail")
        evidence = self.query_one("#evidence", DataTable)
        evidence.add_columns("Source", "Category", "Title", "Severity", "Conf", "Details")
        history = self.query_one("#history", DataTable)
        history.add_columns("Time", "Type", "Verdict", "Risk", "Target")

    def _log(self, message: str) -> None:
        try:
            self.query_one("#activity", RichLog).write(Text(str(message)))
        except Exception:
            pass

    def _set_status(self, message: str, color: str = "white") -> None:
        self.query_one("#status", Static).update(Text(message, style=color))

    def _set_running(self, message: str) -> None:
        self.query_one("#run_status", Static).update(Text(message))
        self.query_one("#loading", LoadingIndicator).display = self._busy

    async def _authorize_sudo(self) -> str | None:
        self._log("Administrator password is needed to start the sandbox manager.")
        try:
            password = await self.push_screen_wait(SudoPasswordScreen())
        except Exception as exc:
            self._log(f"sudo prompt failed: {type(exc).__name__}")
            return None
        if not password:
            self._log("sudo password was not provided")
            return None
        self._log("Checking administrator authorization...")
        return password

    async def _bootstrap_sandbox(self) -> None:
        self._set_status("Checking Docker and sandbox manager...", "yellow")
        self._set_running("Starting sandbox...")
        ok, detail = await self.supervisor.ensure_started(
            log=self._log,
            authorize=self._authorize_sudo,
        )
        if ok:
            self._set_status(detail, "green")
            self._set_running("Sandbox ready")
        else:
            self._set_status(detail, "red")
            self._set_running("Sandbox unavailable")
            self._log("Start manually with: ./run-sandbox.sh")

    async def _start_sandbox(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.query_one("#investigate", Button).disabled = True
        self.query_one("#loading", LoadingIndicator).display = True
        try:
            await self._bootstrap_sandbox()
        finally:
            self._busy = False
            self.query_one("#investigate", Button).disabled = False
            self.query_one("#loading", LoadingIndicator).display = False

    async def _report_health(self) -> None:
        healthy = await self.supervisor.health()
        self._set_status(
            "Sandbox manager is running" if healthy else "Sandbox manager is not running",
            "green" if healthy else "red",
        )

    async def _ensure_sandbox(self) -> bool:
        if await self.supervisor.health():
            self._set_status("Sandbox manager is running", "green")
            return True
        self._set_status("Starting sandbox manager...", "yellow")
        ok, detail = await self.supervisor.ensure_started(
            log=self._log,
            authorize=self._authorize_sudo,
        )
        self._set_status(detail, "green" if ok else "red")
        return ok

    async def _refresh_history(self) -> None:
        try:
            history = HistoryStore(self._history_path)
            await history.initialize()
            rows = await history.list(limit=25)
        except Exception as exc:
            self._log(f"History unavailable: {type(exc).__name__}")
            return
        table = self.query_one("#history", DataTable)
        table.clear(columns=False)
        for row in rows:
            table.add_row(
                str(row.get("completed_at", ""))[:19].replace("T", " "),
                str(row.get("target_type", "")),
                str(row.get("verdict", "")),
                str(row.get("risk_score", "")),
                str(row.get("target", ""))[:60],
                key=str(row.get("report_id", "")),
            )

    async def _load_history_report(self, report_id: str) -> None:
        try:
            history = HistoryStore(self._history_path)
            await history.initialize()
            report = await history.get(report_id)
        except Exception as exc:
            self._log(f"Report unavailable: {type(exc).__name__}")
            return
        if report:
            self._show_report(report)
            self._log(f"Loaded stored report {report_id}")

    def _start_investigation(self) -> None:
        if self._busy:
            return
        target = self.query_one("#target", Input).value.strip()
        target_type = str(self.query_one("#target_type", Select).value or "url")
        if not target:
            self._set_status("Enter a URL or file path first", "red")
            return
        if target_type == "url" and not target.lower().startswith(("http://", "https://")):
            self._set_status("URL must start with http:// or https://", "red")
            return
        if target_type in {"file", "video"}:
            path = Path(target).expanduser()
            if not path.is_file():
                self._set_status("File does not exist or is not a regular file", "red")
                return
            target = str(path.resolve())
        use_llm = bool(self.query_one("#llm", Switch).value)
        self._busy = True
        self.query_one("#investigate", Button).disabled = True
        self._set_running("Investigation running...")
        self._set_status("Agent is working...", "yellow")
        self.run_worker(
            self._run_investigation(target, target_type, use_llm),
            group="investigation",
            exclusive=True,
        )

    async def _run_investigation(self, target: str, target_type: str, use_llm: bool) -> None:
        activity = self.query_one("#activity", RichLog)
        activity.clear()
        activity.write(Text(f"Target: {target}", style="bold"))
        activity.write(Text(f"Type: {target_type}"))
        completed = False
        try:
            if not await self._ensure_sandbox():
                self._set_status("Sandbox is not available; investigation cancelled", "red")
                return
            command = [str(ROOT / "run-agent.sh"), target_type, target, "--pretty"]
            if not use_llm:
                command.append("--no-llm")
            self._log("Starting agent...")
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode("utf-8", "replace").strip()
            error_output = stderr.decode("utf-8", "replace").strip()
            if process.returncode != 0:
                if error_output:
                    self._log(error_output[-2000:])
                self._set_status("Agent failed", "red")
                return
            start = output.find("{")
            end = output.rfind("}")
            if start < 0 or end < start:
                self._log("Agent returned no JSON report")
                self._set_status("Agent returned no report", "red")
                return
            report = json.loads(output[start : end + 1])
            if not isinstance(report, dict):
                self._log("Agent report is not an object")
                self._set_status("Agent returned an invalid report", "red")
                return
            self._show_report(report)
            completed = True
            self._set_status("Investigation complete", "green")
            self._log("Report stored in history")
            await self._refresh_history()
        except json.JSONDecodeError as exc:
            self._log(f"Could not parse report: {exc}")
            self._set_status("Report parsing failed", "red")
        except Exception as exc:
            self._log(f"Investigation failed: {type(exc).__name__}: {exc}")
            self._set_status("Investigation failed", "red")
        finally:
            self._busy = False
            self.query_one("#investigate", Button).disabled = False
            self.query_one("#loading", LoadingIndicator).display = False
            if not completed:
                self.query_one("#run_status", Static).update(Text("Idle"))

    def _show_report(self, report: dict[str, Any]) -> None:
        self._last_report = report
        verdict = str(report.get("verdict", "UNKNOWN"))
        risk = int(report.get("risk_score", 0) or 0)
        confidence = report.get("confidence", 0)
        status = str(report.get("status", ""))
        verdict_text = Text()
        verdict_text.append(verdict, style=VERDICT_STYLES.get(verdict, "bold white"))
        verdict_text.append(f"  {status}\n", style="dim")
        verdict_text.append(str(report.get("summary", "")).strip())
        self.query_one("#verdict", Static).update(verdict_text)
        self.query_one("#risk", ProgressBar).update(progress=float(max(0, min(100, risk))))
        self.query_one("#run_status", Static).update(
            Text(f"Risk {risk}/100  Confidence {float(confidence):.2f}")
        )
        activity = self.query_one("#activity", RichLog)
        activity.clear()
        activity.write(Text(f"Target: {report.get('target', '')}", style="bold"))
        activity.write(Text(f"Report: {report.get('report_id', '')}"))
        activity.write(Text(f"Verdict: {verdict}", style=VERDICT_STYLES.get(verdict, "bold white")))
        activity.write(Text(f"Status: {status}"))
        activity.write(Text(f"Risk: {risk}/100  Confidence: {float(confidence):.2f}"))
        activity.write(Text(""))
        activity.write(Text("Reasons", style="bold cyan"))
        for reason in report.get("reasons", []) or ["None"]:
            activity.write(Text(f"- {reason}"))
        activity.write(Text(""))
        activity.write(Text("Threats", style="bold cyan"))
        threats = report.get("threats", []) or []
        if threats:
            for threat in threats:
                if isinstance(threat, dict):
                    label = threat.get("title") or threat.get("type") or threat.get("code") or "Threat"
                    detail = threat.get("description") or threat.get("detail") or ""
                    activity.write(Text(f"- {label}: {detail}"))
                else:
                    activity.write(Text(f"- {threat}"))
        else:
            activity.write(Text("- None identified"))
        activity.write(Text(""))
        activity.write(Text("Recommendations", style="bold cyan"))
        for recommendation in report.get("recommendations", []) or ["None"]:
            activity.write(Text(f"- {recommendation}"))
        errors = report.get("errors", []) or []
        if errors:
            activity.write(Text(""))
            activity.write(Text("Errors", style="bold red"))
            for error in errors:
                if isinstance(error, dict):
                    activity.write(Text(f"- {error.get('stage', '')}: {error.get('message', '')}"))
                else:
                    activity.write(Text(f"- {error}"))
        steps_table = self.query_one("#steps", DataTable)
        steps_table.clear(columns=False)
        for step in report.get("steps", []) or []:
            steps_table.add_row(
                str(step.get("phase", "")),
                str(step.get("tool", "")),
                str(step.get("status", "")),
                str(step.get("duration_ms", "")),
            )
        coverage_table = self.query_one("#coverage", DataTable)
        coverage_table.clear(columns=False)
        for item in report.get("coverage", []) or []:
            coverage_table.add_row(
                str(item.get("name", "")),
                str(item.get("status", "")),
                str(item.get("detail", "")),
            )
        evidence_table = self.query_one("#evidence", DataTable)
        evidence_table.clear(columns=False)
        for index, item in enumerate(report.get("evidence", []) or []):
            if not isinstance(item, dict):
                item = {"title": str(item)}
            data = item.get("data")
            detail = str(item.get("description") or "").strip()
            if data:
                rendered = json.dumps(data, ensure_ascii=False, sort_keys=True)
                detail = f"{detail} {rendered}".strip()
            if not detail:
                detail = str(item.get("code") or "")
            try:
                confidence = f"{float(item.get('confidence', 0)):.2f}"
            except (TypeError, ValueError):
                confidence = str(item.get("confidence", ""))
            evidence_table.add_row(
                str(item.get("source", "")),
                str(item.get("category", "")),
                str(item.get("title", "")),
                str(item.get("severity", "")),
                confidence,
                detail,
                key=str(index),
            )

    def _show_evidence_detail(self, index: int) -> None:
        report = self._last_report or {}
        items = report.get("evidence", []) or []
        if index < 0 or index >= len(items) or not isinstance(items[index], dict):
            return
        item = items[index]
        activity = self.query_one("#activity", RichLog)
        activity.write(Text(""))
        activity.write(Text(f"Evidence {item.get('id', '')}", style="bold cyan"))
        activity.write(Text(f"Source: {item.get('source', '')}"))
        activity.write(Text(f"Category: {item.get('category', '')}"))
        activity.write(Text(f"Title: {item.get('title', '')}"))
        activity.write(Text(f"Severity: {item.get('severity', '')}  Confidence: {item.get('confidence', '')}"))
        description = str(item.get("description") or "").strip()
        if description:
            activity.write(Text(f"Description: {description}"))
        data = item.get("data")
        if data:
            activity.write(Text("Data:", style="bold"))
            activity.write(Text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)))

    @on(DataTable.RowSelected, "#evidence")
    def _evidence_selected(self, event: DataTable.RowSelected) -> None:
        value = event.row_key.value
        if value is not None:
            self._show_evidence_detail(int(value))

    @on(Input.Submitted, "#target")
    def _target_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self._start_investigation()

    @on(DataTable.RowSelected, "#history")
    def _history_selected(self, event: DataTable.RowSelected) -> None:
        value = event.row_key.value
        if value:
            self.run_worker(
                self._load_history_report(str(value)),
                group="history",
                exclusive=True,
            )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "investigate":
            self._start_investigation()
        elif event.button.id == "start_sandbox":
            self.run_worker(self._start_sandbox(), group="sandbox", exclusive=True)
        elif event.button.id == "refresh":
            self.run_worker(self._refresh_history(), group="history", exclusive=True)

    def action_refresh_history(self) -> None:
        self.run_worker(self._refresh_history(), group="history", exclusive=True)

    def action_start_sandbox(self) -> None:
        self.run_worker(self._start_sandbox(), group="sandbox", exclusive=True)


def main() -> None:
    load_env_file(ROOT / ".env")
    TrinetraTUI().run()


if __name__ == "__main__":
    main()
