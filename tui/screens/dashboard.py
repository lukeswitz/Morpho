from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static
from textual.containers import Horizontal, Vertical

from tui.bridge import PromptKind, PromptRequest
from tui.widgets.prompt_bar import PromptBar
from tui.widgets.stage_list import StageState, StageStatusWidget
from tui.widgets.target_table import TargetTableWidget

if TYPE_CHECKING:
    pass


class DashboardScreen(Screen):
    """
    Live three-panel dashboard shown during stage execution:
      Left  26 cols : StageStatusWidget (stage list with state icons)
      Center 1fr    : RichLog (scrolling colored log output)
      Right  52 cols: TargetTableWidget (live BLE target table)
      Bottom 3 rows : PromptBar (free-text prompts)
    """

    BINDINGS = [
        ("ctrl+c", "abort_run", "Abort"),
        ("ctrl+l", "toggle_log", "Log"),
        ("ctrl+r", "toggle_redact", "Redact"),
    ]

    def __init__(self, requested_stages: set[int]) -> None:
        super().__init__()
        self._requested_stages = requested_stages
        self._redact_on: bool = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-panels"):
            yield StageStatusWidget(self._requested_stages)
            yield RichLog(id="log-pane", highlight=False, markup=True, wrap=True)
            yield TargetTableWidget()
        yield PromptBar()
        yield Footer()

    def action_toggle_log(self) -> None:
        pane = self.query_one("#log-pane", RichLog)
        pane.display = not pane.display

    def action_abort_run(self) -> None:
        """Ctrl+C: abort the run cleanly."""
        self.app.abort_run()

    def action_toggle_redact(self) -> None:
        """Ctrl+R: toggle redaction of MACs and device names in all output."""
        from core.logger import enable_redact, disable_redact, _REDACT_ENABLED
        tbl = self.query_one(TargetTableWidget)
        if _REDACT_ENABLED:
            self._redact_on = False
            disable_redact()
            tbl.restore_all_rows()
            self.on_append_log("REDACT OFF — showing real addresses and names", "WARNING")
        else:
            self._redact_on = True
            enable_redact()
            tbl.redact_all_rows()
            self.on_append_log(
                "REDACT ON — MACs replaced with XX:XX:XX:XX:XX:XX, names with [REDACTED]",
                "WARNING",
            )
        try:
            self.app.refresh_bindings()
        except Exception:
            pass

    # ── Methods called by ButterflyApp message handlers ────────────────────────

    def on_stage_started(self, stage: int, title: str, passive: bool) -> None:
        """Mark stage as RUNNING; write a single clean header line to log pane."""
        from rich.markup import escape
        self.query_one(StageStatusWidget).set_stage_state(stage, StageState.RUNNING)
        pane = self.query_one("#log-pane", RichLog)
        tag_markup = "[#40c060]PASSIVE[/#40c060]" if passive else "[bold #e04040]ACTIVE[/bold #e04040]"
        pane.write(f"[bold #2080b0]S{stage:02d}[/bold #2080b0] {tag_markup} [bold white]{escape(title)}[/bold white]")

    def on_stage_finished(self, stage: int, skipped: bool, error: bool) -> None:
        """Update stage icon to COMPLETE, SKIPPED, or ERROR."""
        widget = self.query_one(StageStatusWidget)
        if error:
            widget.set_stage_state(stage, StageState.ERROR)
        elif skipped:
            widget.set_stage_state(stage, StageState.SKIPPED)
        else:
            widget.set_stage_state(stage, StageState.COMPLETE)
        self.query_one(TargetTableWidget).clear_stage_scan_status()

    def on_target_found(self, target: object) -> None:
        """Add a row to the live target table."""
        self.query_one(TargetTableWidget).add_target(target)

    def on_scan_status(self, addr: str, stage_label: str) -> None:
        """Mark a target row as currently being scanned by a stage."""
        self.query_one(TargetTableWidget).set_scan_status(addr, stage_label)

    def on_finding(self, addr: str, n: int) -> None:
        """Increment findings count for a target row."""
        self.query_one(TargetTableWidget).add_finding(addr, n)

    def on_append_log(self, text: str, level: str) -> None:
        """Write a log line to the RichLog with level-appropriate color."""
        from rich.markup import escape
        pane = self.query_one("#log-pane", RichLog)
        color = {
            "ERROR":    "bold #e04040",
            "CRITICAL": "bold #e040a0",
            "WARNING":  "#d08020",
            "DEBUG":    "#303848",
        }.get(level, "#8090a0")
        pane.write(f"[{color}]{escape(text)}[/{color}]")

    def show_prompt_for(self, req: PromptRequest) -> None:
        """
        Show the appropriate UI for a pending PromptRequest.
        Called from ButterflyApp when PromptReady message arrives.
        Auto-shows the log pane so the user sees any menu options logged above.
        """
        self.query_one("#log-pane", RichLog).display = True
        if req.kind == PromptKind.ACTIVE_GATE:
            self.app.push_screen(ActiveGateModal(req))
        elif req.kind == PromptKind.SELECT_TARGETS:
            self.app.push_screen(SelectTargetsModal(req))
        else:
            # TEXT_INPUT or MENU_CHOICE: use the bottom prompt bar
            bar = self.query_one(PromptBar)
            bar.show_prompt(req.description)

    def on_prompt_bar_submitted(self, event: PromptBar.Submitted) -> None:
        """Relay prompt bar input to the app (which resolves the bridge)."""
        event.stop()
        bar = self.query_one(PromptBar)
        bar.hide()
        self.app.on_prompt_input(event.value)


class ActiveGateModal(Screen):
    """
    Full-screen modal overlay for active stage confirmation gates.
    Operator must explicitly choose YES, SKIP, or ABORT.
    """

    def __init__(self, req: PromptRequest) -> None:
        super().__init__()
        self._req = req

    def compose(self) -> ComposeResult:
        with Vertical(classes="gate-box"):
            yield Static(
                f"ACTIVE STAGE {self._req.stage} GATE",
                classes="gate-title",
            )
            yield Static(self._req.description, classes="gate-desc")
            yield Static(
                "This stage will transmit RF packets.\n"
                "Only proceed on equipment you own or have written authorization to test.",
                classes="gate-warning",
            )
            with Horizontal():
                yield Button(
                    "YES — proceed",
                    id="btn-yes",
                    classes="btn-yes",
                    variant="success",
                )
                yield Button(
                    "SKIP stage",
                    id="btn-skip",
                    classes="btn-skip",
                    variant="warning",
                )
                yield Button(
                    "ABORT run",
                    id="btn-abort",
                    classes="btn-abort",
                    variant="error",
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "btn-yes":
            result: bool | None = True
        elif event.button.id == "btn-skip":
            result = False
        else:  # abort
            result = None
        self.dismiss()
        self.app.on_active_gate_result(result)


class SelectTargetsModal(Screen):
    """
    Modal for target selection. Shows a DataTable of candidates and an input
    accepting the same grammar as the plain-text select_targets() function:
    numbers (1,3), 'all', 'smart', 'skip'.
    """

    def __init__(self, req: PromptRequest) -> None:
        super().__init__()
        self._req = req
        self._candidates: list = sorted(
            req.options or [], key=lambda t: getattr(t, "risk_score", 0), reverse=True
        )

    def compose(self) -> ComposeResult:
        from rich.text import Text as RichText

        smart_skip = self._req.smart_skip_classes or set()
        with Vertical(classes="targets-box"):
            yield Static(
                f"  {self._req.description} — {len(self._candidates)} candidates",
                classes="targets-title",
            )
            table: DataTable = DataTable(id="sel-dt", zebra_stripes=True)
            table.add_columns("#", "RISK", "ADDRESS", "CLASS", "RSSI", "NAME")
            for i, t in enumerate(self._candidates, 1):
                risk = self._risk_label(getattr(t, "risk_score", 0))
                addr = getattr(t, "bd_address", "??")
                cls  = getattr(t, "device_class", "unknown") or "unknown"
                rssi = f"{getattr(t, 'rssi_avg', 0):.0f}"
                name = (getattr(t, "name", None) or "—")[:20]
                row_style = "dim" if cls in smart_skip else ""
                table.add_row(
                    RichText(str(i), style=row_style),
                    RichText(risk, style=row_style),
                    RichText(addr, style=row_style),
                    RichText(cls[:14], style=row_style),
                    RichText(rssi, style=row_style),
                    RichText(name, style=row_style),
                )
            yield table
            multi = self._req.max_count != 1
            skip_label = (
                f"smart (skip {', '.join(sorted(smart_skip))})"
                if smart_skip else "smart"
            )
            hint = (
                f"numbers (1,3), 'all', '{skip_label}', 'skip'"
                if multi
                else f"number, '{skip_label}', 'skip'"
            )
            if self._req.default_all and multi:
                hint += "  [Enter]=all"
            yield Label(f"Enter: {hint}")
            yield Input(placeholder="Selection", id="sel-input")
            yield Button("Confirm", id="btn-confirm", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-confirm":
            return
        raw = self.query_one("#sel-input", Input).value.strip().lower()
        selected = self._parse_selection(raw)
        self.dismiss()
        self.app.on_select_targets_result(selected)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip().lower()
        selected = self._parse_selection(raw)
        self.dismiss()
        self.app.on_select_targets_result(selected)

    def _parse_selection(self, raw: str) -> list:
        """Parse selection string using same logic as core/logger.py:select_targets()."""
        smart_skip = self._req.smart_skip_classes or set()
        single = self._req.max_count == 1
        candidates = self._candidates

        if raw == "":
            if self._req.default_all and not single:
                return list(candidates)
            return []
        if raw == "skip":
            return []
        if raw == "all":
            return [] if single else list(candidates)
        if raw == "smart":
            filtered = [
                t for t in candidates
                if getattr(t, "device_class", "") not in smart_skip
            ]
            if not filtered:
                return []
            return [filtered[0]] if single else filtered
        # Parse numbers
        try:
            nums = [int(x) for x in raw.replace(",", " ").split() if x.strip()]
            if not nums:
                return []
            if single and len(nums) > 1:
                nums = [nums[0]]
            result = []
            for n in nums:
                if 1 <= n <= len(candidates):
                    result.append(candidates[n - 1])
            return result
        except ValueError:
            return []

    @staticmethod
    def _risk_label(score: int) -> str:
        if score >= 8:
            return "CRIT"
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MED "
        if score >= 2:
            return "LOW "
        return "INFO"
