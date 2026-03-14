from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Input, Label, RichLog

from tui.bridge import PromptRequest

if TYPE_CHECKING:
    from tui.bridge import PromptBridge


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class GattShellScreen(Screen):
    BINDINGS = [
        ("ctrl+c", "exit_shell", "Exit shell"),
        ("ctrl+l", "clear_log", "Clear"),
    ]

    def __init__(self, addr: str, bridge: "PromptBridge") -> None:
        super().__init__()
        self._addr = addr
        self._bridge = bridge
        self._prompt_label = f"gatt://{addr}> "
        self._pending: list[str] = []
        self._mounted = False

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical, Horizontal
        from textual.widgets import Static

        with Vertical(id="shell-outer"):
            yield Static(
                f"  // GATT SHELL  //  {self._addr}  //  type 'help'  //  Ctrl+C to exit",
                id="shell-info",
            )
            yield Static("─" * 100, id="shell-divider")
            yield RichLog(
                id="shell-log",
                highlight=False,
                markup=True,
                wrap=True,
            )
            yield Static("─" * 100, id="shell-divider2")
            with Horizontal(id="shell-prompt-row"):
                yield Label(self._prompt_label, id="shell-prompt-label")
                yield Input(placeholder="type a command…", id="shell-input")

        yield Footer()

    def on_mount(self) -> None:
        self._mounted = True
        log = self.query_one("#shell-log", RichLog)
        log.write(f"[bold #00ff41]  SESSION  {self._addr}[/bold #00ff41]")
        for line in self._pending:
            self._write_line(log, line)
        self._pending.clear()
        self.app.call_after_refresh(self.query_one("#shell-input", Input).focus)
        self._bridge._shell_ready.set()

    # ── Output routing ─────────────────────────────────────────────────────

    def append_output(self, text: str) -> None:
        """Called by ButterflyApp when bridge.write_console_output() fires."""
        if not self._mounted:
            # Screen not composed yet — buffer for on_mount to flush
            self._pending.append(text)
            return
        try:
            log = self.query_one("#shell-log", RichLog)
            self._write_line(log, text)
        except Exception:
            self._pending.append(text)

    def _write_line(self, log: RichLog, text: str) -> None:
        ts = _ts()
        stripped = text.strip()
        if stripped.startswith("[OK]") or stripped.startswith("OK"):
            colour = "#00ff41"
        elif stripped.startswith("[ERR]") or stripped.startswith("ERR") or stripped.startswith("[!]"):
            colour = "#ff4040"
        elif stripped.startswith("[WARN]") or stripped.startswith("WARN"):
            colour = "#ffcc00"
        elif stripped.startswith("═") or stripped.startswith("─") or stripped.startswith("┌"):
            colour = "#1a6632"
        else:
            colour = "#22dd66"
        from rich.markup import escape
        log.write(f"[{colour}][{ts}]  {escape(text)}[/{colour}]")

    # ── Prompt handling ────────────────────────────────────────────────────

    def show_prompt_for(self, req: PromptRequest) -> None:
        try:
            self.query_one("#shell-prompt-label", Label).update(req.description)
        except Exception:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        inp = self.query_one("#shell-input", Input)
        if not value:
            self.app.call_after_refresh(inp.focus)
            return
        try:
            from rich.markup import escape
            self.query_one("#shell-log", RichLog).write(
                f"[bold #00ff41]gatt://{self._addr}> {escape(value)}[/bold #00ff41]"
            )
            inp.value = ""
        except Exception:
            pass
        # Re-focus input so the next command can be typed immediately
        self.app.call_after_refresh(inp.focus)
        self.app.on_prompt_input(value)

    # ── Actions ────────────────────────────────────────────────────────────

    def action_exit_shell(self) -> None:
        """Ctrl+C: send 'quit' as if the user typed it."""
        self.app.on_prompt_input("quit")

    def action_clear_log(self) -> None:
        try:
            self.query_one("#shell-log", RichLog).clear()
        except Exception:
            pass
