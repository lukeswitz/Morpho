from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Input, Label, RichLog

from tui.bridge import PromptRequest


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class GattShellScreen(Screen):
    """
    Hackers (1995)-style GATT interactive shell screen.

    Pushed over DashboardScreen for the duration of a GATT shell session.
    Shell output from shell_write() arrives via append_output().
    The gatt> prompt is delivered via show_prompt_for() — same TEXT_INPUT
    bridge mechanism as the rest of the framework.

    Race condition note: push_screen() schedules mounting asynchronously.
    ConsoleOutput messages from _shell_banner() often arrive in the same
    event-loop tick — before compose()/on_mount() have run — so
    append_output() may be called before the RichLog widget exists.
    We buffer those early lines in _pending and flush them in on_mount().
    """

    BINDINGS = [
        ("ctrl+c", "exit_shell", "Exit shell"),
        ("ctrl+l", "clear_log", "Clear"),
    ]

    def __init__(self, addr: str) -> None:
        super().__init__()
        self._addr = addr
        self._prompt_label = f"gatt://{addr}> "
        self._pending: list[str] = []   # output buffered before on_mount
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
        log.write(
            f"[bold #00ff41]  SESSION  {self._addr}[/bold #00ff41]"
        )
        # Flush any output that arrived before we were mounted
        for line in self._pending:
            self._write_line(log, line)
        self._pending.clear()
        self.app.call_after_refresh(self.query_one("#shell-input", Input).focus)

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
        """Called by ButterflyApp._notify_prompt when this screen is active."""
        try:
            self.query_one("#shell-prompt-label", Label).update(req.description)
            inp = self.query_one("#shell-input", Input)
            inp.value = ""
            self.app.call_after_refresh(inp.focus)
        except Exception:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value
        # Echo the command into the log before routing
        try:
            from rich.markup import escape
            self.query_one("#shell-log", RichLog).write(
                f"[bold #00ff41]gatt://{self._addr}> {escape(value)}[/bold #00ff41]"
            )
            self.query_one("#shell-input", Input).value = ""
        except Exception:
            pass
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
