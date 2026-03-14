from __future__ import annotations

import logging
import pathlib
import threading
from typing import Any, Callable

from textual.app import App, ComposeResult
from textual.message import Message
from textual import on

from tui.bridge import PromptBridge, PromptRequest
from tui.handler import TuiLogHandler
from tui.screens.dashboard import DashboardScreen
from tui.screens.gatt_shell import GattShellScreen
from tui.screens.launch import LaunchConfig, LaunchScreen


class ButterflyApp(App):
    """
    Textual application for Butterfly-RedTeam.

    Flow:
      1. on_mount → install log handler → push LaunchScreen
      2. User fills form and clicks LAUNCH → on_launch_screen_launched
         → push DashboardScreen → start worker thread calling run_stages_fn
      3. Worker thread calls bridge.request_prompt() → blocks → ButterflyApp
         receives PromptReady → pushes modal → user responds → on_*_result
         → bridge.resolve(value) → worker unblocks
      4. Worker ends → run complete
      5. Ctrl+C or ABORT button → abort_run() → bridge.abort() → exit()
    """

    # Resolve CSS path relative to THIS file (tui/app.py) not the CWD
    CSS_PATH = str(pathlib.Path(__file__).parent / "butterfly.tcss")

    # ── Internal cross-thread messages ────────────────────────────────────────

    class LogLine(Message):
        def __init__(self, text: str, level: str) -> None:
            super().__init__()
            self.text = text
            self.level = level

    class StageStarted(Message):
        def __init__(self, stage: int, title: str, passive: bool) -> None:
            super().__init__()
            self.stage = stage
            self.title = title
            self.passive = passive

    class StageFinished(Message):
        def __init__(self, stage: int, skipped: bool = False, error: bool = False) -> None:
            super().__init__()
            self.stage = stage
            self.skipped = skipped
            self.error = error

    class TargetFound(Message):
        def __init__(self, target: Any) -> None:
            super().__init__()
            self.target = target

    class PromptReady(Message):
        def __init__(self, req: PromptRequest) -> None:
            super().__init__()
            self.req = req

    class GattShellPush(Message):
        def __init__(self, addr: str) -> None:
            super().__init__()
            self.addr = addr

    class GattShellPop(Message):
        pass

    class ConsoleOutput(Message):
        def __init__(self, line: str) -> None:
            super().__init__()
            self.line = line

    # ── Constructor ───────────────────────────────────────────────────────────

    def __init__(
        self,
        bridge: PromptBridge,
        run_stages_fn: Callable[[LaunchConfig, PromptBridge], None],
        initial_cfg: LaunchConfig | None = None,
    ) -> None:
        super().__init__()
        self._bridge = bridge
        self._run_stages_fn = run_stages_fn
        self._initial_cfg = initial_cfg
        self._worker: threading.Thread | None = None
        self._log_handler: TuiLogHandler | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        # compose() is required; the first real screen is pushed in on_mount
        yield from []

    def on_mount(self) -> None:
        """Wire bridge callback, install log handler, push launch screen."""
        self._wire_bridge()
        self._install_log_handler()
        self.push_screen(LaunchScreen(initial_cfg=self._initial_cfg))

    def on_unmount(self) -> None:
        """Ensure worker is unblocked when app shuts down."""
        self._bridge.abort()

    # ── Bridge wiring ─────────────────────────────────────────────────────────

    def _wire_bridge(self) -> None:
        """
        Wire the bridge so worker-thread notifications reach the event loop.
        We call screen methods directly via call_from_thread rather than routing
        through post_message + auto-named handlers (name derivation is fragile).
        """
        app = self
        self._bridge.set_app_callback(self.call_from_thread)

        def _notify_prompt(req: PromptRequest) -> None:
            # Runs inside event loop already (called via call_from_thread in request_prompt)
            screen = app.screen
            if isinstance(screen, DashboardScreen):
                screen.show_prompt_for(req)
            elif isinstance(screen, GattShellScreen):
                screen.show_prompt_for(req)

        self._bridge._notify_prompt = _notify_prompt  # type: ignore[method-assign]

        def _notify_stage_start(stage: int, title: str, passive: bool) -> None:
            def _do() -> None:
                try:
                    screen = app.screen
                    if isinstance(screen, DashboardScreen):
                        screen.on_stage_started(stage, title, passive)
                except Exception as exc:
                    logging.getLogger("tui").error("on_stage_started S%s: %s", stage, exc, exc_info=True)
            app.call_from_thread(_do)

        def _notify_stage_finish(stage: int, skipped: bool, error: bool) -> None:
            def _do() -> None:
                try:
                    screen = app.screen
                    if isinstance(screen, DashboardScreen):
                        screen.on_stage_finished(stage, skipped, error)
                except Exception as exc:
                    logging.getLogger("tui").error("on_stage_finished S%s: %s", stage, exc, exc_info=True)
            app.call_from_thread(_do)

        def _notify_target_found(target: Any) -> None:
            def _do() -> None:
                try:
                    screen = app.screen
                    if isinstance(screen, DashboardScreen):
                        screen.on_target_found(target)
                except Exception as exc:
                    logging.getLogger("tui").error("on_target_found: %s", exc, exc_info=True)
            app.call_from_thread(_do)

        def _notify_scan_status(addr: str, stage_label: str) -> None:
            def _do() -> None:
                try:
                    screen = app.screen
                    if isinstance(screen, DashboardScreen):
                        screen.on_scan_status(addr, stage_label)
                except Exception as exc:
                    logging.getLogger("tui").error("on_scan_status: %s", exc)
            app.call_from_thread(_do)

        def _notify_finding(addr: str, n: int) -> None:
            def _do() -> None:
                try:
                    screen = app.screen
                    if isinstance(screen, DashboardScreen):
                        screen.on_finding(addr, n)
                except Exception as exc:
                    logging.getLogger("tui").error("on_finding: %s", exc)
            app.call_from_thread(_do)

        self._bridge.notify_stage_start = _notify_stage_start  # type: ignore[method-assign]
        self._bridge.notify_stage_finish = _notify_stage_finish  # type: ignore[method-assign]
        self._bridge.notify_target_found = _notify_target_found  # type: ignore[method-assign]
        self._bridge.notify_scan_status = _notify_scan_status  # type: ignore[method-assign]
        self._bridge.notify_finding = _notify_finding  # type: ignore[method-assign]

        def _notify_push_gatt_shell(addr: str) -> None:
            app.call_from_thread(lambda: app.post_message(app.GattShellPush(addr)))

        def _notify_pop_gatt_shell() -> None:
            app.call_from_thread(lambda: app.post_message(app.GattShellPop()))

        def _notify_console_output(line: str) -> None:
            app.call_from_thread(lambda: app.post_message(app.ConsoleOutput(line)))

        self._bridge.push_gatt_shell = _notify_push_gatt_shell  # type: ignore[method-assign]
        self._bridge.pop_gatt_shell = _notify_pop_gatt_shell  # type: ignore[method-assign]
        self._bridge.write_console_output = _notify_console_output  # type: ignore[method-assign]

    # ── Log handler ───────────────────────────────────────────────────────────

    def _install_log_handler(self) -> None:
        """Attach TuiLogHandler to root logger only.
        Strip any existing StreamHandlers first — WHAD and other imports may
        have called logging.basicConfig() or added their own StreamHandlers
        that write ANSI-coloured text to stderr, bleeding through the TUI.
        """
        logging.root.handlers = [
            h for h in logging.root.handlers
            if not isinstance(h, logging.StreamHandler)
        ]
        handler = TuiLogHandler(self)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s", "%H:%M:%S"
        ))
        self._log_handler = handler
        logging.root.addHandler(handler)

    # ── Screen event handlers ─────────────────────────────────────────────────

    @on(LaunchScreen.Launched)
    def on_launch_screen_launched(self, event: LaunchScreen.Launched) -> None:
        """Operator submitted the launch form. Start dashboard, then worker thread.

        push_screen() only queues the screen change — DashboardScreen won't be
        active until after this handler returns and the event loop processes the
        push.  call_after_refresh() defers _start_worker until after that first
        render cycle, so every isinstance(screen, DashboardScreen) check in the
        message handlers will succeed.
        """
        cfg = event.cfg
        self.push_screen(DashboardScreen(cfg.stages))
        self.call_after_refresh(lambda: self._start_worker(cfg))

    def _start_worker(self, cfg: LaunchConfig) -> None:
        # whad.cli.app was pre-imported in main.py before the TUI started.
        # Re-strip any StreamHandlers it may have added to the root logger.
        if self._log_handler is not None:
            logging.root.handlers = [
                h for h in logging.root.handlers
                if not isinstance(h, logging.StreamHandler)
                or h is self._log_handler
            ]
        self._worker = threading.Thread(
            target=self._run_stages_fn,
            args=(cfg, self._bridge),
            daemon=True,
            name="stage-worker",
        )
        self._worker.start()

    # ── Cross-thread message handlers (run in Textual event loop) ─────────────

    def on_butterfly_app_log_line(self, event: LogLine) -> None:
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen.on_append_log(event.text, event.level)
        except Exception:
            pass

    def on_butterfly_app_stage_started(self, event: StageStarted) -> None:
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen.on_stage_started(event.stage, event.title, event.passive)
        except Exception:
            pass

    def on_butterfly_app_stage_finished(self, event: StageFinished) -> None:
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen.on_stage_finished(event.stage, event.skipped, event.error)
        except Exception:
            pass

    def on_butterfly_app_target_found(self, event: TargetFound) -> None:
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen.on_target_found(event.target)
        except Exception:
            pass

    def on_butterfly_app_prompt_ready(self, event: PromptReady) -> None:
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen.show_prompt_for(event.req)
        except Exception:
            pass

    def on_butterfly_app_gatt_shell_push(self, event: GattShellPush) -> None:
        try:
            screen = GattShellScreen(event.addr, self._bridge)
            self.push_screen(screen)
        except Exception as exc:
            logging.getLogger("tui").error("gatt_shell_push: %s", exc)
            self._bridge._shell_ready.set()

    def on_butterfly_app_gatt_shell_pop(self, event: GattShellPop) -> None:
        popped = False
        try:
            if isinstance(self.screen, GattShellScreen):
                self.pop_screen()
                popped = True
        except Exception as exc:
            logging.getLogger("tui").error("gatt_shell_pop: %s", exc)
        if popped:
            self.call_after_refresh(self._bridge._shell_popped.set)
        else:
            self._bridge._shell_popped.set()

    def on_butterfly_app_console_output(self, event: ConsoleOutput) -> None:
        try:
            screen = self.screen
            if isinstance(screen, GattShellScreen):
                screen.append_output(event.line)
        except Exception:
            pass

    # ── Methods called by DashboardScreen / modals to resolve prompts ──────────

    def on_prompt_input(self, value: str) -> None:
        """Called by DashboardScreen when PromptBar.Submitted fires."""
        self._bridge.resolve(value)

    def on_active_gate_result(self, result: bool | None) -> None:
        """Called by ActiveGateModal on dismiss."""
        if result is None:
            self.abort_run()
            return
        self._bridge.resolve(result)

    def on_select_targets_result(self, selected: list) -> None:
        """Called by SelectTargetsModal on dismiss."""
        self._bridge.resolve(selected)

    # ── Called from worker thread via call_from_thread ────────────────────────

    def append_log(self, text: str, level: str) -> None:
        """Routes log records from TuiLogHandler into the event loop."""
        self.post_message(self.LogLine(text, level))

    # ── Abort ─────────────────────────────────────────────────────────────────

    def abort_run(self) -> None:
        """Abort the run: unblock any waiting prompt and exit the app."""
        self._bridge.abort()
        self.exit()
