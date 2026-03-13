from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable


class PromptKind(Enum):
    ACTIVE_GATE = auto()    # yes/skip/abort — returns bool
    SELECT_TARGETS = auto() # numbered list picker — returns list[Target]
    MENU_CHOICE = auto()    # single-letter menu — returns str
    TEXT_INPUT = auto()     # free-form single line — returns str


@dataclass
class PromptRequest:
    kind: PromptKind
    stage: int
    description: str
    options: Any = None           # list[Target] for SELECT_TARGETS; list[str] for MENU_CHOICE
    default_all: bool = False     # SELECT_TARGETS: treat empty Enter as 'all'
    smart_skip_classes: set[str] = field(default_factory=set)
    max_count: int | None = None  # SELECT_TARGETS: None=multi-pick, 1=single-pick


class PromptBridge:
    """
    Thread-safe channel between the synchronous stage worker thread and the Textual TUI.

    The worker calls request_prompt() which blocks until the TUI calls resolve().
    Fire-and-forget notifications (stage start, target found) use notify_* methods.
    """

    def __init__(self) -> None:
        self._event: threading.Event = threading.Event()
        self._response_q: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._app_call: Callable[..., None] | None = None

    def set_app_callback(self, call_from_thread: Callable[..., None]) -> None:
        """Called by ButterflyApp.on_mount to wire in app.call_from_thread."""
        self._app_call = call_from_thread

    def request_prompt(self, req: PromptRequest) -> Any:
        """
        Called from the worker thread. Blocks until the TUI resolves the prompt.
        Returns the resolved value (bool for ACTIVE_GATE, list for SELECT_TARGETS,
        str for TEXT_INPUT/MENU_CHOICE, or None if app was aborted).
        """
        self._event.clear()
        if self._app_call is not None:
            # _notify_prompt is called inside Textual's event loop
            self._app_call(self._notify_prompt, req)
        self._event.wait()
        try:
            return self._response_q.get_nowait()
        except queue.Empty:
            return None

    def resolve(self, value: Any) -> None:
        """
        Called from Textual's async event loop (main thread) to unblock the worker.
        """
        try:
            self._response_q.put_nowait(value)
        except queue.Full:
            pass  # stale resolve after abort — discard
        self._event.set()

    def abort(self) -> None:
        """
        Called on app exit to unblock any worker thread waiting on request_prompt.
        Puts None into the queue so the worker gets a safe sentinel value.
        """
        try:
            self._response_q.put_nowait(None)
        except queue.Full:
            pass
        self._event.set()

    # --- Fire-and-forget notifications (non-blocking) ---

    def notify_stage_start(self, stage: int, title: str, passive: bool) -> None:
        """Notify TUI that a stage has started. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def notify_stage_finish(self, stage: int, skipped: bool = False, error: bool = False) -> None:
        """Notify TUI that a stage has completed. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def notify_target_found(self, target: Any) -> None:
        """Notify TUI of a newly discovered BLE target. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def notify_scan_status(self, addr: str, stage_label: str) -> None:
        """Notify TUI that a stage has started scanning a specific device. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def notify_finding(self, addr: str, n: int = 1) -> None:
        """Notify TUI of N findings for a device (clears active scan indicator). Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    # --- GATT shell console notifications (fire-and-forget) ---

    def push_gatt_shell(self, addr: str) -> None:
        """Tell TUI to push the Hackers-style GATT shell screen. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def pop_gatt_shell(self) -> None:
        """Tell TUI to pop the GATT shell screen. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    def write_console_output(self, line: str) -> None:
        """Write a line of shell output to the GattShellScreen console. Called from worker thread."""
        pass  # replaced by ButterflyApp._wire_bridge()

    # --- Internal helpers ---

    def _notify_prompt(self, req: PromptRequest) -> None:
        """Runs inside Textual's event loop. Overridden by ButterflyApp after wiring."""
        pass  # ButterflyApp replaces this via set_app_callback

    @staticmethod
    def _noop() -> None:
        pass
