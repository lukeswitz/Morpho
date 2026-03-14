from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable


class PromptKind(Enum):
    ACTIVE_GATE = auto()
    SELECT_TARGETS = auto()
    MENU_CHOICE = auto()
    TEXT_INPUT = auto()


@dataclass
class PromptRequest:
    kind: PromptKind
    stage: int
    description: str
    options: Any = None
    default_all: bool = False
    smart_skip_classes: set[str] = field(default_factory=set)
    max_count: int | None = None


class PromptBridge:
    """
    Thread-safe channel between the synchronous stage worker thread
    and the Textual TUI.

    The worker calls request_prompt() which blocks until the TUI calls
    resolve(). Fire-and-forget notifications (stage start, target found)
    use notify_* methods.
    """

    def __init__(self) -> None:
        self._event: threading.Event = threading.Event()
        self._waiting: threading.Event = threading.Event()
        self._response_q: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._app_call: Callable[..., None] | None = None
        self._shell_ready: threading.Event = threading.Event()
        self._shell_popped: threading.Event = threading.Event()
        self._shell_popped.set()
        self._aborted: bool = False

    def set_app_callback(self, call_from_thread: Callable[..., None]) -> None:
        self._app_call = call_from_thread

    def request_prompt(self, req: PromptRequest) -> Any:
        self._event.clear()
        while not self._response_q.empty():
            try:
                self._response_q.get_nowait()
            except queue.Empty:
                break
        self._waiting.set()
        if self._app_call is not None:
            self._app_call(self._notify_prompt, req)
        self._event.wait()
        self._waiting.clear()
        try:
            return self._response_q.get_nowait()
        except queue.Empty:
            return None

    def resolve(self, value: Any) -> None:
        if not self._waiting.is_set():
            return
        try:
            self._response_q.put_nowait(value)
        except queue.Full:
            pass
        self._event.set()

    def abort(self) -> None:
        self._aborted = True
        try:
            self._response_q.put_nowait(None)
        except queue.Full:
            pass
        self._waiting.clear()
        self._event.set()

    def notify_stage_start(self, stage: int, title: str, passive: bool) -> None:
        pass

    def notify_stage_finish(self, stage: int, skipped: bool = False, error: bool = False) -> None:
        pass

    def notify_target_found(self, target: Any) -> None:
        pass

    def notify_scan_status(self, addr: str, stage_label: str) -> None:
        pass

    def notify_finding(self, addr: str, n: int = 1) -> None:
        pass

    def push_gatt_shell(self, addr: str) -> None:
        pass

    def pop_gatt_shell(self) -> None:
        pass

    def write_console_output(self, line: str) -> None:
        pass

    def _notify_prompt(self, req: PromptRequest) -> None:
        pass

    @staticmethod
    def _noop() -> None:
        pass