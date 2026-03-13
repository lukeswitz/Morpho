from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tui.app import ButterflyApp

class TuiLogHandler(logging.Handler):
    """
    Routes Python log records to Textual's RichLog widget via call_from_thread.
    """

    def __init__(self, app: "ButterflyApp") -> None:
        super().__init__()
        self._app = app

    @staticmethod
    def _is_spam(record: logging.LogRecord) -> bool:
        """Return True for high-volume per-packet/per-device noise below WARNING."""
        if record.levelno >= logging.WARNING:
            return False
        # All internal WHAD machinery — per-packet, per-PDU, lock traces, etc.
        if record.name.startswith("whad."):
            return True
        # s14_esb raw ESB packet noise — target table already shows results.
        if record.name == "s14_esb":
            return True
        return False

    def emit(self, record: logging.LogRecord) -> None:
        if self._is_spam(record):
            return
        try:
            msg = self.format(record)
            # Collapse embedded newlines so multi-line records don't render as
            # separate unformatted lines in the RichLog.
            msg = msg.replace("\n", " | ")
            # Apply redaction here — logging.root.addFilter() only covers records
            # that originate at root; named loggers that propagate bypass it.
            from core.logger import redact_str
            msg = redact_str(msg)
            level = record.levelname
            self._app.call_from_thread(self._app.append_log, msg, level)
        except Exception:
            pass  # silently drop — TUI may not be mounted yet
