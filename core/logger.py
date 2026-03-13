import logging
import re
import sys
from datetime import datetime
from typing import TYPE_CHECKING

# ── Redaction engine ──────────────────────────────────────────────────────────

_REDACT_ENABLED: bool = False
_name_set: set[str] = set()

_MAC_RE = re.compile(
    r"\b([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
    r":[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\b"
)
_MAC_REDACTED = "XX:XX:XX:XX:XX:XX"


def enable_redact() -> None:
    """Enable redaction of MACs and device names in all output.

    NOTE on log filter placement: Python's logging.root.addFilter() only runs
    for records originating at the root logger, NOT for records from named
    loggers that propagate. Redaction of TUI log-pane output is therefore done
    inside TuiLogHandler.emit() which calls redact_str() directly.  Plain-mode
    StreamHandlers get a filter installed here as a best-effort fallback.
    """
    global _REDACT_ENABLED
    _REDACT_ENABLED = True
    _f = _RedactFilter()
    # Best-effort: attach to every handler currently on root and named loggers
    for handler in logging.root.handlers:
        if not any(isinstance(flt, _RedactFilter) for flt in handler.filters):
            handler.addFilter(_f)
    for lgr in logging.Logger.manager.loggerDict.values():
        if isinstance(lgr, logging.Logger):
            for handler in lgr.handlers:
                if not any(isinstance(flt, _RedactFilter) for flt in handler.filters):
                    handler.addFilter(_f)


def disable_redact() -> None:
    """Disable redaction. Future log records and table rows show real values."""
    global _REDACT_ENABLED
    _REDACT_ENABLED = False
    # Remove RedactFilters from all handlers
    for handler in logging.root.handlers:
        handler.filters = [f for f in handler.filters if not isinstance(f, _RedactFilter)]
    for lgr in logging.Logger.manager.loggerDict.values():
        if isinstance(lgr, logging.Logger):
            for handler in lgr.handlers:
                handler.filters = [
                    f for f in handler.filters if not isinstance(f, _RedactFilter)
                ]


def register_redact_name(name: str) -> None:
    """Register a device name to be redacted from output."""
    if name and len(name) > 2:
        _name_set.add(name)


def redact_str(text: str) -> str:
    """Replace all BD addresses and registered names in *text*."""
    if not _REDACT_ENABLED:
        return text
    result = _MAC_RE.sub(_MAC_REDACTED, text)
    for name in sorted(_name_set, key=len, reverse=True):
        result = result.replace(name, "[REDACTED]")
    return result


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_str(str(record.msg))
        record.args = None  # prevent double-format of args after msg substitution
        return True


def _drain_stdin() -> None:
    """Discard any buffered stdin bytes before an interactive prompt.

    Prevents stale newlines (e.g. from SSH terminal buffering) from being
    consumed as empty inputs and causing repeated blank-prompt loops.
    """
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass

if TYPE_CHECKING:
    from core.models import Target
    from tui.bridge import PromptBridge  # noqa: F401  (type-check only)

# TUI bridge — set by install_tui(); None in plain-text / --plain mode
_bridge: "PromptBridge | None" = None
# Stage currently in progress (for auto-finish on next stage_banner call)
_current_stage: int | None = None

LOG_FMT  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
DATE_FMT = "%H:%M:%S"


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
    logger.addHandler(ch)
    return logger


def install_tui(bridge: "PromptBridge") -> None:
    """Wire a PromptBridge into this module. Called by run_stages() at startup."""
    global _bridge
    _bridge = bridge


def prompt_line(msg: str) -> str:
    """Drop-in replacement for raw input() calls in stage files and main.py.

    In TUI mode: blocks worker thread via bridge until operator responds in modal.
    In plain mode: falls back to stdin input() identical to before.
    """
    if _bridge is not None:
        from tui.bridge import PromptRequest, PromptKind
        result = _bridge.request_prompt(PromptRequest(
            kind=PromptKind.TEXT_INPUT,
            stage=0,
            description=msg,
        ))
        return result if result is not None else ""
    _drain_stdin()
    return input(msg)


def stage_banner(stage: int, title: str, passive: bool = True) -> None:
    global _current_stage
    if _bridge is not None:
        # Auto-complete the previous stage when the next one starts
        if _current_stage is not None:
            _bridge.notify_stage_finish(_current_stage, skipped=False, error=False)
        _current_stage = stage
        _bridge.notify_stage_start(stage, title, passive)
        return
    tag  = "PASSIVE" if passive else "ACTIVE"
    line = "=" * 60
    ts   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{line}")
    print(f"  STAGE {stage} [{tag}]  {title}")
    print(f"  {ts}")
    print(f"{line}\n")


def stage_finished(stage: int, skipped: bool = False, error: bool = False) -> None:
    """Explicitly mark a stage done."""
    global _current_stage
    if _bridge is not None:
        _bridge.notify_stage_finish(stage, skipped=skipped, error=error)
        if _current_stage == stage:
            _current_stage = None


def finish_current_stage(error: bool = False) -> None:
    """Close whatever stage is currently running. Call from finally/except blocks."""
    global _current_stage
    if _bridge is not None and _current_stage is not None:
        _bridge.notify_stage_finish(_current_stage, skipped=False, error=error)
        _current_stage = None


def active_gate(stage: int, description: str) -> bool:
    """
    Blocks execution until analyst explicitly approves an active stage.
    Returns True to proceed, False to skip.
    """
    if _bridge is not None:
        from tui.bridge import PromptRequest, PromptKind
        result = _bridge.request_prompt(PromptRequest(
            kind=PromptKind.ACTIVE_GATE,
            stage=stage,
            description=description,
        ))
        # result is True (proceed), False (skip), or None (aborted)
        if result is None or result is False:
            return False
        return bool(result)
    print(f"\n{'--^----' * 10}")
    print(f"  ACTIVE STAGE {stage} GATE")
    print(f"  {description}")
    print(f"{'-------' * 10}")
    print("\n  This stage will transmit RF packets.")
    print("  Only proceed on equipment you own or have written authorization to test.\n")
    _drain_stdin()
    while True:
        resp = input("  Proceed? [yes/skip/abort]: ").strip().lower()
        if resp == "yes":
            return True
        if resp == "skip":
            print(f"  Stage {stage} skipped.")
            return False
        if resp == "abort":
            print("  Aborting run.")
            sys.exit(0)
        print("  Enter 'yes', 'skip', or 'abort'.")


def scan_status_update(addr: str, stage_label: str) -> None:
    """Mark a target device as currently being scanned by stage_label (e.g. 'S05').

    Shows a spinning indicator in the RESULTS column of the TUI target table.
    No-op in plain-text mode.
    """
    if _bridge is not None:
        _bridge.notify_scan_status(addr, stage_label)


def add_finding(addr: str, n: int = 1) -> None:
    """Record N findings for a device; clears the active scan indicator.

    Increments the RESULTS counter in the TUI target table.
    No-op in plain-text mode.
    """
    if _bridge is not None:
        _bridge.notify_finding(addr, n)


def shell_write(text: str) -> None:
    """Write a line of output to the GATT shell console.

    In TUI mode: routes to the GattShellScreen via bridge.
    In plain mode: falls back to print().
    """
    text = redact_str(text)
    if _bridge is not None:
        _bridge.write_console_output(text)
        return
    print(text)


def push_shell(addr: str) -> None:
    """Signal TUI to push the GATT shell screen for the given address."""
    if _bridge is not None:
        _bridge.push_gatt_shell(addr)


def pop_shell() -> None:
    """Signal TUI to pop the GATT shell screen."""
    if _bridge is not None:
        _bridge.pop_gatt_shell()


def select_targets(
    candidates: "list[Target]",
    prompt: str = "Select targets",
    default_all: bool = False,
    smart_skip_classes: "set[str] | None" = None,
    max_count: "int | None" = None,
) -> "list[Target]":
    """
    Interactive target picker for active stages.

    Displays a numbered list of candidates (sorted by risk descending).

    Multi-pick mode (max_count=None):
      Operator enters: numbers (1,3,5), 'all', 'smart', or 'skip'.
      'smart' returns all non-skipped targets.

    Single-pick mode (max_count=1):
      Operator enters: one number, 'smart' (auto-picks highest-risk non-skipped),
      or 'skip'. 'all' and multi-number inputs are rejected.

    smart_skip_classes: device classes to exclude in 'smart' mode.
    Returns the selected subset (empty list = skip stage).
    """
    if not candidates:
        return []

    if _bridge is not None:
        from tui.bridge import PromptRequest, PromptKind
        result = _bridge.request_prompt(PromptRequest(
            kind=PromptKind.SELECT_TARGETS,
            stage=0,
            description=prompt,
            options=candidates,
            default_all=default_all,
            smart_skip_classes=smart_skip_classes or set(),
            max_count=max_count,
        ))
        # result is a list[Target] from the modal, or None if aborted
        return result if result is not None else []

    smart_skip_classes = smart_skip_classes or set()
    single_pick = max_count == 1

    _RISK = {
        range(8, 11): "CRIT",
        range(6, 8):  "HIGH",
        range(4, 6):  "MED ",
        range(2, 4):  "LOW ",
        range(0, 2):  "INFO",
    }

    def _risk_label(score: int) -> str:
        for r, lbl in _RISK.items():
            if score in r:
                return lbl
        return "INFO"

    sorted_targets = sorted(candidates, key=lambda t: t.risk_score, reverse=True)

    print(f"\n  {prompt} — {len(sorted_targets)} candidates:")
    print(
        f"  {'#':<4} {'RISK':<5} {'ADDRESS':<20} {'CLASS':<14} "
        f"{'RSSI':>5}  NAME"
    )
    print("  " + "─" * 72)
    for i, t in enumerate(sorted_targets, 1):
        name = (t.name or "—")[:28]
        print(
            f"  {i:<4} {_risk_label(t.risk_score):<5} "
            f"{t.bd_address:<20} {t.device_class:<14} "
            f"{t.rssi_avg:>4.0f}  {name}"
        )
    print()

    if single_pick:
        skip_desc = (
            f"auto-picks highest-risk non-{'/'.join(sorted(smart_skip_classes))}"
            if smart_skip_classes
            else "auto-picks highest-risk"
        )
        print(f"  Enter: one number (1–{len(sorted_targets)}), 'smart' ({skip_desc}), or 'skip'")
    else:
        smart_label = (
            f"smart (skip {', '.join(sorted(smart_skip_classes))})"
            if smart_skip_classes
            else "smart"
        )
        print(f"  Enter: numbers (e.g. 1,3), 'all', '{smart_label}', or 'skip'")
        if default_all:
            print("  [Enter] = all")

    _drain_stdin()
    while True:
        _inp = input("  Selection: ").lower()
        # Strip non-printable/control chars that some terminals inject
        # (escape sequences, null bytes, etc.) to prevent false comparison misses
        raw = "".join(c for c in _inp if c.isalnum() or c in " ,").strip()

        if raw == "" and default_all and not single_pick:
            return sorted_targets

        if raw == "":
            # Silently re-prompt on empty input (accidental Enter / buffered newline)
            continue

        if raw == "skip":
            return []

        if raw == "smart":
            filtered = [
                t for t in sorted_targets
                if t.device_class not in smart_skip_classes
            ]
            if not filtered:
                print(
                    f"  No non-{'/'.join(sorted(smart_skip_classes))} targets found — "
                    "skipping stage."
                )
                return []
            if single_pick:
                chosen = filtered[0]
                print(
                    f"  Auto-selected: [{chosen.bd_address}] "
                    f"{chosen.name or chosen.device_class} (risk={chosen.risk_score})"
                )
                return [chosen]
            print(f"  Smart selection: {len(filtered)} target(s)")
            return filtered

        if raw == "all":
            if single_pick:
                print("  Enter a single number to select one target, or 'skip'.")
                continue
            return sorted_targets

        # Parse numbers
        try:
            indices = [int(x.strip()) for x in raw.replace(",", " ").split()]
            if not indices:
                raise ValueError
            if single_pick and len(indices) > 1:
                print("  This stage requires exactly one target — enter a single number.")
                continue
            selected = []
            for idx in indices:
                if not 1 <= idx <= len(sorted_targets):
                    print(f"  Invalid: {idx} (valid range 1–{len(sorted_targets)})")
                    selected = []
                    break
                selected.append(sorted_targets[idx - 1])
            if selected:
                return selected
        except ValueError:
            pass

        if single_pick:
            print(f"  Enter a number (1–{len(sorted_targets)}), 'smart', or 'skip'.")
        else:
            print(
                f"  Enter numbers (1–{len(sorted_targets)}), "
                f"'all', 'smart', or 'skip'."
            )
