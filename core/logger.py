import logging
import sys
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import Target

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


def stage_banner(stage: int, title: str, passive: bool = True) -> None:
    tag  = "PASSIVE" if passive else "ACTIVE"
    line = "=" * 60
    ts   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{line}")
    print(f"  STAGE {stage} [{tag}]  {title}")
    print(f"  {ts}")
    print(f"{line}\n")


def active_gate(stage: int, description: str) -> bool:
    """
    Blocks execution until analyst explicitly approves an active stage.
    Returns True to proceed, False to skip.
    """
    print(f"\n{'--^----' * 10}")
    print(f"  ACTIVE STAGE {stage} GATE")
    print(f"  {description}")
    print(f"\n{'--^----' * 10}")
    print("\n  This stage will transmit RF packets.")
    print("  Only proceed on equipment you own or have written authorization to test.\n")
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


def select_targets(
    candidates: "list[Target]",
    prompt: str = "Select targets",
    default_all: bool = False,
    smart_skip_classes: "set[str] | None" = None,
) -> "list[Target]":
    """
    Interactive target picker for active stages.

    Displays a numbered list of candidates (sorted by risk descending).
    Operator enters: numbers (1,3,5), 'all', 'smart', or 'skip'.

    smart_skip_classes: device classes to exclude in 'smart' mode.
    Returns the selected subset (empty = skip stage).
    """
    if not candidates:
        return []

    smart_skip_classes = smart_skip_classes or set()

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
        print(
            f"  {i:<4} {_risk_label(t.risk_score):<5} "
            f"{t.bd_address:<20} {t.device_class:<14} "
            f"{t.rssi_avg:>4.0f}  {t.name or '—'}"
        )
    print()

    smart_label = (
        f"smart (skip {', '.join(sorted(smart_skip_classes))})"
        if smart_skip_classes
        else "smart"
    )
    print(
        f"  Enter: numbers (e.g. 1,3), 'all', '{smart_label}', or 'skip'"
    )
    if default_all:
        print("  [Enter] = all")

    while True:
        raw = input("  Selection: ").strip().lower()

        if raw == "" and default_all:
            return sorted_targets

        if raw == "skip":
            return []

        if raw == "all":
            return sorted_targets

        if raw == "smart":
            selected = [
                t for t in sorted_targets
                if t.device_class not in smart_skip_classes
            ]
            if not selected:
                print(
                    f"  No targets remain after smart filter "
                    f"(all are {', '.join(sorted(smart_skip_classes))})."
                )
                continue
            print(f"  Smart selection: {len(selected)} target(s)")
            return selected

        # Parse comma/space separated numbers
        try:
            indices = [int(x.strip()) for x in raw.replace(",", " ").split()]
            if not indices:
                raise ValueError
            selected = []
            for idx in indices:
                if not 1 <= idx <= len(sorted_targets):
                    print(
                        f"  Invalid selection: {idx} "
                        f"(valid range 1–{len(sorted_targets)})"
                    )
                    selected = []
                    break
                selected.append(sorted_targets[idx - 1])
            if selected:
                return selected
        except ValueError:
            pass

        print(
            f"  Enter numbers (1–{len(sorted_targets)}), "
            f"'all', 'smart', or 'skip'."
        )
