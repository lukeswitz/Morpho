import logging
import sys
from pathlib import Path
from datetime import datetime

LOG_FMT  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
DATE_FMT = "%H:%M:%S"


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
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
