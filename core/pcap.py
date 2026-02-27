from __future__ import annotations

from pathlib import Path
from typing import Any
import subprocess

import config
from core.logger import get_logger

log = get_logger("pcap")


def pcap_path(engagement_id: str, stage: int, addr: str) -> Path:
    """Return the canonical PCAP path for a stage + address combination.

    Args:
        engagement_id: Short hex engagement ID from main.py.
        stage: Stage number (1–6).
        addr: BD address string like 'AA:BB:CC:DD:EE:FF', or a label
              like 'scan' for stage 1 which has no single device address.

    Returns:
        Absolute Path under config.PCAP_DIR.
    """
    sanitized = addr.lower().replace(":", "_")
    filename = f"{engagement_id}_s{stage}_{sanitized}.pcap"
    return config.PCAP_DIR / filename


def attach_monitor(connector: Any, path: Path) -> dict | None:
    """Store PCAP path for CLI tool capture (Python API has no monitor).

    Args:
        connector: Any WHAD connector (unused, for API compatibility).
        path: Filesystem path for the PCAP output file.

    Returns:
        Dict with pcap_path key, or None on failure.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        log.debug(f"PCAP will be captured to: {path}")
        return {"pcap_path": str(path)}
    except Exception as exc:
        log.warning(f"PCAP path setup failed for {path}: {exc}")
        return None


def detach_monitor(monitor: dict | None) -> None:
    """No-op for Python API (PCAP handled by CLI tools).

    Safe to call with None or dict from attach_monitor().
    """
    if monitor is None:
        return
    pcap_path = monitor.get("pcap_path")
    if pcap_path:
        log.debug(f"PCAP capture complete: {pcap_path}")