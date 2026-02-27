"""
core/pcap.py — PCAP path generation and PcapWriterMonitor lifecycle helpers.

All stages import pcap_path(), attach_monitor(), and detach_monitor() from here.
PCAP failure must never crash a stage — attach_monitor() is exception-safe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def attach_monitor(connector: Any, path: Path) -> Any | None:
    """Attach a PcapWriterMonitor to a WHAD connector before start().

    Catches all exceptions — PCAP failure must never crash a stage.

    Args:
        connector: Any WHAD connector (Scanner, Sniffer, Peripheral, BLE, Central).
        path: Filesystem path for the PCAP output file.

    Returns:
        The monitor instance to pass to detach_monitor(), or None on failure.
    """
    try:
        from whad.monitors import PcapWriterMonitor
        monitor = PcapWriterMonitor(str(path))
        monitor.attach(connector)
        monitor.start()
        log.debug(f"PCAP monitor attached: {path}")
        return monitor
    except Exception as exc:
        log.warning(f"PcapWriterMonitor attach failed for {path}: {exc}")
        return None


def detach_monitor(monitor: Any | None) -> None:
    """Stop and close a PcapWriterMonitor. Safe to call with None.

    Always call in a finally block to ensure the file is flushed.
    """
    if monitor is None:
        return
    try:
        monitor.close()
        log.debug("PCAP monitor closed.")
    except Exception as exc:
        log.warning(f"PcapWriterMonitor close error: {exc}")
