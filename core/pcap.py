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
        engagement_id: Short hex engagement ID from morpho.py.
        stage: Stage number (1–6).
        addr: BD address string like 'AA:BB:CC:DD:EE:FF', or a label
              like 'scan' for stage 1 which has no single device address.

    Returns:
        Absolute Path under config.PCAP_DIR.
    """
    sanitized = addr.lower().replace(":", "_")
    filename = f"{engagement_id}_s{stage}_{sanitized}.pcap"
    return config.PCAP_DIR / filename


def attach_monitor(connector: Any, path: Path) -> Any:
    """Attach a PCAP writer monitor to a WHAD connector.

    Tries whad's PcapWriterMonitor first for real packet capture.
    Falls back to a path-storage stub when unavailable (CLI stages).

    Args:
        connector: Any WHAD connector (Central, Peripheral, Sniffer …).
        path: Filesystem path for the PCAP output file.

    Returns:
        PcapWriterMonitor instance on success, stub dict on fallback,
        or None if even the directory cannot be created.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        log.warning(f"PCAP path setup failed for {path}: {exc}")
        return None

    try:
        from whad.device.connector.monitors import PcapWriterMonitor
        monitor = PcapWriterMonitor(str(path))
        monitor.attach(connector)
        monitor.start()
        log.debug(f"PcapWriterMonitor active → {path}")
        return monitor
    except Exception as exc:
        log.debug(f"PcapWriterMonitor unavailable ({exc}); using path stub")

    # Fallback: stub dict — CLI tools will write the PCAP directly.
    log.debug(f"PCAP will be captured to: {path}")
    return {"pcap_path": str(path)}


def detach_monitor(monitor: Any) -> None:
    """Detach and stop a monitor returned by attach_monitor().

    Safe to call with None, a stub dict, or a real PcapWriterMonitor.
    """
    if monitor is None:
        return
    if isinstance(monitor, dict):
        p = monitor.get("pcap_path")
        if p:
            log.debug(f"PCAP capture complete: {p}")
        return
    # Real PcapWriterMonitor object.
    try:
        monitor.detach()
        log.debug("PcapWriterMonitor detached.")
    except Exception as exc:
        log.debug(f"Monitor detach: {exc}")