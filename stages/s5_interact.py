"""
Stage 5 — Direct Interaction / GATT Enumeration

Strategy: use the WHAD CLI tools (wble-connect | wble-central profile) so the
battle-tested CLI handles the full connection state machine.  The Python
WhadDevice is closed before each CLI run and recreated afterward.

Fallback: if the CLI binaries are not in PATH, falls back to the Python API.
"""

import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from whad.ble.exceptions import (
    ConnectionLostException,
    PeripheralNotFound,
    HookReturnAccessDenied,
    HookReturnAuthentRequired,
    HookReturnAuthorRequired,
    HookReturnNotFound,
    HookReturnGattError,
    InvalidHandleValueException,
    NotConnected,
)

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Target, Finding, GattCharacteristic
from core.db import insert_finding
from core.logger import get_logger, prompt_line, shell_write, push_shell, pop_shell
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s5_interact")

CONNECT_TIMEOUT = 15
GATT_DISCOVER_TIMEOUT = 20   # seconds for discover() call
CLI_TIMEOUT = 45             # seconds for the full wble-connect | wble-central run

# Standard GATT characteristic UUID (int) → human-readable name
UUID_NAMES: dict[int, str] = {
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A04: "Preferred Connection Parameters",
    0x2A05: "Service Changed",
    0x2A06: "Alert Level",
    0x2A19: "Battery Level",
    0x2A1C: "Temperature Measurement",
    0x2A1D: "Temperature Type",
    0x2A1E: "Intermediate Temperature",
    0x2A24: "Model Number",
    0x2A25: "Serial Number",
    0x2A26: "Firmware Revision",
    0x2A27: "Hardware Revision",
    0x2A28: "Software Revision",
    0x2A29: "Manufacturer Name",
    0x2A2A: "IEEE Regulatory",
    0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location",
    0x2A39: "Heart Rate Control Point",
    0x2A6D: "Pressure",
    0x2A6E: "Temperature (Environmental)",
    0x2A6F: "Humidity",
}

# Properties bitmask
PROP_READ       = 0x02
PROP_WRITE_NR   = 0x04
PROP_WRITE      = 0x08
PROP_NOTIFY     = 0x10
PROP_INDICATE   = 0x20

NOTIFY_HARVEST_SECS = 15   # max wall-clock time to listen for notifications
NOTIFY_SILENCE_SECS = 4    # exit early after this many seconds with no new notifications


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    cancel: Callable[[], bool] | None = None,
) -> tuple[list[int], list[dict]]:
    """Returns (writable_handles, full_profile) for S5→S7/S8 handoff."""
    if _cli_available():
        return _run_cli(dongle, target, engagement_id, cancel=cancel)
    return _run_python_api(dongle, target, engagement_id)


# ---------------------------------------------------------------------------
# CLI approach: wble-connect | wble-central profile
# ---------------------------------------------------------------------------

def _cli_available() -> bool:
    return (
        shutil.which("wble-connect") is not None
        and shutil.which("wble-central") is not None
    )


def _run_cli(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    cancel: Callable[[], bool] | None = None,
) -> tuple[list[int], list[dict]]:
    addr = target.bd_address
    is_random = target.address_type != "public"
    rand_flag = "-r" if is_random else ""

    log.info(
        f"[CLI] Connecting to {addr} "
        f"({'random' if is_random else 'public'}) ..."
    )

    dongle.device.close()
    time.sleep(1.0)

    cmd = (
        f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
        f"| wble-central profile"
    )
    log.debug(f"Running: {cmd}")

    stdout = ""
    stderr = ""
    returncode = -1

    cancelled = False
    try:
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        t_out = threading.Thread(
            target=lambda: stdout_buf.append(proc.stdout.read()), daemon=True
        )
        t_err = threading.Thread(
            target=lambda: stderr_buf.append(proc.stderr.read()), daemon=True
        )
        t_out.start()
        t_err.start()
        deadline = time.time() + CLI_TIMEOUT
        while proc.poll() is None:
            time.sleep(0.3)
            if cancel is not None and cancel():
                proc.kill()
                proc.wait(timeout=2.0)
                t_out.join(1.0)
                t_err.join(1.0)
                cancelled = True
                break
            if time.time() >= deadline:
                proc.kill()
                proc.wait(timeout=2.0)
                log.warning(f"[CLI] Timeout reaching {addr} after {CLI_TIMEOUT}s")
                break
        t_out.join()
        t_err.join()
        stdout = stdout_buf[0] if stdout_buf else ""
        stderr = stderr_buf[0] if stderr_buf else ""
        returncode = proc.returncode if proc.returncode is not None else -1
    except Exception as exc:
        log.error(
            f"[CLI] Subprocess error for {addr}: {type(exc).__name__}: {exc}"
        )
    finally:
        _reopen_dongle(dongle)

    if cancelled:
        return [], []

    if not stdout.strip():
        log.warning(
            f"[CLI] No profile output for {addr} "
            f"(exit={returncode}): {stderr.strip()[:120]}"
        )
        return [], []

    log.debug(f"[CLI] Raw profile stdout for {addr}: {stdout[:500]!r}")

    chars, unauth_readable, unauth_writable, device_info = _parse_cli_profile(
        stdout
    )

    if not chars:
        log.info(f"[CLI] No characteristics parsed on {addr} — check debug log for raw output.")
        return [], []

    profile = [_char_to_dict(c) for c in chars]

    if not unauth_readable and not unauth_writable:
        log.info(
            f"[CLI] {addr}: {len(chars)} characteristic(s) found, "
            "all require authentication — no finding."
        )
        return (
            [c.value_handle for c in chars
             if "write" in c.properties or "write_no_resp" in c.properties],
            profile,
        )

    _record_finding(
        addr, target, engagement_id,
        chars, unauth_readable, unauth_writable, device_info,
    )
    _print_summary(
        addr, target, chars, unauth_readable, unauth_writable, device_info,
    )
    return [c.value_handle for c in unauth_writable], profile


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the underlying WhadDevice, polling every 0.5s up to 15s."""
    import time as _time
    deadline = _time.time() + 15.0
    attempt = 0
    last_exc: Exception | None = None
    while _time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            if attempt > 0:
                log.debug(f"Reopen succeeded after {attempt * 0.5:.1f}s")
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            _time.sleep(0.5)
    log.warning(
        f"Could not reopen WHAD device after 15s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


def _parse_cli_profile(
    output: str,
) -> tuple[
    list[GattCharacteristic],
    list[GattCharacteristic],
    list[GattCharacteristic],
    dict[str, str],
]:
    """
    Parse `wble-central profile` text output into GattCharacteristic objects.

    Actual wble-central profile output format (ANSI codes stripped):
        Service Generic Access (0x1800) (handle 1 to 7)
          Device Name (0x2a00) R, handle 3, value handle: 4
            Value: 4163657200
          Battery Level (0x2a19) RW, handle 9, value handle: 10
        ...

    Rights letters: R=read, W=write or write_no_resp, N=notify, I=indicate.
    Both Write and Write_Without_Response display as 'W' — we add both.
    """
    # Strip ANSI/prompt_toolkit escape codes
    ansi_re = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKLMSTfnsulh]")
    clean = ansi_re.sub("", output)

    chars: list[GattCharacteristic] = []
    unauth_readable: list[GattCharacteristic] = []
    unauth_writable: list[GattCharacteristic] = []
    device_info: dict[str, str] = {}

    current_char: GattCharacteristic | None = None

    for raw_line in clean.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Characteristic lines always contain "value handle: N"
        vh_match = re.search(r"\bvalue handle:\s*(\d+)", line, re.I)
        h_match = re.search(r"\bhandle\s+(\d+)", line, re.I)

        if vh_match or h_match:
            # Skip service-level lines ("Service ... (handle N to N)")
            if re.match(r"service\b", line, re.I):
                current_char = None
                continue

            value_handle = int(vh_match.group(1)) if vh_match else 0
            handle = int(h_match.group(1)) if h_match else value_handle

            # Extract UUID from "(0xNNNN)" or full 128-bit UUID in the line
            uuid_str = f"ATTR{value_handle:04X}"
            uuid16_m = re.search(r"\(0x([0-9A-Fa-f]{4,8})\)", line)
            uuid128_m = re.search(
                r"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
                r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
                line,
            )
            if uuid16_m:
                uuid_str = uuid16_m.group(1).upper()
            elif uuid128_m:
                uuid_str = uuid128_m.group(1).upper()

            # Rights section: text before ", handle" minus the name portion
            # Name ends at last ')' or at start of rights letters
            prefix = re.split(r",\s*handle\s+\d+", line, maxsplit=1)[0]
            props = _extract_props_from_rights(prefix)

            current_char = GattCharacteristic(
                uuid=uuid_str,
                handle=handle,
                value_handle=value_handle,
                properties=props,
            )
            chars.append(current_char)
            continue

        # Value line: "Value: <hex>"
        if current_char and re.match(r"value\s*:", line, re.I):
            raw_val = line.split(":", 1)[1].strip()
            _decode_char_value(current_char, raw_val)
            uuid_int = _uuid_to_int(current_char.uuid)
            if uuid_int in UUID_NAMES and current_char.value_text:
                device_info[UUID_NAMES[uuid_int]] = current_char.value_text
            if "read" in current_char.properties:
                current_char.requires_auth = False
                unauth_readable.append(current_char)
            continue

        # Auth-required line
        if current_char and re.search(
            r"(authentication|insufficient|auth required|not permitted)",
            line, re.I,
        ):
            current_char.requires_auth = True

    # Write access: writable chars not confirmed to require auth.
    # Write-only chars have no value line so value_hex is None — include them.
    for char in chars:
        if (
            ("write" in char.properties or "write_no_resp" in char.properties)
            and not char.requires_auth
            and char not in unauth_writable
        ):
            unauth_writable.append(char)

    return chars, unauth_readable, unauth_writable, device_info


def _extract_props_from_rights(prefix: str) -> list[str]:
    """Extract property list from the characteristic line prefix (before ', handle N').

    wble-central shows rights as single letters after the characteristic name:
      R = read, W = write or write_without_response, N = notify, I = indicate
    Both Write and Write_Without_Response display as 'W', so we add both.
    """
    # Rights letters appear after the last ')' (end of name) or at end of prefix
    after_name = re.sub(r".*\)", "", prefix).strip()
    if not after_name:
        after_name = prefix

    props: list[str] = []
    letters = set(after_name.upper().replace(" ", ""))
    if "R" in letters:
        props.append("read")
    if "W" in letters:
        # Can't distinguish write vs write_no_resp from single-letter display
        props.append("write")
        props.append("write_no_resp")
    if "N" in letters:
        props.append("notify")
    if "I" in letters:
        props.append("indicate")
    return props


# ---------------------------------------------------------------------------
# Python API fallback
# ---------------------------------------------------------------------------

def _run_python_api(dongle: WhadDongle, target: Target, engagement_id: str) -> tuple[list[int], list[dict]]:
    addr = target.bd_address
    is_random = target.address_type != "public"

    log.info(
        f"Connecting to {addr} "
        f"({'random' if is_random else 'public'}) ..."
    )

    _monitor = None
    _pcap_file = pcap_path(engagement_id, 5, addr)
    central = dongle.central()
    _monitor = attach_monitor(central, _pcap_file)
    periph_dev = None

    dongle.log_whad_connect(addr, is_random, CONNECT_TIMEOUT)
    try:
        periph_dev = central.connect(
            addr, random=is_random, timeout=CONNECT_TIMEOUT,
        )
    except ConnectionLostException:
        log.warning(f"Connection to {addr} lost during setup.")
        detach_monitor(_monitor)
        return [], []
    except Exception as exc:
        log.error(f"Failed to connect to {addr}: {type(exc).__name__}: {exc}")
        detach_monitor(_monitor)
        return [], []

    if periph_dev is None:
        log.warning(f"Could not connect to {addr} (timeout).")
        detach_monitor(_monitor)
        return [], []

    try:
        ver = central.version(synchronous=True)
        if ver is not None:
            log.info(f"[S5] Remote BLE version: {ver}")
    except Exception as exc:
        log.debug(f"[S5] central.version() failed: {exc}")

    log.info(f"Connected to {addr}. Discovering GATT profile...")

    _negotiated_mtu: int | None = None
    try:
        central.set_mtu(247)
        _negotiated_mtu = getattr(central, "mtu", None) or getattr(
            central, "get_mtu", lambda: None
        )()
        log.info(f"[S5] MTU negotiated: {_negotiated_mtu}")
    except Exception as exc:
        log.debug(f"[S5] MTU negotiation (non-critical): {exc}")

    if not _discover_with_timeout(periph_dev, addr):
        try:
            periph_dev.disconnect()
        except Exception:
            pass
        return [], []

    try:
        profile_json = central.export_profile()
        log.debug(f"[S5] GATT profile exported ({len(profile_json)} chars)")
    except Exception as exc:
        log.debug(f"[S5] export_profile() not available: {exc}")

    log.info("Enumerating characteristics...")

    chars: list[GattCharacteristic] = []
    unauth_readable: list[GattCharacteristic] = []
    unauth_writable: list[GattCharacteristic] = []
    device_info: dict[str, str] = {}
    if _negotiated_mtu:
        device_info["negotiated_mtu"] = str(_negotiated_mtu)

    try:
        for service in dongle.periph_services(periph_dev):
            for char in dongle.periph_chars(service):
                char_uuid = str(char.uuid)
                handle = char.handle
                value_handle = char.value_handle
                props = _extract_properties(char)

                gc = GattCharacteristic(
                    uuid=char_uuid,
                    handle=handle,
                    value_handle=value_handle,
                    properties=props,
                )

                if "read" in props:
                    try:
                        raw_val = periph_dev.read(value_handle)
                        dongle.log_whad_read(value_handle, raw_val)
                        if raw_val is not None:
                            _decode_char_value(gc, raw_val.hex())
                            gc.requires_auth = False
                            unauth_readable.append(gc)
                            uuid_int = _uuid_to_int(char_uuid)
                            if uuid_int in UUID_NAMES and gc.value_text:
                                device_info[UUID_NAMES[uuid_int]] = gc.value_text
                    except PeripheralNotFound:
                        log.warning(f"[S5] Device lost during enumeration: {addr}")
                        break
                    except NotConnected:
                        log.warning(f"[S5] Not connected during read: h=0x{value_handle:04X} — disconnecting")
                        break
                    except HookReturnAccessDenied:
                        log.debug(f"[S5] Access denied: h=0x{value_handle:04X} {char_uuid}")
                    except HookReturnNotFound:
                        log.debug(f"[S5] Attribute not found: h=0x{value_handle:04X} {char_uuid}")
                    except HookReturnAuthentRequired:
                        gc.requires_auth = True
                        log.info(
                            f"[S5] Auth required for read: h=0x{value_handle:04X} {char_uuid}"
                        )
                    except HookReturnAuthorRequired:
                        gc.requires_auth = True
                        log.info(
                            f"[S5] Authorization required for read: h=0x{value_handle:04X} {char_uuid}"
                        )
                    except HookReturnGattError as exc:
                        log.debug(
                            f"  {char_uuid} h={value_handle} "
                            f"READ GattError: {exc}"
                        )
                    except Exception as exc:
                        _s = str(exc).lower()
                        if "authentication" in _s or "authorization" in _s or "encryption" in _s:
                            gc.requires_auth = True
                            log.info(
                                f"[S5] Auth required for read: h=0x{value_handle:04X} {char_uuid}"
                            )
                        else:
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"READ {type(exc).__name__}: {exc}"
                            )

                if "write" in props or "write_no_resp" in props:
                    try:
                        no_resp = "write_no_resp" in props
                        dongle.log_whad_write(value_handle, b"\x00", no_resp)
                        if no_resp:
                            periph_dev.write_command(value_handle, b"\x00")
                        else:
                            periph_dev.write(value_handle, b"\x00")
                        gc.requires_enc = False
                        if gc not in unauth_writable:
                            unauth_writable.append(gc)
                    except PeripheralNotFound:
                        log.warning(f"[S5] Device lost during write scan: {addr}")
                        break
                    except NotConnected:
                        log.warning(f"[S5] Not connected during write: h=0x{value_handle:04X} — disconnecting")
                        break
                    except HookReturnAccessDenied:
                        log.debug(f"[S5] Write access denied: h=0x{value_handle:04X} {char_uuid}")
                    except HookReturnNotFound:
                        log.debug(f"[S5] Attribute not found (write): h=0x{value_handle:04X} {char_uuid}")
                    except InvalidHandleValueException:
                        log.debug(f"[S5] Invalid handle value (write): h=0x{value_handle:04X} {char_uuid}")
                    except HookReturnAuthentRequired:
                        gc.requires_enc = True
                        log.info(
                            f"[S5] Auth required for write: h=0x{value_handle:04X} {char_uuid}"
                        )
                    except HookReturnAuthorRequired:
                        gc.requires_enc = True
                        log.info(
                            f"[S5] Authorization required for write: h=0x{value_handle:04X} {char_uuid}"
                        )
                    except HookReturnGattError as exc:
                        log.debug(
                            f"  {char_uuid} h={value_handle} "
                            f"WRITE GattError: {exc}"
                        )
                    except Exception as exc:
                        _s = str(exc).lower()
                        if "authentication" in _s or "authorization" in _s or "encryption" in _s:
                            gc.requires_enc = True
                            log.info(
                                f"[S5] Auth required for write: h=0x{value_handle:04X} {char_uuid}"
                            )
                        else:
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"WRITE {type(exc).__name__}: {exc}"
                            )

                try:
                    desc = char.get_descriptor(0x2901)
                    if desc is not None:
                        raw_desc = desc.read()
                        if raw_desc:
                            gc.user_description = raw_desc.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

                if periph_dev and not central.is_connected():
                    log.debug("[S5] central.is_connected() returned False — treating as disconnected")
                    break

                chars.append(gc)

    except ConnectionLostException:
        log.warning(f"Connection to {addr} lost during enumeration.")
    except Exception as exc:
        log.error(
            f"GATT enumeration error on {addr}: {type(exc).__name__}: {exc}"
        )

    auth_blocked = [c for c in chars if c.requires_auth or c.requires_enc]
    if auth_blocked and periph_dev is not None:
        _try_inline_auth_escalation(
            periph_dev, auth_blocked, addr, engagement_id, target,
        )

    notifications: list[dict] = []
    notify_chars = [
        c for c in chars
        if "notify" in c.properties or "indicate" in c.properties
    ]
    if notify_chars and periph_dev is not None:
        notifications = _harvest_notifications(periph_dev, notify_chars, addr)

    if periph_dev is not None:
        _query_standard_services(periph_dev, device_info, addr)

    try:
        if periph_dev is not None:
            periph_dev.disconnect()
    except Exception:
        pass
    finally:
        detach_monitor(_monitor)

    if not chars:
        log.info(f"No characteristics discovered on {addr}.")
        return [], []

    profile = [_char_to_dict(c) for c in chars]

    import json as _json
    _profile_path = (
        config.REPORT_DIR
        / f"s5_profile_{addr.replace(':', '')}_{engagement_id}.json"
    )
    try:
        _profile_path.write_text(_json.dumps(profile, indent=2))
        log.info(f"[S5] Profile saved: {_profile_path}")
    except Exception as exc:
        log.debug(f"[S5] Profile save: {exc}")

    if not unauth_readable and not unauth_writable:
        log.info(
            f"{addr}: {len(chars)} characteristic(s) found, "
            "all require authentication — no finding."
        )
        return (
            [c.value_handle for c in chars
             if "write" in c.properties or "write_no_resp" in c.properties],
            profile,
        )

    _record_finding(
        addr, target, engagement_id,
        chars, unauth_readable, unauth_writable, device_info, notifications,
        pcap_path=str(_pcap_file),
    )
    _print_summary(
        addr, target, chars, unauth_readable, unauth_writable, device_info,
        notifications,
    )
    return [c.value_handle for c in unauth_writable], profile


def _try_inline_auth_escalation(
    periph_dev,
    auth_blocked: list[GattCharacteristic],
    addr: str,
    engagement_id: str,
    target: Target,
) -> None:
    """Attempt LESC Just Works pairing on the open connection when auth-blocked chars exist.

    If pairing succeeds, retries blocked reads/writes. Records
    gatt_auth_escalation_success (high) if any previously-locked char becomes accessible.
    WHAD's pairing() can block indefinitely — uses a daemon thread with a hard timeout.
    """
    try:
        from whad.ble.stack.smp.parameters import Pairing as _Pairing
    except ImportError:
        log.debug("[S5] SMP Pairing not importable — inline auth escalation skipped")
        return

    log.info(
        f"[S5] {len(auth_blocked)} auth-blocked char(s) on {addr} — "
        "attempting inline LESC Just Works pairing ..."
    )

    pairing_result: list[bool] = [False]
    pairing_done = threading.Event()

    def _pair() -> None:
        try:
            pairing_result[0] = periph_dev.pairing(
                pairing=_Pairing(lesc=True, mitm=False, bonding=False)
            )
        except Exception as exc:
            log.debug(f"[S5] Inline pairing exception: {type(exc).__name__}: {exc}")
        finally:
            pairing_done.set()

    t = threading.Thread(target=_pair, daemon=True)
    t.start()
    pairing_done.wait(timeout=15.0)

    if not pairing_result[0]:
        log.info("[S5] Inline LESC Just Works pairing rejected or timed out.")
        return

    log.info("[S5] Inline LESC pairing accepted — retrying blocked characteristics ...")
    unlocked_read: list[dict] = []
    unlocked_write: list[dict] = []

    for gc in auth_blocked:
        if gc.requires_auth and "read" in gc.properties:
            try:
                raw_val = periph_dev.read(gc.value_handle)
                if raw_val is not None:
                    _decode_char_value(gc, raw_val.hex())
                    gc.requires_auth = False
                    unlocked_read.append({
                        "uuid": gc.uuid,
                        "uuid_name": UUID_NAMES.get(_uuid_to_int(gc.uuid), ""),
                        "handle": gc.value_handle,
                        "value_hex": gc.value_hex,
                        "value_text": gc.value_text,
                    })
                    log.info(
                        f"[S5] Auth escalation: read unlocked h=0x{gc.value_handle:04X} "
                        f"{gc.uuid} → {gc.value_text or gc.value_hex}"
                    )
            except Exception as exc:
                log.debug(f"[S5] Post-pairing read h={gc.value_handle}: {exc}")

        if gc.requires_enc and ("write" in gc.properties or "write_no_resp" in gc.properties):
            try:
                no_resp = "write_no_resp" in gc.properties
                if no_resp:
                    periph_dev.write_command(gc.value_handle, b"\x00")
                else:
                    periph_dev.write(gc.value_handle, b"\x00")
                gc.requires_enc = False
                unlocked_write.append({
                    "uuid": gc.uuid,
                    "uuid_name": UUID_NAMES.get(_uuid_to_int(gc.uuid), ""),
                    "handle": gc.value_handle,
                })
                log.info(
                    f"[S5] Auth escalation: write unlocked h=0x{gc.value_handle:04X} {gc.uuid}"
                )
            except Exception as exc:
                log.debug(f"[S5] Post-pairing write h={gc.value_handle}: {exc}")

    if unlocked_read or unlocked_write:
        insert_finding(Finding(
            type="gatt_auth_escalation_success",
            severity="high",
            target_addr=addr,
            description=(
                f"Device {addr} ({target.name or 'unnamed'}) accepted LESC Just Works "
                f"pairing without MITM protection, granting access to "
                f"{len(unlocked_read)} previously-locked read(s) and "
                f"{len(unlocked_write)} previously-locked write(s)."
            ),
            remediation=(
                "Require MITM-protected pairing (Numeric Comparison or Passkey Entry) "
                "for characteristics that restrict unauthenticated access. "
                "Enforce SMP security level >= 3 for all sensitive characteristics."
            ),
            evidence={
                "unlocked_read": unlocked_read,
                "unlocked_write": unlocked_write,
                "pairing_mode": "LESC Just Works (no MITM)",
            },
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info(
            f"FINDING [high] gatt_auth_escalation_success: {addr} — "
            f"{len(unlocked_read)}R / {len(unlocked_write)}W unlocked via inline pairing"
        )
    else:
        log.info("[S5] Inline pairing succeeded but no previously-blocked chars were unlocked.")


def _harvest_notifications(
    periph_dev,
    notify_chars: list[GattCharacteristic],
    addr: str,
) -> list[dict]:
    """
    Subscribe to notify/indicate characteristics and collect updates for
    NOTIFY_HARVEST_SECS seconds.  Uses the WHAD Python API subscribe callback.
    Returns a list of {uuid, uuid_name, value_hex, value_text, ts} dicts.
    """
    import time as _time

    log.info(
        f"Subscribing to {len(notify_chars)} notify/indicate characteristic(s) "
        f"on {addr} for {NOTIFY_HARVEST_SECS}s ..."
    )

    collected: list[dict] = []
    lock = threading.Lock()

    def _make_cb(uuid_str: str, uuid_name: str):
        def _cb(characteristic, value: bytes, indication: bool = False) -> None:
            hex_val = value.hex() if isinstance(value, bytes) else str(value)
            text_val = _sanitize_string(
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else str(value)
            )
            entry = {
                "uuid": uuid_str,
                "uuid_name": uuid_name,
                "value_hex": hex_val,
                "value_text": text_val,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            with lock:
                collected.append(entry)
            log.info(
                f"  NOTIFY {uuid_str}"
                + (f" ({uuid_name})" if uuid_name else "")
                + f": {text_val or hex_val}"
            )
        return _cb

    subscribed = 0
    subscribed_objs: list = []   # track for cleanup after harvest
    for gc in notify_chars[:8]:   # cap at 8 handles
        uuid_name = UUID_NAMES.get(_uuid_to_int(gc.uuid), "")
        try:
            char_obj = periph_dev.char(gc.uuid.lower().replace("0x", ""))
            if char_obj is None:
                char_obj = periph_dev.char(gc.uuid)
            if char_obj is not None:
                char_obj.subscribe(
                    notification="notify" in gc.properties,
                    indication="indicate" in gc.properties,
                    callback=_make_cb(gc.uuid, uuid_name),
                )
                subscribed += 1
                subscribed_objs.append(char_obj)
                log.debug(f"  Subscribed to {gc.uuid} h={gc.value_handle}")
        except Exception as exc:
            log.debug(
                f"  Subscribe failed on {gc.uuid}: {type(exc).__name__}: {exc}"
            )

    if subscribed == 0:
        log.info(f"  No subscriptions established on {addr}.")
        return []

    log.info(f"  Listening ({subscribed} handle(s) subscribed) ...")
    deadline = _time.time() + NOTIFY_HARVEST_SECS
    last_count = 0
    silence_start = _time.time()
    while _time.time() < deadline:
        _time.sleep(0.2)
        with lock:
            current_count = len(collected)
        if current_count > last_count:
            last_count = current_count
            silence_start = _time.time()
        elif _time.time() - silence_start >= NOTIFY_SILENCE_SECS:
            log.debug(f"  No new notifications for {NOTIFY_SILENCE_SECS}s, exiting early")
            break

    log.info(
        f"  Notification harvest complete: {len(collected)} update(s) received"
    )

    # Unsubscribe to prevent stale callbacks interfering with later stages.
    for char_obj in subscribed_objs:
        try:
            char_obj.unsubscribe()
        except Exception:
            pass

    return collected


def _query_standard_services(periph_dev, device_info: dict, addr: str) -> None:
    """Best-effort standard service enrichment via WHAD Profile API.

    Queries BatteryService, DeviceInformationService, and HeartRateService if
    present on the target. Results are merged into device_info for the Finding.
    All errors are silenced — this is an additive enrichment, not a hard requirement.
    """
    try:
        from whad.ble.profile.services.battery import BatteryService
        if periph_dev.has(BatteryService):
            svc = periph_dev.query(BatteryService)
            level = svc.percentage
            device_info["battery_level_pct"] = level
            log.info(f"[S5] Battery level: {level}%")
    except Exception as exc:
        log.debug(f"[S5] BatteryService query: {exc}")

    try:
        from whad.ble.profile.services.dis import DeviceInformationService
        if periph_dev.has(DeviceInformationService):
            dis = periph_dev.query(DeviceInformationService)
            dis_fields = {
                k: getattr(dis, k, None)
                for k in ("manufacturer_name", "model_number",
                          "firmware_revision", "serial_number")
            }
            device_info["dis"] = dis_fields
            log.info(f"[S5] DIS: {dis_fields}")
    except Exception as exc:
        log.debug(f"[S5] DIS query: {exc}")

    try:
        from whad.ble.profile.services.hrs import HeartRateService
        if periph_dev.has(HeartRateService):
            hrs = periph_dev.query(HeartRateService)
            bpm = getattr(hrs, "rate", None)
            device_info["heart_rate_bpm"] = bpm
            log.info(f"[S5] Heart rate: {bpm} bpm")
    except Exception as exc:
        log.debug(f"[S5] HRS query: {exc}")


def _discover_with_timeout(periph_dev, addr: str) -> bool:
    """Call periph_dev.discover() with a hard wall-clock timeout."""
    exc_holder: list[Exception] = []
    done = threading.Event()

    def _do() -> None:
        try:
            periph_dev.discover()
        except Exception as exc:
            exc_holder.append(exc)
        finally:
            done.set()

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    finished = done.wait(timeout=GATT_DISCOVER_TIMEOUT)

    if not finished:
        log.warning(
            f"GATT discovery timed out on {addr} after {GATT_DISCOVER_TIMEOUT}s"
        )
        return False

    if exc_holder:
        exc = exc_holder[0]
        log.warning(
            f"GATT discovery failed on {addr}: {type(exc).__name__}: {exc}"
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _char_to_dict(c: GattCharacteristic) -> dict:
    return {
        "uuid": c.uuid,
        "uuid_name": UUID_NAMES.get(_uuid_to_int(c.uuid), ""),
        "handle": c.handle,
        "value_handle": c.value_handle,
        "properties": c.properties,
        "requires_auth": c.requires_auth,
        "value_text": c.value_text,
        "value_hex": c.value_hex,
        "user_description": c.user_description,
    }


def _decode_char_value(gc: GattCharacteristic, raw: str | bytes) -> None:
    """
    Populate gc.value_hex and gc.value_text from a hex string or raw bytes.

    Decodes UTF-8 where possible; strips null padding and non-printable chars.
    """
    if isinstance(raw, bytes):
        hex_str = raw.hex()
        raw_bytes = raw
    else:
        hex_str = re.sub(r"\s+", "", raw.lower())
        try:
            raw_bytes = bytes.fromhex(hex_str)
        except ValueError:
            # Already plain text (some CLI variants emit the decoded string)
            gc.value_hex = raw.encode("utf-8", errors="replace").hex()
            gc.value_text = _sanitize_string(raw)
            return

    gc.value_hex = hex_str

    text = _sanitize_string(raw_bytes.decode("utf-8", errors="replace"))
    if text and all(c.isprintable() or c.isspace() for c in text):
        gc.value_text = text


def _sanitize_string(s: str | None) -> str | None:
    """Strip null bytes, Unicode replacement chars, and surrounding whitespace."""
    if not s:
        return None
    clean = s.replace("\x00", "").replace("\ufffd", "").strip()
    return clean if clean else None


def _extract_properties(char) -> list[str]:
    props = []
    try:
        raw = char.properties
        if isinstance(raw, int):
            if raw & PROP_READ:
                props.append("read")
            if raw & PROP_WRITE_NR:
                props.append("write_no_resp")
            if raw & PROP_WRITE:
                props.append("write")
            if raw & PROP_NOTIFY:
                props.append("notify")
            if raw & PROP_INDICATE:
                props.append("indicate")
        elif isinstance(raw, (list, tuple)):
            props = [str(p) for p in raw]
        else:
            props = [str(raw)]
    except Exception:
        pass
    return props


def _uuid_to_int(uuid_str: str) -> int:
    try:
        clean = uuid_str.replace("-", "").replace("0x", "")
        if len(clean) <= 4:
            return int(clean, 16)
        if clean.endswith("00001000800000805f9b34fb"):
            return int(clean[:8], 16)
    except Exception:
        pass
    return 0


def _uuid_label(uuid_str: str) -> str:
    uuid_int = _uuid_to_int(uuid_str)
    name = UUID_NAMES.get(uuid_int)
    return f"{uuid_str} ({name})" if name else uuid_str


# ---------------------------------------------------------------------------
# Finding + summary
# ---------------------------------------------------------------------------

def _compute_severity(
    readable: list[GattCharacteristic],
    writable: list[GattCharacteristic],
    target: Target,
) -> str:
    if writable and target.device_class in (
        "access_control", "medical", "industrial",
    ):
        return "critical"
    if writable:
        return "high"
    if len(readable) > 3:
        return "medium"
    if readable:
        return "low"
    return "info"


def _record_finding(
    addr: str,
    target: Target,
    engagement_id: str,
    chars: list[GattCharacteristic],
    unauth_readable: list[GattCharacteristic],
    unauth_writable: list[GattCharacteristic],
    device_info: dict[str, str],
    notifications: list[dict] | None = None,
    pcap_path: str | None = None,
) -> None:
    severity = _compute_severity(unauth_readable, unauth_writable, target)

    readable_desc = ", ".join(
        f"{_uuid_label(c.uuid)}: {c.value_text or '<binary>'}"
        for c in unauth_readable[:3]
    ) or "none"

    finding = Finding(
        type="direct_access",
        severity=severity,
        target_addr=addr,
        description=(
            f"GATT profile of {addr} ({target.name or 'unnamed'}, "
            f"{target.device_class}): "
            f"{len(chars)} characteristics discovered. "
            f"{len(unauth_readable)} readable without auth — "
            f"including: {readable_desc}. "
            f"{len(unauth_writable)} writable without auth "
            f"(allows remote control without pairing)."
        ),
        remediation=(
            "Require pairing and bonding (LE Secure Connections with MITM) for all "
            "characteristic access. Set GAP Security Level >= 2. "
            "Mark characteristics with ATT_PERMISSION_AUTHEN_READ / "
            "ATT_PERMISSION_AUTHEN_WRITE in the GATT server profile."
        ),
        evidence={
            "total_characteristics": len(chars),
            "device_info": device_info,
            "unauth_readable": [
                {
                    "uuid": c.uuid,
                    "uuid_name": UUID_NAMES.get(_uuid_to_int(c.uuid), ""),
                    "handle": c.value_handle,
                    "value_hex": c.value_hex,
                    "value_text": c.value_text,
                }
                for c in unauth_readable
            ],
            "unauth_writable": [
                {
                    "uuid": c.uuid,
                    "uuid_name": UUID_NAMES.get(_uuid_to_int(c.uuid), ""),
                    "handle": c.value_handle,
                }
                for c in unauth_writable
            ],
            "full_profile": [
                {
                    "uuid": c.uuid,
                    "uuid_name": UUID_NAMES.get(_uuid_to_int(c.uuid), ""),
                    "handle": c.handle,
                    "value_handle": c.value_handle,
                    "properties": c.properties,
                    "requires_auth": c.requires_auth,
                    "value_text": c.value_text,
                    "value_hex": c.value_hex,
                }
                for c in chars
            ],
            "notifications": notifications or [],
        },
        pcap_path=pcap_path,
        engagement_id=engagement_id,
    )
    insert_finding(finding)

    log.info(
        f"FINDING [{severity}] direct_access: {addr} — "
        f"{len(unauth_readable)}R / {len(unauth_writable)}W without auth"
    )


def shell(
    dongle: WhadDongle,
    target: Target,
    profile: list[dict],
    engagement_id: str,
) -> None:
    """Interactive GATT REPL — reconnects and gives a live read/write/subscribe shell.

    Launched by main.py after S5 completes when the operator opts in.
    Available commands: read, write, wnr, sub, unsub, notify, info, pyshell, help, quit.
    'pyshell' drops to a raw Python REPL with `periph` and `profile` bound.
    """
    import code as _code
    import time as _time

    addr = target.bd_address
    is_random = target.address_type != "public"

    # Handle → char info index built from the profile list.
    by_handle: dict[int, dict] = {
        c["value_handle"]: c
        for c in profile
        if isinstance(c.get("value_handle"), int) and c["value_handle"] > 0
    }

    push_shell(addr)
    _shell_banner(addr, profile, by_handle)

    central = dongle.central()
    periph_dev = None
    try:
        log.info(f"[shell] Connecting to {addr} …")
        periph_dev = central.connect(addr, random=is_random, timeout=CONNECT_TIMEOUT)
    except Exception as exc:
        shell_write(f"  [shell] Connection failed: {type(exc).__name__}: {exc}")
        pop_shell()
        return
    if periph_dev is None:
        shell_write(f"  [shell] Could not connect to {addr} (timeout).")
        pop_shell()
        return

    try:
        ver = central.version(synchronous=True)
        if ver is not None:
            log.info(f"[S5] Remote BLE version: {ver}")
    except Exception as exc:
        log.debug(f"[S5] central.version() failed: {exc}")

    shell_write(f"  [OK] Connected to {addr}  —  type 'help' for commands")

    subscribed: dict[int, object] = {}
    notif_buffer: list[dict] = []
    notif_lock = threading.Lock()

    def _make_notif_cb(h: int):
        def _cb(char_obj, value, indication: bool = False) -> None:
            hex_val = value.hex() if isinstance(value, bytes) else str(value)
            text_val = _sanitize_string(
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else str(value)
            )
            with notif_lock:
                notif_buffer.append({"handle": h, "hex": hex_val, "text": text_val})
            label = by_handle.get(h, {}).get("uuid_name") or f"h={h}"
            shell_write(f"  [notify] {label}: {text_val or hex_val}")
        return _cb

    try:
        import readline as _rl
        _rl.parse_and_bind("tab: complete")
    except ImportError:
        pass

    while True:
        try:
            _input = prompt_line("  gatt> ")
        except (EOFError, KeyboardInterrupt):
            break
        if _input is None:
            break
        raw = _input.strip()
        if not raw:
            continue

        if periph_dev and not central.is_connected():
            log.debug("[S5] central.is_connected() returned False — treating as disconnected")
            break

        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help":
            shell_write("  Commands:")
            shell_write("    read   <h>               — read value (hex + text)")
            shell_write("    write  <h> <hex>         — write with response")
            shell_write("    wnr    <h> <hex>         — write without response")
            shell_write("    sub    <h>               — subscribe notifications")
            shell_write("    unsub  <h>               — unsubscribe")
            shell_write("    notify                   — show buffered notifications")
            shell_write("    info   [h]               — profile table (or single char)")
            shell_write("    connupdate <ms> [lat] [to_ms] — request LL conn param update")
            shell_write("    whack                    — oscillate params to stress timing")
            shell_write("    help                     — this message")
            shell_write("    quit / exit              — disconnect and return")

        elif cmd == "info":
            if len(parts) > 1:
                try:
                    h = int(parts[1], 0)
                    c = by_handle.get(h)
                    if c:
                        shell_write(f"  h={h}: uuid={c['uuid']}  name={c.get('uuid_name','')}  "
                                    f"props={c.get('properties',[])}  "
                                    f"auth={c.get('requires_auth', '?')}")
                    else:
                        shell_write(f"  Unknown handle {h}")
                except ValueError:
                    shell_write("  Usage: info [handle]")
            else:
                _print_profile_table(profile, by_handle)

        elif cmd == "read":
            if len(parts) < 2:
                shell_write("  Usage: read <handle>")
                continue
            try:
                h = int(parts[1], 0)
                raw_val = periph_dev.read(h)
                if raw_val is None:
                    shell_write(f"  h={h}: (empty response)")
                else:
                    hex_s = raw_val.hex() if isinstance(raw_val, bytes) else str(raw_val)
                    text_s = _sanitize_string(
                        raw_val.decode("utf-8", errors="replace")
                        if isinstance(raw_val, bytes)
                        else str(raw_val)
                    )
                    name = by_handle.get(h, {}).get("uuid_name") or ""
                    label = f" ({name})" if name else ""
                    shell_write(f"  [OK] h={h}{label}  hex={hex_s}  text={text_s or '(binary)'}")
            except Exception as exc:
                shell_write(f"  [ERR] read h={parts[1]} — {type(exc).__name__}: {exc}")

        elif cmd == "write":
            if len(parts) < 3:
                shell_write("  Usage: write <handle> <hex_bytes>")
                continue
            try:
                h = int(parts[1], 0)
                data = bytes.fromhex(parts[2])
                periph_dev.write(h, data)
                shell_write(f"  [OK] write h={h}  {len(data)} byte(s) written with response")
            except ValueError as exc:
                shell_write(f"  [ERR] bad hex — {exc}")
            except Exception as exc:
                shell_write(f"  [ERR] write h={parts[1]} — {type(exc).__name__}: {exc}")

        elif cmd == "wnr":
            if len(parts) < 3:
                shell_write("  Usage: wnr <handle> <hex_bytes>")
                continue
            try:
                h = int(parts[1], 0)
                data = bytes.fromhex(parts[2])
                periph_dev.write_command(h, data)
                shell_write(f"  [OK] wnr h={h}  {len(data)} byte(s) written no-response")
            except ValueError as exc:
                shell_write(f"  [ERR] bad hex — {exc}")
            except Exception as exc:
                shell_write(f"  [ERR] wnr h={parts[1]} — {type(exc).__name__}: {exc}")

        elif cmd == "sub":
            if len(parts) < 2:
                shell_write("  Usage: sub <handle>")
                continue
            try:
                h = int(parts[1], 0)
                c_info = by_handle.get(h, {})
                uuid_s = c_info.get("uuid", "")
                char_obj = None
                if uuid_s:
                    char_obj = periph_dev.char(uuid_s.lower().replace("0x", ""))
                    if char_obj is None:
                        char_obj = periph_dev.char(uuid_s)
                if char_obj is None:
                    shell_write(f"  [ERR] cannot resolve char h={h} (UUID={uuid_s!r})")
                    continue
                char_obj.subscribe(notification=True, callback=_make_notif_cb(h))
                subscribed[h] = char_obj
                name = c_info.get("uuid_name") or uuid_s
                shell_write(f"  [OK] subscribed h={h} ({name})")
            except Exception as exc:
                shell_write(f"  [ERR] sub h={parts[1]} — {type(exc).__name__}: {exc}")

        elif cmd == "unsub":
            if len(parts) < 2:
                shell_write("  Usage: unsub <handle>")
                continue
            try:
                h = int(parts[1], 0)
                char_obj = subscribed.pop(h, None)
                if char_obj:
                    char_obj.unsubscribe()
                    shell_write(f"  [OK] unsubscribed h={h}")
                else:
                    shell_write(f"  h={h} not currently subscribed")
            except Exception as exc:
                shell_write(f"  [ERR] unsub — {type(exc).__name__}: {exc}")

        elif cmd == "notify":
            with notif_lock:
                buf = list(notif_buffer)
            if not buf:
                shell_write("  No notifications buffered yet. Use 'sub <handle>' first.")
            else:
                for entry in buf:
                    label = by_handle.get(entry["handle"], {}).get("uuid_name") or \
                        f"h={entry['handle']}"
                    shell_write(f"  [{label}]  hex={entry['hex']}  "
                                f"text={entry.get('text') or '(binary)'}")

        elif cmd == "connupdate":
            if len(parts) < 2:
                shell_write("  Usage: connupdate <interval_ms> [latency] [timeout_ms]")
                shell_write("  Example: connupdate 7.5  /  connupdate 4000 0 8000")
                continue
            try:
                interval_ms  = float(parts[1])
                latency      = int(parts[2]) if len(parts) > 2 else 0
                timeout_ms   = int(parts[3]) if len(parts) > 3 else max(1000, int(interval_ms * 10))
                interval_u   = int(interval_ms / 1.25)
                timeout_u    = int(timeout_ms / 10)
                updated = False
                for method_name in (
                    "update_connection_parameters",
                    "set_connection_parameters",
                    "connection_update",
                    "send_connection_update",
                ):
                    fn = getattr(central, method_name, None)
                    if fn is None:
                        continue
                    try:
                        fn(interval_u, interval_u, latency, timeout_u)
                        updated = True
                        shell_write(
                            f"  [OK] connupdate — interval={interval_ms}ms  "
                            f"latency={latency}  timeout={timeout_ms}ms"
                        )
                        break
                    except Exception as exc:
                        log.debug(f"  {method_name}() failed: {exc}")
                if not updated:
                    shell_write("  [ERR] connupdate: no connection update method in WHAD Central")
            except (ValueError, IndexError) as exc:
                shell_write(f"  [ERR] connupdate: bad args — {exc}")

        elif cmd == "whack":
            shell_write("  whack: oscillating connection parameters (5 rounds) ...")
            whack_fn = None
            for mname in ("update_connection_parameters", "set_connection_parameters"):
                if getattr(central, mname, None):
                    whack_fn = getattr(central, mname)
                    break
            if whack_fn is None:
                shell_write("  [ERR] whack: no connection update method available.")
            else:
                import time as _whack_time
                for i in range(5):
                    try:
                        whack_fn(6, 6, 0, 200)
                        _whack_time.sleep(0.3)
                        whack_fn(3200, 3200, 0, 6400)
                        _whack_time.sleep(0.3)
                        shell_write(f"  [OK] whack round {i + 1}/5 — device still connected")
                    except Exception as exc:
                        shell_write(f"  [ERR] whack round {i + 1}/5 — {exc}")
                        break

        elif cmd == "pyshell":
            from core.logger import _bridge as _tui_bridge  # type: ignore[attr-defined]
            if _tui_bridge is not None:
                shell_write("  [WARN] pyshell unavailable in TUI mode (stdin captured by Textual)")
                shell_write("         Run with --plain for a full Python REPL.")
            else:
                shell_write(
                    "\n  Dropping into Python REPL.\n"
                    "  Locals: periph, profile, by_handle, central\n"
                    "  Ctrl-D or exit() to return.\n"
                )
                try:
                    _code.interact(
                        banner="",
                        local={
                            "periph": periph_dev,
                            "profile": profile,
                            "by_handle": by_handle,
                            "central": central,
                        },
                        exitmsg="  Returned to gatt shell.",
                    )
                except SystemExit:
                    pass

        else:
            shell_write(f"  Unknown command: {cmd!r}  (type 'help')")

    # --- Cleanup ---
    for char_obj in subscribed.values():
        try:
            char_obj.unsubscribe()
        except Exception:
            pass
    try:
        if periph_dev is not None:
            periph_dev.disconnect()
    except Exception:
        pass
    log.info(f"[shell] Disconnected from {addr}.")
    shell_write(f"  Session closed — {addr}")
    pop_shell()


def _shell_banner(addr: str, profile: list[dict], by_handle: dict[int, dict]) -> None:
    shell_write("═" * 76)
    shell_write(f"  TARGET  {addr}")
    shell_write(f"  PROFILE {len(profile)} characteristic(s) loaded")
    shell_write("  read  write  wnr  sub  unsub  notify  info  connupdate  whack  help  quit")
    shell_write("═" * 76)
    _print_profile_table(profile, by_handle)


def _print_profile_table(profile: list[dict], by_handle: dict[int, dict]) -> None:
    shell_write(f"  {'H':>4}  {'UUID':<38}  {'NAME':<22}  PROPS")
    shell_write("  " + "─" * 72)
    for c in sorted(profile, key=lambda x: x.get("value_handle", 0)):
        h = c.get("value_handle", 0)
        uuid_s = (c.get("uuid") or "")[:38]
        name = (c.get("uuid_name") or "")[:22]
        props = ",".join(c.get("properties") or [])[:22]
        val = c.get("value_text") or ""
        if val and len(val) > 18:
            val = val[:17] + "…"
        val_col = f"  [{val}]" if val else ""
        shell_write(f"  {h:>4}  {uuid_s:<38}  {name:<22}  {props}{val_col}")


def _print_summary(
    addr: str,
    target: Target,
    chars: list[GattCharacteristic],
    readable: list[GattCharacteristic],
    writable: list[GattCharacteristic],
    device_info: dict[str, str],
    notifications: list[dict] | None = None,
) -> None:
    log.info("─" * 76)
    log.info("  STAGE 5 SUMMARY -- GATT Enumeration")
    log.info("─" * 76)
    log.info(f"  {'Target':<18}: {addr}")
    log.info(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    log.info(f"  {'Manufacturer':<18}: {target.manufacturer or '—'}")
    log.info(f"  {'Device class':<18}: {target.device_class}")
    log.info(f"  {'Total chars':<18}: {len(chars)}")
    log.info(f"  {'Unauth readable':<18}: {len(readable)}")
    log.info(f"  {'Unauth writable':<18}: {len(writable)}")

    if device_info:
        log.info("  Device Information:")
        for k, v in device_info.items():
            v_str = str(v)
            if len(v_str) > 44:
                v_str = v_str[:43] + "…"
            log.info(f"    {k:<20}: {v_str}")

    if readable:
        log.info(f"  Readable without authentication ({len(readable)}):")
        for c in readable[:20]:
            label = (c.user_description or _uuid_label(c.uuid))[:30]
            val = c.value_text or (
                f"<hex:{c.value_hex[:24]}{'…' if c.value_hex and len(c.value_hex) > 24 else ''}>"
                if c.value_hex
                else "—"
            )
            if len(val) > 32:
                val = val[:31] + "…"
            log.info(f"    h={c.value_handle:<4}  {label:<30}  {val}")
        if len(readable) > 20:
            log.info(f"    … and {len(readable) - 20} more")

    if writable:
        log.info(f"  Writable without authentication ({len(writable)}):")
        for c in writable[:20]:
            log.info(f"    h={c.value_handle:<4}  {c.user_description or _uuid_label(c.uuid)}")

    if notifications:
        log.info(f"  Live notifications captured ({len(notifications)}):")
        seen: set[str] = set()
        for n in notifications[:20]:
            key = f"{n['uuid']}:{n['value_hex']}"
            label = _uuid_label(n["uuid"])[:30]
            val = n["value_text"] or f"<hex:{n['value_hex'][:24]}>"
            if len(val) > 28:
                val = val[:27] + "…"
            dedup_mark = " [dup]" if key in seen else ""
            seen.add(key)
            log.info(f"    {n['ts'][11:19]}  {label:<30}  {val}{dedup_mark}")
        if len(notifications) > 20:
            log.info(f"    … and {len(notifications) - 20} more")

    severity = _compute_severity(readable, writable, target)
    log.info(f"  {'Severity':<18}: {severity.upper()}")
    if writable:
        log.info(
            "  Why: Writable characteristics without auth allow "
            "any nearby device to modify state/config."
        )
    elif len(readable) > 3:
        log.info(
            "  Why: Multiple characteristics expose device data "
            "without pairing — enables fingerprinting."
        )
    if notifications:
        log.info(
            "  Notifications: Device broadcasts data without auth — "
            "confirms real-time BLE data leakage."
        )
    log.info("─" * 76)


def _wait_peripheral_connection(peripheral, timeout: int = 30) -> bool:
    """Wait for an inbound BLE connection on a Peripheral connector.

    Returns True if a device connected within timeout, False otherwise.
    Uses peripheral.wait_connection(timeout) if available.
    """
    try:
        result = peripheral.wait_connection(timeout=timeout)
        return result is not None
    except AttributeError:
        log.debug("[S5] peripheral.wait_connection() not available")
        return False
    except Exception as exc:
        log.debug(f"[S5] peripheral.wait_connection() failed: {exc}")
        return False
