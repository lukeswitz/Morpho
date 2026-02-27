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
from datetime import datetime, timezone

from whad.ble.exceptions import ConnectionLostException

from core.dongle import WhadDongle
from core.models import Target, Finding, GattCharacteristic
from core.db import insert_finding
from core.logger import get_logger
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

NOTIFY_HARVEST_SECS = 20   # how long to listen for notifications per device


def run(dongle: WhadDongle, target: Target, engagement_id: str) -> None:
    if _cli_available():
        _run_cli(dongle, target, engagement_id)
    else:
        _run_python_api(dongle, target, engagement_id)


# ---------------------------------------------------------------------------
# CLI approach: wble-connect | wble-central profile
# ---------------------------------------------------------------------------

def _cli_available() -> bool:
    return (
        shutil.which("wble-connect") is not None
        and shutil.which("wble-central") is not None
    )


def _run_cli(dongle: WhadDongle, target: Target, engagement_id: str) -> None:
    addr = target.bd_address
    is_random = target.address_type != "public"
    rand_flag = "-r" if is_random else ""

    log.info(
        f"[CLI] Connecting to {addr} "
        f"({'random' if is_random else 'public'}) ..."
    )

    # Release the WHAD device so wble-connect can open it.
    dongle.device.close()

    cmd = (
        f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
        f"| wble-central profile"
    )
    log.debug(f"Running: {cmd}")

    stdout = ""
    stderr = ""
    returncode = -1

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT,
        )
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        log.warning(f"[CLI] Timeout reaching {addr} after {CLI_TIMEOUT}s")
    except Exception as exc:
        log.error(
            f"[CLI] Subprocess error for {addr}: {type(exc).__name__}: {exc}"
        )
    finally:
        _reopen_dongle(dongle)

    if not stdout.strip():
        log.warning(
            f"[CLI] No profile output for {addr} "
            f"(exit={returncode}): {stderr.strip()[:120]}"
        )
        return

    chars, unauth_readable, unauth_writable, device_info = _parse_cli_profile(
        stdout
    )

    if not chars:
        log.info(f"[CLI] No characteristics discovered on {addr}.")
        return

    _record_finding(
        addr, target, engagement_id,
        chars, unauth_readable, unauth_writable, device_info,
    )
    _print_summary(
        addr, target, chars, unauth_readable, unauth_writable, device_info,
    )


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the underlying WhadDevice after a CLI run."""
    try:
        from whad.device import WhadDevice
        dongle.device = WhadDevice.create(config.INTERFACE)
    except Exception as exc:
        log.warning(f"Could not reopen WHAD device: {exc}")


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

    WHAD profile output format (approximate):
        Service 0x1800 (Generic Access)
          Characteristic 0x2A00 [handle=3, value_handle=4] read write
            Value: 41 63 65 72 ...
          Characteristic 0x2A01 [handle=5, value_handle=6] read
    """
    chars: list[GattCharacteristic] = []
    unauth_readable: list[GattCharacteristic] = []
    unauth_writable: list[GattCharacteristic] = []
    device_info: dict[str, str] = {}

    current_char: GattCharacteristic | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Characteristic line
        char_match = re.search(
            r"[Cc]haracteristic\s+(?:0x)?([0-9A-Fa-f-]{4,36})"
            r"(?:.*?handle=(\d+))?(?:.*?value_handle=(\d+))?",
            line,
        )
        if char_match:
            uuid_str = char_match.group(1).upper()
            handle = int(char_match.group(2)) if char_match.group(2) else 0
            value_handle = int(char_match.group(3)) if char_match.group(3) else handle
            props = _extract_props_from_line(line)
            current_char = GattCharacteristic(
                uuid=uuid_str,
                handle=handle,
                value_handle=value_handle,
                properties=props,
            )
            chars.append(current_char)
            continue

        # Value line
        if current_char and re.match(r"[Vv]alue\s*:", line):
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

    # Write access: any writable char that has a value (was accessible)
    for char in chars:
        if (
            ("write" in char.properties or "write_no_resp" in char.properties)
            and char.value_hex is not None
            and not char.requires_auth
            and char not in unauth_writable
        ):
            unauth_writable.append(char)

    return chars, unauth_readable, unauth_writable, device_info


def _extract_props_from_line(line: str) -> list[str]:
    props = []
    if re.search(r"\bread\b", line, re.I):
        props.append("read")
    if re.search(r"\bwrite[-_]no[-_]resp\b", line, re.I):
        props.append("write_no_resp")
    elif re.search(r"\bwrite\b", line, re.I):
        props.append("write")
    if re.search(r"\bnotify\b", line, re.I):
        props.append("notify")
    if re.search(r"\bindicate\b", line, re.I):
        props.append("indicate")
    return props


# ---------------------------------------------------------------------------
# Python API fallback
# ---------------------------------------------------------------------------

def _run_python_api(dongle: WhadDongle, target: Target, engagement_id: str) -> None:
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
        return
    except Exception as exc:
        log.error(f"Failed to connect to {addr}: {type(exc).__name__}: {exc}")
        detach_monitor(_monitor)
        return

    if periph_dev is None:
        log.warning(f"Could not connect to {addr} (timeout).")
        detach_monitor(_monitor)
        return

    log.info(f"Connected to {addr}. Discovering GATT profile...")

    if not _discover_with_timeout(periph_dev, addr):
        try:
            periph_dev.disconnect()
        except Exception:
            pass
        return

    log.info("Enumerating characteristics...")

    chars: list[GattCharacteristic] = []
    unauth_readable: list[GattCharacteristic] = []
    unauth_writable: list[GattCharacteristic] = []
    device_info: dict[str, str] = {}

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
                    except Exception as exc:
                        err = str(exc).lower()
                        if any(
                            kw in err
                            for kw in ("authentication", "insufficient", "encrypt")
                        ):
                            gc.requires_auth = True
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
                    except Exception as exc:
                        err = str(exc).lower()
                        if any(
                            kw in err
                            for kw in ("authentication", "insufficient", "encrypt")
                        ):
                            gc.requires_enc = True
                        log.debug(
                            f"  {char_uuid} h={value_handle} "
                            f"WRITE {type(exc).__name__}: {exc}"
                        )

                chars.append(gc)

    except ConnectionLostException:
        log.warning(f"Connection to {addr} lost during enumeration.")
    except Exception as exc:
        log.error(
            f"GATT enumeration error on {addr}: {type(exc).__name__}: {exc}"
        )

    # --- Notification harvest (within the same open connection) ---
    notifications: list[dict] = []
    notify_chars = [
        c for c in chars
        if "notify" in c.properties or "indicate" in c.properties
    ]
    if notify_chars and periph_dev is not None:
        notifications = _harvest_notifications(periph_dev, notify_chars, addr)

    try:
        if periph_dev is not None:
            periph_dev.disconnect()
    except Exception:
        pass
    finally:
        detach_monitor(_monitor)

    if not chars:
        log.info(f"No characteristics discovered on {addr}.")
        return

    _record_finding(
        addr, target, engagement_id,
        chars, unauth_readable, unauth_writable, device_info, notifications,
        pcap_path=str(_pcap_file),
    )
    _print_summary(
        addr, target, chars, unauth_readable, unauth_writable, device_info,
        notifications,
    )


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
                log.debug(f"  Subscribed to {gc.uuid} h={gc.value_handle}")
        except Exception as exc:
            log.debug(
                f"  Subscribe failed on {gc.uuid}: {type(exc).__name__}: {exc}"
            )

    if subscribed == 0:
        log.info(f"  No subscriptions established on {addr}.")
        return []

    log.info(f"  Listening ({subscribed} handle(s) subscribed) ...")
    _time.sleep(NOTIFY_HARVEST_SECS)

    log.info(
        f"  Notification harvest complete: {len(collected)} update(s) received"
    )
    return collected


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


def _print_summary(
    addr: str,
    target: Target,
    chars: list[GattCharacteristic],
    readable: list[GattCharacteristic],
    writable: list[GattCharacteristic],
    device_info: dict[str, str],
    notifications: list[dict] | None = None,
) -> None:
    print("\n" + "-" * 72)
    print("  STAGE 5 SUMMARY -- GATT Enumeration")
    print("-" * 72)
    print(f"  Target          : {addr}")
    print(f"  Name            : {target.name or '(unnamed)'}")
    print(f"  Manufacturer    : {target.manufacturer or '—'}")
    print(f"  Device class    : {target.device_class}")
    print(f"  Total chars     : {len(chars)}")
    print(f"  Unauth readable : {len(readable)}")
    print(f"  Unauth writable : {len(writable)}")

    if device_info:
        print("\n  Device Information:")
        for k, v in device_info.items():
            print(f"    {k:<30}: {v}")

    if readable:
        print(f"\n  Readable without authentication ({len(readable)}):")
        for c in readable[:20]:
            label = _uuid_label(c.uuid)
            val = c.value_text or (
                f"<hex:{c.value_hex[:32]}{'…' if c.value_hex and len(c.value_hex) > 32 else ''}>"
                if c.value_hex
                else "—"
            )
            if len(val) > 50:
                val = val[:50] + "…"
            print(f"    h={c.value_handle:<4}  {label:<40}  {val}")
        if len(readable) > 20:
            print(f"    … and {len(readable) - 20} more")

    if writable:
        print(f"\n  Writable without authentication ({len(writable)}):")
        for c in writable[:20]:
            print(f"    h={c.value_handle:<4}  {_uuid_label(c.uuid)}")

    if notifications:
        print(f"\n  Live notifications captured ({len(notifications)}):")
        seen: set[str] = set()
        for n in notifications[:20]:
            key = f"{n['uuid']}:{n['value_hex']}"
            label = _uuid_label(n["uuid"])
            val = n["value_text"] or f"<hex:{n['value_hex'][:32]}>"
            dedup_mark = " [dup]" if key in seen else ""
            seen.add(key)
            print(f"    {n['ts'][11:19]}  {label:<40}  {val}{dedup_mark}")
        if len(notifications) > 20:
            print(f"    … and {len(notifications) - 20} more")

    severity = _compute_severity(readable, writable, target)
    print(f"\n  Severity        : {severity.upper()}")
    if writable:
        print(
            "  Why             : Writable characteristics without auth allow any\n"
            "                    nearby BLE device to modify state/config/behaviour."
        )
    elif len(readable) > 3:
        print(
            "  Why             : Multiple characteristics expose device data\n"
            "                    without pairing — enables fingerprinting."
        )
    if notifications:
        print(
            "  Notifications   : Device actively broadcasts data — confirms real-time\n"
            "                    data leakage over BLE without authentication."
        )
    print("-" * 72 + "\n")
