from datetime import datetime, timezone

from whad.ble.exceptions import ConnectionLostException

from core.dongle import WhadDongle
from core.models import Target, Finding, GattCharacteristic
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s5_interact")

CONNECT_TIMEOUT = 15

INFO_UUIDS = {
    0x2A00: "Device Name",
    0x2A29: "Manufacturer Name",
    0x2A24: "Model Number",
    0x2A25: "Serial Number",
    0x2A26: "Firmware Revision",
    0x2A27: "Hardware Revision",
    0x2A28: "Software Revision",
}


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
) -> None:
    addr = target.bd_address
    is_random = target.address_type != "public"

    log.info(
        f"Connecting to {addr} "
        f"({'random' if is_random else 'public'}) ..."
    )

    central = dongle.central()
    periph_dev = None

    dongle.log_whad_connect(addr, is_random, CONNECT_TIMEOUT)
    try:
        periph_dev = central.connect(
            addr,
            random=is_random,
            timeout=CONNECT_TIMEOUT,
        )
    except ConnectionLostException:
        log.warning(f"Connection to {addr} lost during setup.")
        return
    except Exception as exc:
        log.error(f"Failed to connect to {addr}: {exc}")
        return

    if periph_dev is None:
        log.warning(f"Could not connect to {addr} (timeout).")
        return

    log.info(f"Connected to {addr}. Discovering GATT profile...")
    try:
        periph_dev.discover()
    except Exception as exc:
        log.warning(f"GATT discovery failed on {addr}: {exc}")
        try:
            periph_dev.disconnect()
        except Exception:
            pass
        return

    log.info(f"Enumerating characteristics...")

    chars: list[GattCharacteristic] = []
    unauth_readable: list[GattCharacteristic] = []
    unauth_writable: list[GattCharacteristic] = []
    device_info: dict[str, str] = {}

    try:
        for service in dongle.periph_services(periph_dev):
            svc_uuid = str(service.uuid)
            log.debug(f"Service: {svc_uuid}")

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
                            gc.value_hex = raw_val.hex()
                            try:
                                gc.value_text = raw_val.decode(
                                    "utf-8", errors="replace"
                                )
                            except Exception:
                                pass
                            gc.requires_auth = False
                            unauth_readable.append(gc)

                            uuid_int = _uuid_to_int(char_uuid)
                            if uuid_int in INFO_UUIDS:
                                device_info[
                                    INFO_UUIDS[uuid_int]
                                ] = gc.value_text or gc.value_hex

                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"READ OK: {gc.value_hex}"
                            )
                    except Exception as exc:
                        err_str = str(exc).lower()
                        if (
                            "authentication" in err_str
                            or "insufficient" in err_str
                            or "encrypt" in err_str
                        ):
                            gc.requires_auth = True
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"READ requires auth"
                            )
                        else:
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"READ error: {exc}"
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
                        log.debug(
                            f"  {char_uuid} h={value_handle} "
                            f"WRITE OK (no auth)"
                        )
                    except Exception as exc:
                        err_str = str(exc).lower()
                        if (
                            "authentication" in err_str
                            or "insufficient" in err_str
                            or "encrypt" in err_str
                        ):
                            gc.requires_enc = True
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"WRITE requires auth"
                            )
                        else:
                            log.debug(
                                f"  {char_uuid} h={value_handle} "
                                f"WRITE error: {exc}"
                            )

                chars.append(gc)

    except ConnectionLostException:
        log.warning(f"Connection to {addr} lost during enumeration.")
    except Exception as exc:
        log.error(f"GATT enumeration error on {addr}: {exc}")
    finally:
        try:
            periph_dev.disconnect()
        except Exception:
            pass

    if not chars:
        log.info(f"No characteristics discovered on {addr}.")
        return

    severity = _compute_severity(
        unauth_readable, unauth_writable, target
    )

    finding = Finding(
        type="direct_access",
        severity=severity,
        target_addr=addr,
        description=(
            f"GATT enumeration of {addr} "
            f"({target.name or 'unnamed'}): "
            f"{len(chars)} characteristics discovered, "
            f"{len(unauth_readable)} readable without auth, "
            f"{len(unauth_writable)} writable without auth."
        ),
        remediation=(
            "Require authentication and encryption for all "
            "sensitive characteristics. Use LE Secure Connections. "
            "Restrict 'read' and 'write' permissions to bonded "
            "devices only."
        ),
        evidence={
            "total_characteristics": len(chars),
            "unauth_readable": [
                {
                    "uuid": c.uuid,
                    "handle": c.value_handle,
                    "value_hex": c.value_hex,
                    "value_text": c.value_text,
                }
                for c in unauth_readable
            ],
            "unauth_writable": [
                {
                    "uuid": c.uuid,
                    "handle": c.value_handle,
                }
                for c in unauth_writable
            ],
            "device_info": device_info,
            "full_profile": [
                {
                    "uuid": c.uuid,
                    "handle": c.handle,
                    "value_handle": c.value_handle,
                    "properties": c.properties,
                    "requires_auth": c.requires_auth,
                }
                for c in chars
            ],
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)

    log.info(
        f"FINDING [{severity}] direct_access: {addr} -- "
        f"{len(unauth_readable)}R / {len(unauth_writable)}W "
        f"without auth"
    )

    _print_summary(addr, target, chars, unauth_readable, unauth_writable, device_info)


def _extract_properties(char) -> list[str]:
    props = []
    try:
        raw_props = char.properties
        if isinstance(raw_props, int):
            if raw_props & 0x02:
                props.append("read")
            if raw_props & 0x04:
                props.append("write_no_resp")
            if raw_props & 0x08:
                props.append("write")
            if raw_props & 0x10:
                props.append("notify")
            if raw_props & 0x20:
                props.append("indicate")
        elif isinstance(raw_props, (list, tuple)):
            props = [str(p) for p in raw_props]
        else:
            props = [str(raw_props)]
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


def _compute_severity(
    readable: list, writable: list, target: Target
) -> str:
    if writable and target.device_class in (
        "access_control",
        "medical",
        "industrial",
    ):
        return "critical"
    if writable:
        return "high"
    if len(readable) > 3:
        return "medium"
    if readable:
        return "low"
    return "info"


def _print_summary(
    addr: str,
    target: Target,
    chars: list[GattCharacteristic],
    readable: list[GattCharacteristic],
    writable: list[GattCharacteristic],
    device_info: dict,
) -> None:
    print("\n" + "-" * 72)
    print("  STAGE 5 SUMMARY -- GATT Enumeration")
    print("-" * 72)
    print(f"  Target          : {addr}")
    print(f"  Name            : {target.name or '(unnamed)'}")
    print(f"  Device class    : {target.device_class}")
    print(f"  Total chars     : {len(chars)}")
    print(f"  Unauth readable : {len(readable)}")
    print(f"  Unauth writable : {len(writable)}")

    if device_info:
        print("\n  Device Information:")
        for k, v in device_info.items():
            print(f"    {k}: {v}")

    if readable:
        print(f"\n  Readable without authentication ({len(readable)}):")
        for c in readable[:20]:
            val_display = c.value_text or c.value_hex or ""
            if len(val_display) > 40:
                val_display = val_display[:40] + "..."
            print(
                f"    UUID={c.uuid}  h={c.value_handle}  "
                f"val={val_display}"
            )
        if len(readable) > 20:
            print(f"    ... and {len(readable) - 20} more")

    if writable:
        print(
            f"\n  Writable without authentication "
            f"({len(writable)}):"
        )
        for c in writable[:20]:
            print(f"    UUID={c.uuid}  h={c.value_handle}")

    print("-" * 72 + "\n")