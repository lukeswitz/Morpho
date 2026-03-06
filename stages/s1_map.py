from datetime import datetime, timezone
import threading

from scapy.layers.bluetooth4LE import (
    BTLE_ADV,
    BTLE_ADV_IND,
    BTLE_ADV_NONCONN_IND,
    BTLE_ADV_SCAN_IND,
    BTLE_ADV_DIRECT_IND,
    BTLE_SCAN_RSP,
)

from whad.ble import Scanner

from core.dongle import WhadDongle
from core.models import Target
from core.db import upsert_target
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor
from classify.fingerprint import classify_device, compute_risk_score
from classify.manufacturer import decode_manufacturer, oui_lookup
import config

log = get_logger("s1_map")

AD_FLAGS = 0x01
AD_UUID16_INCOMPLETE = 0x02
AD_UUID16_COMPLETE = 0x03
AD_UUID128_INCOMPLETE = 0x06
AD_UUID128_COMPLETE = 0x07
AD_SHORT_NAME = 0x08
AD_COMPLETE_NAME = 0x09
AD_TX_POWER = 0x0A
AD_MANUFACTURER = 0xFF

_ADV_LAYERS = (
    BTLE_ADV_IND,
    BTLE_ADV_NONCONN_IND,
    BTLE_ADV_SCAN_IND,
    BTLE_ADV_DIRECT_IND,
    BTLE_SCAN_RSP,
)


def _extract_adv_addr(pkt) -> str | None:
    for layer_cls in _ADV_LAYERS:
        layer = pkt.getlayer(layer_cls)
        if layer is not None and hasattr(layer, "AdvA"):
            return str(layer.AdvA)
    return None


def _pdu_type(pkt) -> str:
    if pkt.haslayer(BTLE_ADV_IND):
        return "ADV_IND"
    if pkt.haslayer(BTLE_ADV_NONCONN_IND):
        return "ADV_NONCONN_IND"
    if pkt.haslayer(BTLE_ADV_SCAN_IND):
        return "ADV_SCAN_IND"
    if pkt.haslayer(BTLE_ADV_DIRECT_IND):
        return "ADV_DIRECT_IND"
    if pkt.haslayer(BTLE_SCAN_RSP):
        return "SCAN_RSP"
    return "ADV_UNKNOWN"


def _addr_type_label(pkt, bd_addr: str) -> str:
    try:
        adv_layer = pkt.getlayer(BTLE_ADV)
        if adv_layer is None:
            return "unknown"
        tx_add = adv_layer.TxAdd
    except AttributeError:
        return "unknown"

    if tx_add == 0:
        return "public"

    try:
        addr_bytes = bytes.fromhex(bd_addr.replace(":", ""))
        top2 = (addr_bytes[0] & 0xC0) >> 6
    except Exception:
        return "random"

    return {
        0b11: "random_static",
        0b00: "random_non_resolvable",
        0b01: "random_resolvable",
    }.get(top2, "random")


def _extract_channel(pkt) -> int:
    """Extract channel from packet metadata."""
    meta = getattr(pkt, "metadata", None)
    if meta is not None:
        return getattr(meta, "channel", 0) or 0
    return 0


def _raw_ad_bytes(pkt) -> bytes:
    """Extract advertising payload from raw packet bytes."""
    raw = bytes(pkt)
    if len(raw) < 12:
        return b""
    # Skip access address (4) + header (2) + AdvA (6) = 12 bytes
    return raw[12:]

def _parse_ad_records(raw_bytes: bytes) -> dict:
    result = {
        "name": None,
        "services": [],
        "tx_power": None,
        "company_id": None,
        "manufacturer_data": None,
        "flags": None,
    }

    i = 0
    while i < len(raw_bytes):
        length = raw_bytes[i]
        if length == 0:
            i += 1
            continue
        if i + length >= len(raw_bytes):
            break

        ad_type = raw_bytes[i + 1]
        payload = raw_bytes[i + 2 : i + 1 + length]
        i += 1 + length

        if ad_type in (AD_COMPLETE_NAME, AD_SHORT_NAME):
            try:
                decoded = payload.decode("utf-8", errors="replace").strip("\x00")
                result["name"] = _sanitize_string(decoded)
            except Exception:
                pass

        elif ad_type in (AD_UUID16_COMPLETE, AD_UUID16_INCOMPLETE):
            for j in range(0, len(payload) - 1, 2):
                uuid_val = int.from_bytes(payload[j : j + 2], "little")
                result["services"].append(f"{uuid_val:04X}")

        elif ad_type in (AD_UUID128_COMPLETE, AD_UUID128_INCOMPLETE):
            for j in range(0, len(payload), 16):
                chunk = payload[j : j + 16]
                if len(chunk) == 16:
                    uuid_str = "-".join(
                        [
                            chunk[12:16][::-1].hex(),
                            chunk[10:12][::-1].hex(),
                            chunk[8:10][::-1].hex(),
                            chunk[6:8][::-1].hex(),
                            chunk[0:6][::-1].hex(),
                        ]
                    )
                    result["services"].append(uuid_str.upper())

        elif ad_type == AD_TX_POWER:
            if payload:
                result["tx_power"] = int.from_bytes(
                    payload[:1], "big", signed=True
                )

        elif ad_type == AD_MANUFACTURER:
            result["manufacturer_data"] = payload
            company_id, _ = decode_manufacturer(payload)
            result["company_id"] = company_id

        elif ad_type == AD_FLAGS:
            if payload:
                result["flags"] = payload[0]

    return result


def run(
    dongle: WhadDongle,
    engagement_id: str,
    ubertooth_dongle: "WhadDongle | None" = None,
) -> list[Target]:
    targets: dict[str, Target] = {}
    _lock = threading.Lock()  # protects `targets` dict for parallel writes

    log.info(
        f"Starting passive scan for {config.SCAN_DURATION}s "
        f"on {config.INTERFACE}"
    )
    log.info("Listening on advertising channels 37, 38, 39...")
    if config.RSSI_MIN_FILTER:
        log.info(f"[S1] RSSI filter: ignoring devices below {config.RSSI_MIN_FILTER} dBm")
    if ubertooth_dongle:
        log.info(
            f"[S1] Ubertooth One [{ubertooth_dongle.interface}] running as "
            "parallel passive sniffer — extended channel coverage."
        )

    _monitor = None
    scanner = dongle.scanner()
    _monitor = attach_monitor(scanner, pcap_path(engagement_id, 1, "scan"))

    # Hardware address filter: reduce firmware overhead for single-target scans.
    if len(config.TARGET_FILTER) == 1:
        _hw_addr = list(config.TARGET_FILTER)[0]
        try:
            scanner.filter_address = _hw_addr
            log.info(f"[S1] Hardware address filter set: {_hw_addr}")
        except AttributeError:
            log.debug(
                "[S1] Scanner.filter_address not supported on this WHAD version "
                "— software filter active"
            )

    scanner.start()

    # Start Ubertooth parallel scan thread if available.
    _ubertooth_thread: threading.Thread | None = None
    if ubertooth_dongle is not None and ubertooth_dongle.caps.can_scan:
        _ubertooth_thread = threading.Thread(
            target=_ubertooth_scan_worker,
            args=(ubertooth_dongle, targets, _lock, engagement_id, config.SCAN_DURATION),
            daemon=True,
        )
        _ubertooth_thread.start()

    try:
        for pkt in dongle.sniff_iter(scanner, total_duration=config.SCAN_DURATION):
            now = datetime.now(timezone.utc)

            try:
                bd_addr = _extract_adv_addr(pkt)
                if bd_addr is None:
                    continue
                bd_addr = bd_addr.upper()

                rssi = 0
                meta = getattr(pkt, "metadata", None)
                if meta is not None:
                    rssi = getattr(meta, "rssi", 0) or 0

                # RSSI filter: drop devices below minimum signal threshold.
                if config.RSSI_MIN_FILTER and rssi < config.RSSI_MIN_FILTER:
                    continue

                if (
                    config.TARGET_FILTER
                    and bd_addr not in config.TARGET_FILTER
                ):
                    continue

                pdu = _pdu_type(pkt)

                if pdu == "SCAN_RSP" and bd_addr in targets:
                    raw_ad = _raw_ad_bytes(pkt)
                    ad = _parse_ad_records(raw_ad)
                    t = targets[bd_addr]
                    t.last_seen = now
                    if ad["name"] and not t.name:
                        t.name = ad["name"]
                        t.device_class = classify_device(t)
                        t.risk_score = compute_risk_score(t)
                    for svc in ad["services"]:
                        if svc not in t.services:
                            t.services.append(svc)
                    upsert_target(t)
                    continue

                raw_ad = _raw_ad_bytes(pkt)
                ad = _parse_ad_records(raw_ad)
                addr_type = _addr_type_label(pkt, bd_addr)
                connectable = pdu in ("ADV_IND", "ADV_DIRECT_IND")
                channel = _extract_channel(pkt)

                if bd_addr not in targets:
                    t = Target(
                        bd_address=bd_addr,
                        address_type=addr_type,
                        adv_type=pdu,
                        name=ad["name"],
                        manufacturer=None,
                        company_id=ad["company_id"],
                        services=ad["services"],
                        tx_power=ad["tx_power"],
                        rssi_samples=[rssi],
                        rssi_avg=float(rssi),
                        device_class="unknown",
                        connectable=connectable,
                        first_seen=now,
                        last_seen=now,
                        raw_adv_records=[raw_ad] if raw_ad else [],
                        risk_score=0,
                        engagement_id=engagement_id,
                        channel=channel,
                    )

                    if addr_type == "public":
                        oui_name = oui_lookup(bd_addr)
                        if oui_name:
                            t.manufacturer = oui_name

                    if ad["company_id"] is not None:
                        _, mfr_name = decode_manufacturer(
                            ad["manufacturer_data"] or b"\x00\x00"
                        )
                        t.manufacturer = mfr_name

                    t.device_class = classify_device(t)
                    t.risk_score = compute_risk_score(t)
                    targets[bd_addr] = t
                    _log_new_target(t)

                else:
                    t = targets[bd_addr]
                    t.last_seen = now
                    t.rssi_samples.append(rssi)
                    t.rssi_avg = sum(t.rssi_samples) / len(
                        t.rssi_samples
                    )

                    raw_ad = _raw_ad_bytes(pkt)
                    ad = _parse_ad_records(raw_ad)

                    if ad["name"] and not t.name:
                        t.name = ad["name"]
                        t.device_class = classify_device(t)
                        t.risk_score = compute_risk_score(t)

                    for svc in ad["services"]:
                        if svc not in t.services:
                            t.services.append(svc)

                upsert_target(targets[bd_addr])

            except Exception as exc:
                log.debug(f"Packet parse error: {exc}")
                continue

    except KeyboardInterrupt:
        log.info("Scan interrupted by user.")
    finally:
        try:
            detach_monitor(_monitor)
            scanner.stop()
        except Exception:
            pass

    if _ubertooth_thread is not None:
        _ubertooth_thread.join(timeout=5.0)

    with _lock:
        result = sorted(
            targets.values(), key=lambda x: x.risk_score, reverse=True
        )
    _print_summary(result)
    return result


def _ubertooth_scan_worker(
    dongle: "WhadDongle",
    targets: dict,
    lock: threading.Lock,
    engagement_id: str,
    duration: float,
) -> None:
    """Background thread: scan with Ubertooth One and merge into shared targets."""
    try:
        ub_scanner = dongle.scanner()
        ub_scanner.start()
        for pkt in dongle.sniff_iter(ub_scanner, total_duration=duration):
            now = datetime.now(timezone.utc)
            try:
                bd_addr = _extract_adv_addr(pkt)
                if bd_addr is None:
                    continue
                bd_addr = bd_addr.upper()
                if config.RSSI_MIN_FILTER:
                    rssi = 0
                    meta = getattr(pkt, "metadata", None)
                    if meta is not None:
                        rssi = getattr(meta, "rssi", 0) or 0
                    if rssi < config.RSSI_MIN_FILTER:
                        continue
                if config.TARGET_FILTER and bd_addr not in config.TARGET_FILTER:
                    continue
                with lock:
                    if bd_addr not in targets:
                        raw_ad = _raw_ad_bytes(pkt)
                        ad = _parse_ad_records(raw_ad)
                        pdu = _pdu_type(pkt)
                        connectable = pdu in ("ADV_IND", "ADV_DIRECT_IND")
                        t = Target(
                            bd_address=bd_addr,
                            address_type=_addr_type_label(pkt, bd_addr),
                            adv_type=pdu,
                            name=ad["name"],
                            manufacturer=None,
                            company_id=ad["company_id"],
                            services=ad["services"],
                            tx_power=ad["tx_power"],
                            rssi_samples=[],
                            rssi_avg=0.0,
                            device_class="unknown",
                            connectable=connectable,
                            first_seen=now,
                            last_seen=now,
                            raw_adv_records=[raw_ad] if raw_ad else [],
                            risk_score=0,
                            engagement_id=engagement_id,
                            channel=_extract_channel(pkt),
                        )
                        from classify.fingerprint import classify_device, compute_risk_score
                        t.device_class = classify_device(t)
                        t.risk_score = compute_risk_score(t)
                        targets[bd_addr] = t
                        log.info(f"[S1][ubertooth] New device: {bd_addr} ({t.device_class})")
            except Exception as exc:
                log.debug(f"[S1][ubertooth] Packet error: {exc}")
    except Exception as exc:
        log.debug(f"[S1][ubertooth] Scanner error: {type(exc).__name__}: {exc}")
    finally:
        try:
            ub_scanner.stop()
        except Exception:
            pass


def _log_new_target(t: Target) -> None:
    risk_tag = _risk_label(t.risk_score)
    log.info(
        f"[{risk_tag}] {t.bd_address}  "
        f"{t.address_type:<22}  "
        f"{t.adv_type:<14}  "
        f"conn={t.connectable}  "
        f"ch={t.channel:<2}  "
        f"rssi={t.rssi_samples[-1]:>4} dBm  "
        f"name={t.name or '—'}"
    )
    if t.services:
        log.debug(f"         services: {', '.join(t.services)}")
    if t.manufacturer:
        log.debug(f"         manufacturer: {t.manufacturer}")


def _sanitize_string(s: str | None) -> str | None:
    """Strip null bytes and whitespace from strings."""
    if not s:
        return None
    clean = s.lstrip('\x00').rstrip('\x00').strip()
    return clean if clean else None


def _trunc(s: str | None, n: int) -> str:
    val = s or '—'
    return val[:n] if len(val) > n else val


def _addr_type_short(addr_type: str) -> str:
    return {
        "public": "public",
        "random_static": "rand:static",
        "random_non_resolvable": "rand:non-res",
        "random_resolvable": "rand:res",
        "random": "random",
    }.get(addr_type, addr_type[:14])


def _risk_label(score: int) -> str:
    if score >= 8:
        return "CRIT"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MED "
    if score >= 2:
        return "LOW "
    return "INFO"


def _print_summary(targets: list[Target]) -> None:
    print("\033[2J\033[H", end="")
    
    print("\n" + "─" * 130)
    print(f"  STAGE 1 SUMMARY -- {len(targets)} devices discovered")
    print("─" * 130)
    print(
        f"  {'RISK':<6} {'BD ADDRESS':<20} {'TYPE':<14} "
        f"{'PDU':<16} {'CONN':<5} {'CH':<4} {'RSSI':>5}  {'NAME':<24} MANUFACTURER"
    )
    print("─" * 130)
    for t in targets:
        print(
            f"  {_risk_label(t.risk_score):<6} "
            f"{t.bd_address:<20} "
            f"{_addr_type_short(t.address_type):<14} "
            f"{t.adv_type:<16} "
            f"{'yes' if t.connectable else 'no':<5} "
            f"{t.channel:<4} "
            f"{t.rssi_avg:>5.0f}  "
            f"{_trunc(t.name, 24):<24} "
            f"{_trunc(t.manufacturer, 22)}"
        )
    print("─" * 130)

    by_class: dict[str, list[Target]] = {}
    for t in targets:
        by_class.setdefault(t.device_class, []).append(t)

    print("\n  Device class breakdown:")
    for cls, items in sorted(
        by_class.items(), key=lambda x: -len(x[1])
    ):
        connectable_count = sum(1 for t in items if t.connectable)
        print(
            f"    {cls:<16} {len(items):>3} total  "
            f"{connectable_count:>3} connectable"
        )

    high_risk = [t for t in targets if t.risk_score >= 6]
    if high_risk:
        print(f"\n  HIGH/CRITICAL targets ({len(high_risk)}):")
        for t in high_risk:
            print(
                f"    {t.bd_address}  score={t.risk_score}  "
                f"{t.name or '(unnamed)'}  {t.device_class}"
            )
    print()