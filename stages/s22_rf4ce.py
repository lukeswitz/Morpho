"""
Stage 22 — RF4CE Remote Control Reconnaissance

Passively sniffs RF4CE traffic on the three standard channels (15, 20, 25)
and attempts to identify controllers (remotes) and targets (TVs, set-top boxes).
Uses whad.rf4ce if available, falls back to whad.dot15d4 raw sniffing on
the same channels.

RF4CE operates on IEEE 802.15.4 channels 15, 20, and 25 at 2.4 GHz.
Standard pairing uses a 3-channel hop sequence. JustWorks pairing transmits
the link key in cleartext, making passive capture during pairing a viable
attack path.
"""
from __future__ import annotations

import time

from core.dongle import WhadDongle, HardwareMap
from core.logger import get_logger
from core.models import Finding
from core.db import insert_finding
import config

log = get_logger("s22_rf4ce")

# Standard RF4CE operating channels (IEEE 802.15.4 2.4 GHz band)
RF4CE_CHANNELS: list[int] = [15, 20, 25]

RF4CE_SNIFF_SECS: int = getattr(config, "RF4CE_SNIFF_SECS", 30)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(hw: HardwareMap, engagement_id: str) -> list[dict]:
    """Sniff RF4CE traffic on channels 15, 20, 25 and identify remote control devices.

    Tries whad.rf4ce first. Falls back to whad.dot15d4 raw 802.15.4 sniffing
    on the same three channels if whad.rf4ce is not importable.

    Args:
        hw: HardwareMap — uses esb_dongle first, then ble_dongle.
        engagement_id: Engagement ID for findings storage.

    Returns:
        List of discovered RF4CE device dicts.
    """
    log.info(f"[S22] RF4CE recon starting — {RF4CE_SNIFF_SECS}s per channel "
             f"(channels {RF4CE_CHANNELS})")

    device = _pick_device(hw)
    if device is None:
        log.warning("[S22] No suitable hardware for RF4CE sniffing — stage skipped.")
        _print_summary([])
        return []

    log.debug(f"[S22] Using device: {device.interface} ({device.caps.device_type})")

    rf4ce_cls = _probe_rf4ce_connector()

    if rf4ce_cls is not None:
        devices = _sniff_with_rf4ce(rf4ce_cls, device, engagement_id)
    else:
        devices = _sniff_with_dot15d4(device, engagement_id)

    _print_summary(devices)
    return devices


# ---------------------------------------------------------------------------
# Device selection
# ---------------------------------------------------------------------------

def _pick_device(hw: HardwareMap) -> "WhadDongle | None":
    """Return the best dongle for 802.15.4 sniffing.

    ESB dongle (rfstorm) is preferred because it has a genuine 802.15.4 PHY.
    Falls back to BLE dongle (nRF52840/ButteRFly) which also supports 802.15.4
    via whad.zigbee / whad.dot15d4. PHY dongle (YardStickOne) does not support
    802.15.4 framing, so it is excluded.
    """
    return hw.esb_dongle or hw.ble_dongle


# ---------------------------------------------------------------------------
# whad.rf4ce connector probe
# ---------------------------------------------------------------------------

def _probe_rf4ce_connector():
    """Return the best whad.rf4ce connector class, or None if unavailable.

    Probes class names in order of preference: Sniffer, Scanner, Connector.
    Returns the first one that imports successfully, or None.
    """
    for cls_name in ("Sniffer", "Scanner", "Connector"):
        try:
            mod = __import__("whad.rf4ce", fromlist=[cls_name])
            cls = getattr(mod, cls_name, None)
            if cls is not None:
                log.debug(f"[S22] whad.rf4ce.{cls_name} available")
                return cls
        except (ImportError, AttributeError):
            continue
    log.debug("[S22] whad.rf4ce not importable — will use dot15d4 fallback")
    return None


# ---------------------------------------------------------------------------
# RF4CE sniff path
# ---------------------------------------------------------------------------

def _sniff_with_rf4ce(rf4ce_cls, device: "WhadDongle", engagement_id: str) -> list[dict]:
    """Sniff RF4CE traffic using a native whad.rf4ce connector class."""
    results: list[dict] = []
    seen_addrs: set[str] = set()

    for ch in RF4CE_CHANNELS:
        connector = None
        try:
            connector = rf4ce_cls(device.device)

            if hasattr(connector, "channel"):
                connector.channel = ch
            if hasattr(connector, "start"):
                connector.start()

            log.info(f"[S22][rf4ce] Listening on channel {ch} for {RF4CE_SNIFF_SECS}s")
            deadline = time.time() + RF4CE_SNIFF_SECS

            sniff_iter = _get_sniff_iter(connector)
            if sniff_iter is not None:
                for pkt in sniff_iter:
                    if time.time() > deadline:
                        break
                    dev = _parse_packet(pkt, ch)
                    if dev and dev["address"] not in seen_addrs:
                        seen_addrs.add(dev["address"])
                        results.append(dev)
                        log.info(
                            f"[S22][rf4ce] Device: {dev['address']}  "
                            f"type={dev['type']}  ch={ch}"
                        )
            else:
                # Connector has no sniff/stream — wait out the dwell period passively
                log.debug(f"[S22][rf4ce] ch{ch}: no sniff/stream method; waiting passively")
                time.sleep(RF4CE_SNIFF_SECS)

        except (AttributeError, NotImplementedError) as exc:
            log.debug(f"[S22][rf4ce] ch{ch} connector error: {exc}")
        except Exception as exc:
            log.debug(f"[S22][rf4ce] ch{ch} unexpected error: {type(exc).__name__}: {exc}")
        finally:
            if connector is not None:
                try:
                    if hasattr(connector, "stop"):
                        connector.stop()
                except Exception:
                    pass

    _record_findings(results, engagement_id)
    return results


def _get_sniff_iter(connector):
    """Return a packet iterator from a connector, trying sniff() then stream()."""
    fn = getattr(connector, "sniff", None)
    if fn is not None:
        try:
            return fn(timeout=RF4CE_SNIFF_SECS)
        except TypeError:
            try:
                return fn()
            except Exception:
                return None
    fn = getattr(connector, "stream", None)
    if fn is not None:
        try:
            return fn()
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# dot15d4 fallback path
# ---------------------------------------------------------------------------

def _sniff_with_dot15d4(device: "WhadDongle", engagement_id: str) -> list[dict]:
    """Raw IEEE 802.15.4 sniffing on RF4CE channels via whad.dot15d4.Sniffer."""
    try:
        from whad.dot15d4 import Sniffer
    except ImportError:
        log.warning(
            "[S22] whad.dot15d4.Sniffer not importable — RF4CE sniff skipped. "
            "Upgrade WHAD for 802.15.4 support."
        )
        return []

    results: list[dict] = []
    seen_addrs: set[str] = set()

    for ch in RF4CE_CHANNELS:
        sniffer = None
        try:
            sniffer = Sniffer(device.device)
            sniffer.channel = ch
            sniffer.start()
            log.info(f"[S22][dot15d4] Listening on channel {ch} for {RF4CE_SNIFF_SECS}s")

            for pkt in sniffer.sniff(timeout=RF4CE_SNIFF_SECS):
                dev = _parse_packet(pkt, ch)
                if dev and dev["address"] not in seen_addrs:
                    seen_addrs.add(dev["address"])
                    results.append(dev)
                    log.info(f"[S22][dot15d4] Device: {dev['address']}  ch={ch}")

        except (AttributeError, NotImplementedError, ImportError) as exc:
            log.debug(f"[S22][dot15d4] ch{ch}: {exc}")
        except Exception as exc:
            log.debug(f"[S22][dot15d4] ch{ch} unexpected error: {type(exc).__name__}: {exc}")
        finally:
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass

    _record_findings(results, engagement_id)
    return results


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def _parse_packet(pkt, channel: int) -> dict | None:
    """Extract device info from a captured RF4CE / IEEE 802.15.4 packet.

    Returns None if no usable address can be extracted.
    """
    try:
        src = getattr(pkt, "src_addr", None) or getattr(pkt, "source_addr", None)
        dst = getattr(pkt, "dst_addr", None) or getattr(pkt, "dest_addr", None)
        if src is None and dst is None:
            return None
        address = str(src or dst)
        frame_type = getattr(pkt, "fcf_frametype", None)
        return {
            "address": address,
            "src": str(src) if src else None,
            "dst": str(dst) if dst else None,
            "channel": channel,
            "type": _classify_frame(frame_type),
            "raw_hex": bytes(pkt).hex() if pkt else "",
        }
    except Exception:
        return None


def _classify_frame(frame_type) -> str:
    """Map 802.15.4 frame type integer to a human-readable label."""
    _TYPES: dict[int, str] = {0: "beacon", 1: "data", 2: "ack", 3: "command"}
    if frame_type is None:
        return "unknown"
    try:
        return _TYPES.get(int(frame_type), "unknown")
    except (ValueError, TypeError):
        return "unknown"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _record_findings(devices: list[dict], engagement_id: str) -> None:
    """Insert a Finding for each observed RF4CE device, plus a summary finding."""
    if not devices:
        return

    for dev in devices:
        insert_finding(Finding(
            type="rf4ce_device_observed",
            severity="info",
            target_addr=dev["address"],
            description=(
                f"RF4CE device observed on channel {dev['channel']} "
                f"(frame type: {dev['type']}). "
                "RF4CE is used by TV remotes, set-top boxes, and smart home controllers. "
                "JustWorks pairing transmits the link key in cleartext."
            ),
            remediation=(
                "Use RF4CE SecureChannel pairing (out-of-band key exchange) instead of "
                "JustWorks. Verify the device vendor implements RF4CE Security Level 5 "
                "(AES-128 CCM). Physically restrict RF exposure where possible."
            ),
            evidence={
                "address": dev["address"],
                "src": dev["src"],
                "dst": dev["dst"],
                "channel": dev["channel"],
                "frame_type": dev["type"],
                "raw_hex": dev["raw_hex"][:64],
            },
            engagement_id=engagement_id,
        ))
        log.info(f"FINDING [info] rf4ce_device_observed: {dev['address']}")

    # Aggregate finding to flag pairing-key risk
    insert_finding(Finding(
        type="rf4ce_traffic_detected",
        severity="medium",
        target_addr=devices[0]["address"],
        description=(
            f"RF4CE remote control traffic detected on channel(s) "
            f"{sorted({d['channel'] for d in devices})}. "
            f"{len(devices)} unique device address(es) observed. "
            "RF4CE JustWorks pairing exchanges the link key in cleartext — "
            "an attacker within RF range during pairing can capture the key "
            "and subsequently decrypt all traffic or inject commands."
        ),
        remediation=(
            "Prefer RF4CE SecureChannel (out-of-band key distribution). "
            "Audit device firmware for JustWorks pairing support and disable it "
            "if SecureChannel is available. Limit pairing to physically controlled "
            "environments. Replace legacy RF4CE devices with BLE-based alternatives "
            "where MITM-resistant pairing is required."
        ),
        evidence={
            "channels_observed": sorted({d["channel"] for d in devices}),
            "device_count": len(devices),
            "device_addresses": [d["address"] for d in devices],
        },
        engagement_id=engagement_id,
    ))
    log.info(
        f"FINDING [medium] rf4ce_traffic_detected: {len(devices)} device(s) "
        f"on channels {sorted({d['channel'] for d in devices})}"
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(devices: list[dict]) -> None:
    log.info("─" * 70)
    log.info(f"STAGE 22 SUMMARY — RF4CE RECON — {len(devices)} device(s) observed")
    log.info("─" * 70)
    if not devices:
        log.info(f"  No RF4CE traffic observed on channels {RF4CE_CHANNELS}.")
    else:
        log.info(f"  {'Address':<24}  {'Ch':<4}  Type")
        for d in devices:
            log.info(f"  {d['address']:<24}  {d['channel']:<4}  {d['type']}")
    log.info("─" * 70)
