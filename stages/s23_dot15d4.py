"""Stage 23 — Raw IEEE 802.15.4 Reconnaissance

Passively sniffs raw 802.15.4 frames across all 16 channels (11-26) to
identify devices using any 802.15.4-based protocol: ZigBee, Thread, RF4CE,
WirelessHART, 6LoWPAN, or proprietary stacks.

Uses whad.dot15d4.Sniffer. Falls back to whad.dot15d4.Scanner or
whad.dot15d4.Coordinator if Sniffer is not available.

Complements S11 (ZigBee-specific) by operating at the raw MAC layer without
protocol assumptions. Useful when the upper-layer protocol is unknown or when
the environment mixes multiple 802.15.4-based stacks.
"""
from __future__ import annotations

import time
from typing import Any

from core.dongle import WhadDongle
from core.logger import get_logger
from core.models import Finding
from core.db import insert_finding
import config

log = get_logger("s23_dot15d4")

DOT15D4_CHANNELS = list(range(11, 27))  # 2.4 GHz channels 11-26
DOT15D4_PER_CH_SECS = getattr(config, "DOT15D4_PER_CH_SECS", 5)


# ---------------------------------------------------------------------------
# Protocol identification
# ---------------------------------------------------------------------------

# 802.15.4 frame type field (bits 2-0 of Frame Control low byte)
_FC_FRAME_TYPE_MASK = 0x07
_FC_FRAME_TYPES = {
    0: "Beacon",
    1: "Data",
    2: "ACK",
    3: "MAC Command",
    4: "Reserved",
    5: "Multipurpose",
    6: "Fragment/Frak",
    7: "Extended",
}


def _identify_protocol(payload: bytes) -> str:
    """Heuristically classify the upper-layer protocol from the MAC payload.

    Args:
        payload: Raw bytes of the MAC frame payload (after FCS stripped).

    Returns:
        Human-readable protocol label string.
    """
    if not payload or len(payload) < 2:
        return "unknown"

    first = payload[0]
    second = payload[1] if len(payload) > 1 else 0

    # ZigBee NWK layer: Frame Control byte has frame type in bits 1-0.
    # ZigBee NWK data frame = 0x08/0x09 (type bits = 00, version bits = 10).
    # ZigBee command frame has type bits = 01 (0x09/0x0D variants).
    if first in (0x08, 0x09, 0x48, 0x49):
        return "ZigBee"

    # 6LoWPAN dispatch byte ranges (RFC 4944 / RFC 6282):
    #   0x41-0x4F: LOWPAN_IPHCv1 (IPv6 header compression)
    #   0x60-0x7F: LOWPAN_IPHC (RFC 6282 compressed IPv6)
    #   0x7N: LOWPAN_NHC
    # Thread uses 6LoWPAN, so this also catches Thread.
    if 0x41 <= first <= 0x4F:
        return "6LoWPAN / Thread (IPHCv1)"
    if 0x60 <= first <= 0x7F:
        return "6LoWPAN / Thread (IPHC)"
    if first == 0x3F:
        return "6LoWPAN (fragment)"
    if first == 0xC0:
        return "6LoWPAN (broadcast)"

    # WirelessHART: starts with a distinctive 2-byte preamble 0xFF 0xFF
    # followed by a start delimiter 0x02/0x06 (STX).
    if first == 0xFF and second == 0xFF and len(payload) >= 3 and payload[2] in (0x02, 0x06):
        return "WirelessHART"

    # RF4CE: Network layer frame control. RF4CE frames use a 1-byte network
    # frame control where bits 1-0 indicate frame type: 00=data, 01=command.
    # RF4CE profile IDs occupy 0x01-0x0F; vendor-specific starts at 0xC0.
    if first in (0x01, 0x41) and second in range(0x01, 0x10):
        return "RF4CE"

    # MiWi: Microchip proprietary stack built on 802.15.4.
    # Frame control byte 0x61/0x63 is characteristic of MiWi data frames.
    if first in (0x61, 0x63):
        return "MiWi (proprietary)"

    return "proprietary/unknown"


def _frame_type_label(fc_byte: int) -> str:
    """Return the 802.15.4 frame type name from the low byte of Frame Control."""
    return _FC_FRAME_TYPES.get(fc_byte & _FC_FRAME_TYPE_MASK, "unknown")


# ---------------------------------------------------------------------------
# Sniffer import helpers
# ---------------------------------------------------------------------------

def _import_sniffer():
    """Try importing a usable dot15d4 sniffer class.

    Returns:
        (sniffer_class, api_label) or (None, None) if nothing is available.
    """
    for module_path, class_name in (
        ("whad.dot15d4", "Sniffer"),
        ("whad.dot15d4.connector.sniffer", "Sniffer"),
        ("whad.dot15d4", "Scanner"),
        ("whad.dot15d4.connector.scanner", "Scanner"),
        ("whad.dot15d4", "Coordinator"),
        ("whad.dot15d4.connector.coordinator", "Coordinator"),
    ):
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name, None)
            if cls is not None:
                return cls, f"{module_path}.{class_name}"
        except ImportError:
            continue
    return None, None


# ---------------------------------------------------------------------------
# Per-channel scan
# ---------------------------------------------------------------------------

def _sniff_channel(
    sniffer_cls,
    device,
    channel: int,
    dwell: float,
) -> list[dict[str, Any]]:
    """Sniff one channel for dwell seconds, return list of parsed frame dicts.

    Args:
        sniffer_cls: The imported WHAD dot15d4 connector class.
        device: WhadDevice instance from the dongle.
        channel: 802.15.4 channel number (11-26).
        dwell: Seconds to listen on this channel.

    Returns:
        List of dicts with keys: src_addr, dst_addr, pan_id, frame_type,
        sequence_number, protocol, raw_hex.
    """
    frames: list[dict[str, Any]] = []
    try:
        sniffer = sniffer_cls(device)
        sniffer.channel = channel

        deadline = time.time() + dwell
        for pkt in sniffer.sniff(timeout=dwell):
            frame = _parse_packet(pkt)
            if frame:
                frames.append(frame)
            if time.time() >= deadline:
                break

        try:
            sniffer.stop()
        except Exception:
            pass

    except Exception as exc:
        log.debug(f"[S23] ch={channel} sniff error: {type(exc).__name__}: {exc}")

    return frames


def _parse_packet(pkt) -> dict[str, Any] | None:
    """Extract fields from a raw 802.15.4 packet object.

    Args:
        pkt: Packet object from WHAD sniffer.

    Returns:
        Dict with frame fields, or None if the packet is not parseable.
    """
    src_addr = (
        getattr(pkt, "src_addr", None)
        or getattr(pkt, "source", None)
        or getattr(pkt, "src", None)
    )
    dst_addr = (
        getattr(pkt, "dst_addr", None)
        or getattr(pkt, "dest", None)
        or getattr(pkt, "dst", None)
    )
    pan_id = (
        getattr(pkt, "src_panid", None)
        or getattr(pkt, "dest_panid", None)
        or getattr(pkt, "panid", None)
        or getattr(pkt, "pan_id", None)
    )
    seqnum = (
        getattr(pkt, "seqnum", None)
        or getattr(pkt, "sequence_number", None)
        or getattr(pkt, "seq", None)
    )

    # Frame control byte — used to derive frame type
    fc_raw = getattr(pkt, "fcf", None) or getattr(pkt, "frame_control", None)
    fc_byte = int(fc_raw) if fc_raw is not None else 0
    frame_type = _frame_type_label(fc_byte)

    # Raw payload for protocol identification
    try:
        raw = bytes(pkt)
    except Exception:
        raw = b""

    # The MAC payload follows the MAC header; for heuristics we use the full
    # frame bytes since header size varies. Pass all bytes to the identifier.
    protocol = _identify_protocol(raw[3:] if len(raw) > 3 else raw)

    if src_addr is None and dst_addr is None and pan_id is None:
        return None

    return {
        "src_addr": str(src_addr) if src_addr is not None else None,
        "dst_addr": str(dst_addr) if dst_addr is not None else None,
        "pan_id":   int(pan_id) if pan_id is not None else None,
        "frame_type": frame_type,
        "sequence_number": int(seqnum) if seqnum is not None else None,
        "protocol": protocol,
        "raw_hex": raw.hex()[:64],
    }


# ---------------------------------------------------------------------------
# Result accumulation
# ---------------------------------------------------------------------------

def _accumulate(
    frames: list[dict[str, Any]],
    channel: int,
    devices: dict[str, dict],
    pan_stats: dict[int, dict],
) -> None:
    """Merge per-channel frames into the global device and PAN tables.

    Args:
        frames: Frames returned by _sniff_channel for this channel.
        channel: Channel the frames were captured on.
        devices: Global device address map (mutated in place).
        pan_stats: Global PAN stats map (mutated in place).
    """
    for f in frames:
        for addr_key in ("src_addr", "dst_addr"):
            addr = f.get(addr_key)
            if addr and addr not in ("None", "0xFFFF", "65535"):
                if addr not in devices:
                    devices[addr] = {
                        "first_channel": channel,
                        "channels": set(),
                        "protocols": set(),
                        "frame_count": 0,
                    }
                    log.info(
                        f"[S23] New device: {addr}  ch={channel}  "
                        f"protocol={f['protocol']}"
                    )
                devices[addr]["channels"].add(channel)
                devices[addr]["protocols"].add(f["protocol"])
                devices[addr]["frame_count"] += 1

        pan_id = f.get("pan_id")
        if pan_id is not None and pan_id not in (0xFFFF, 65535):
            if pan_id not in pan_stats:
                pan_stats[pan_id] = {
                    "channel": channel,
                    "frame_count": 0,
                    "protocols": set(),
                    "device_addrs": set(),
                }
                log.info(
                    f"[S23] New PAN: 0x{pan_id:04X}  ch={channel}  "
                    f"protocol={f['protocol']}"
                )
            pan_stats[pan_id]["frame_count"] += 1
            pan_stats[pan_id]["protocols"].add(f["protocol"])
            src = f.get("src_addr")
            if src and src not in ("None", "0xFFFF", "65535"):
                pan_stats[pan_id]["device_addrs"].add(src)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _emit_findings(
    devices: dict[str, dict],
    pan_stats: dict[int, dict],
    engagement_id: str,
) -> None:
    """Create one Finding per discovered PAN and a summary Finding for devices.

    Args:
        devices: Device address map built during the scan.
        pan_stats: PAN stats map built during the scan.
        engagement_id: Engagement ID for Finding storage.
    """
    for pan_id, info in pan_stats.items():
        pan_hex = f"0x{pan_id:04X}"
        protocols = sorted(info["protocols"] - {"unknown", "proprietary/unknown"})
        protocol_str = ", ".join(protocols) if protocols else "unknown/proprietary"
        finding = Finding(
            type="dot15d4_pan_discovered",
            severity="medium",
            target_addr=pan_hex,
            description=(
                f"Raw IEEE 802.15.4 PAN discovered: PAN ID {pan_hex} "
                f"on channel {info['channel']}. "
                f"{info['frame_count']} frame(s) captured from "
                f"{len(info['device_addrs'])} device address(es). "
                f"Detected protocol(s): {protocol_str}. "
                "802.15.4 is the MAC layer for ZigBee, Thread, RF4CE, "
                "WirelessHART, 6LoWPAN, and proprietary stacks."
            ),
            remediation=(
                "Identify and inventory all 802.15.4 devices. "
                "Ensure upper-layer protocol security (ZigBee AES-128, "
                "Thread commissioning, WirelessHART HMAC-MD5). "
                "Segregate 802.15.4 traffic from IT networks using "
                "dedicated coordinators with access control lists."
            ),
            evidence={
                "pan_id_hex": pan_hex,
                "channel": info["channel"],
                "frame_count": info["frame_count"],
                "device_count": len(info["device_addrs"]),
                "device_addresses": list(info["device_addrs"])[:20],
                "protocols_detected": list(info["protocols"]),
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [medium] dot15d4_pan_discovered: {pan_hex}")

    if devices:
        addr_list = list(devices.keys())[:50]
        all_protocols: set[str] = set()
        for d in devices.values():
            all_protocols |= d["protocols"]
        finding = Finding(
            type="dot15d4_devices_enumerated",
            severity="low",
            target_addr="802.15.4",
            description=(
                f"{len(devices)} unique 802.15.4 device address(es) observed "
                f"across {len(pan_stats)} PAN(s). "
                f"Protocol(s) detected: "
                f"{', '.join(sorted(all_protocols - {'unknown', 'proprietary/unknown'})) or 'unknown'}. "
                "Device addresses may be used to fingerprint specific hardware "
                "vendors and plan targeted attacks."
            ),
            remediation=(
                "Review device inventory against authorised asset list. "
                "Remove unauthorised or unrecognised devices. "
                "Implement 802.15.4 MAC-layer access control lists (ACLs) "
                "on coordinators where supported."
            ),
            evidence={
                "device_count": len(devices),
                "pan_count": len(pan_stats),
                "device_addresses": addr_list,
                "all_protocols": list(all_protocols),
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [low] dot15d4_devices_enumerated: "
            f"{len(devices)} device(s)"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: WhadDongle, engagement_id: str) -> list[dict]:
    """Scan 802.15.4 channels 11-26 for raw MAC-layer activity.

    Operates at the raw MAC layer without protocol assumptions, complementing
    S11 (ZigBee-specific). Identifies ZigBee, Thread, RF4CE, WirelessHART,
    6LoWPAN, and proprietary 802.15.4 stacks.

    Args:
        dongle: Active WHAD dongle with can_zigbee capability.
        engagement_id: Engagement ID for Finding storage.

    Returns:
        List of device dicts found (suitable for downstream stages).
    """
    sniffer_cls, api_label = _import_sniffer()
    if sniffer_cls is None:
        log.warning(
            "[S23] whad.dot15d4 not available — stage skipped. "
            "Install WHAD with dot15d4 support or upgrade WHAD."
        )
        return []

    log.info(
        f"[S23] Raw IEEE 802.15.4 scan: channels 11-26 "
        f"({DOT15D4_PER_CH_SECS}s per channel, "
        f"~{len(DOT15D4_CHANNELS) * DOT15D4_PER_CH_SECS}s total) "
        f"via {api_label}"
    )

    # {addr: {"first_channel": int, "channels": set, "protocols": set, "frame_count": int}}
    devices: dict[str, dict] = {}
    # {pan_id_int: {"channel": int, "frame_count": int, "protocols": set, "device_addrs": set}}
    pan_stats: dict[int, dict] = {}

    for ch in DOT15D4_CHANNELS:
        log.info(f"[S23] Channel {ch} ...")
        frames = _sniff_channel(sniffer_cls, dongle.device, ch, DOT15D4_PER_CH_SECS)
        if frames:
            log.info(f"[S23] Channel {ch}: {len(frames)} frame(s)")
        _accumulate(frames, ch, devices, pan_stats)

    if not devices and not pan_stats:
        log.info("[S23] No 802.15.4 activity detected across all channels.")
        _print_summary(devices, pan_stats)
        return []

    log.info(
        f"[S23] Scan complete: {len(pan_stats)} PAN(s), "
        f"{len(devices)} unique device address(es)."
    )

    _emit_findings(devices, pan_stats, engagement_id)
    _print_summary(devices, pan_stats)

    return [
        {
            "address": addr,
            "first_channel": info["first_channel"],
            "protocols": list(info["protocols"]),
            "frame_count": info["frame_count"],
        }
        for addr, info in devices.items()
    ]


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(
    devices: dict[str, dict],
    pan_stats: dict[int, dict],
) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 23 SUMMARY -- Raw IEEE 802.15.4 Reconnaissance")
    log.info("─" * 76)
    log.info(f"  {'Channels scanned':<30}: {len(DOT15D4_CHANNELS)} (11-26)")
    log.info(f"  {'PANs discovered':<30}: {len(pan_stats)}")
    log.info(f"  {'Unique device addresses':<30}: {len(devices)}")
    if pan_stats:

        log.info("  PANs:")
        for pan_id, info in sorted(pan_stats.items()):
            protocols = sorted(info["protocols"] - {"unknown", "proprietary/unknown"})
            proto_str = ", ".join(protocols) if protocols else "unknown"
            log.info(
                f"    PAN 0x{pan_id:04X}  ch={info['channel']:<3}  "
                f"frames={info['frame_count']:<5}  "
                f"devices={len(info['device_addrs'])}  "
                f"protocol={proto_str}"
            )
    if devices:

        log.info("  Devices (first 20):")
        for addr, info in list(devices.items())[:20]:
            protocols = sorted(info["protocols"] - {"unknown", "proprietary/unknown"})
            proto_str = ", ".join(protocols) if protocols else "unknown"
            log.info(
                f"    {addr:<24}  "
                f"ch={info['first_channel']:<3}  "
                f"frames={info['frame_count']:<4}  "
                f"protocol={proto_str}"
            )
    log.info("─" * 76 + "\n")
