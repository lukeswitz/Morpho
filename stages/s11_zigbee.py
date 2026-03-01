"""
Stage 11 — IEEE 802.15.4 / ZigBee Reconnaissance

Uses the WHAD Python API (whad.zigbee.Sniffer) to scan all 16 802.15.4
channels (11–26) for ZigBee network activity.

  - Discovers ZigBee networks by PAN ID and device addresses
  - Automatically enables decryption and extracts recovered keys
  - Generates Findings for discovered networks, recovered keys, and decrypted traffic
  - Passive mode only — no transmission

ZigBee is ubiquitous in building automation: smart locks, HVAC, lighting control,
access panels, and industrial sensors.  A ZigBee recon pass often reveals more
high-value targets than a BLE scan in enterprise/government environments.
"""

from __future__ import annotations

import time
from typing import Any

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s11_zigbee")

# 802.15.4 channels in the 2.4 GHz band (11–26)
CHANNELS = list(range(11, 27))

ZIGBEE_PER_CH_SECS = config.ZIGBEE_PER_CH_SECS  # dwell per channel
ZIGBEE_SCAN_SECS   = config.ZIGBEE_SCAN_SECS     # informational total


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: WhadDongle, engagement_id: str) -> None:
    """Scan 802.15.4 channels 11-26 for ZigBee networks.

    Args:
        dongle: Active WHAD dongle.
        engagement_id: Engagement ID for Finding storage.
    """
    try:
        from whad.zigbee import Sniffer
    except ImportError as exc:
        log.warning(f"[S11] whad.zigbee not available — stage skipped. ({exc})")
        return

    log.info(
        f"[S11] Scanning 802.15.4 channels 11-26 "
        f"({ZIGBEE_PER_CH_SECS}s per channel, "
        f"~{len(CHANNELS) * ZIGBEE_PER_CH_SECS}s total) ..."
    )

    # {pan_id: {"channel": int, "devices": set[str], "pkt_count": int}}
    networks: dict[int, dict] = {}
    all_keys: list[bytes] = []
    decrypted_count = 0
    decrypted_sample: list[str] = []

    for ch in CHANNELS:
        log.info(f"[S11] Channel {ch} ...")
        try:
            sniffer = Sniffer(dongle.device)
            sniffer.decrypt = True
            sniffer.channel = ch

            deadline = time.time() + ZIGBEE_PER_CH_SECS
            for pkt in sniffer.sniff(timeout=ZIGBEE_PER_CH_SECS):
                # Extract PAN ID from the 802.15.4 frame header.
                pan_id = (
                    getattr(pkt, "src_panid", None)
                    or getattr(pkt, "dest_panid", None)
                    or getattr(pkt, "panid", None)
                )
                if pan_id is None:
                    continue
                pan_int = int(pan_id) if not isinstance(pan_id, int) else pan_id

                if pan_int not in networks:
                    networks[pan_int] = {
                        "channel": ch,
                        "devices": set(),
                        "pkt_count": 0,
                    }
                    log.info(
                        f"[S11] New ZigBee network: PAN=0x{pan_int:04X} ch={ch}"
                    )

                networks[pan_int]["pkt_count"] += 1

                src = (
                    getattr(pkt, "src_addr", None)
                    or getattr(pkt, "source", None)
                )
                if src is not None:
                    networks[pan_int]["devices"].add(str(src))

                # Check if this packet was decrypted automatically.
                if getattr(pkt, "decrypted", False) or getattr(pkt, "is_decrypted", False):
                    decrypted_count += 1
                    if len(decrypted_sample) < 5:
                        try:
                            decrypted_sample.append(bytes(pkt).hex())
                        except Exception:
                            pass

                if time.time() >= deadline:
                    break

            # Collect recovered keys after each channel scan.
            try:
                keys = getattr(sniffer.configuration, "keys", [])
                for k in (keys or []):
                    k_bytes = bytes(k) if not isinstance(k, bytes) else k
                    if k_bytes not in all_keys:
                        all_keys.append(k_bytes)
                        log.info(f"[S11] Key recovered: {k_bytes.hex()}")
            except Exception as exc:
                log.debug(f"[S11] Key extraction ch={ch}: {exc}")

            try:
                sniffer.stop()
            except Exception:
                pass

        except Exception as exc:
            log.debug(f"[S11] ch={ch} error: {type(exc).__name__}: {exc}")

    # --- Generate Findings ---

    if not networks:
        log.info("[S11] No ZigBee networks detected across all channels.")
        _print_summary(networks, all_keys, decrypted_count)
        return

    log.info(
        f"[S11] {len(networks)} network(s) found, "
        f"{len(all_keys)} key(s) recovered, "
        f"{decrypted_count} packet(s) decrypted."
    )

    for pan_id, info in networks.items():
        pan_hex = f"0x{pan_id:04X}"
        finding = Finding(
            type="zigbee_network_discovered",
            severity="medium",
            target_addr=pan_hex,
            description=(
                f"ZigBee network discovered: PAN ID {pan_hex} on channel {info['channel']}. "
                f"{info['pkt_count']} packet(s) captured from "
                f"{len(info['devices'])} device address(es). "
                "ZigBee is commonly used in smart locks, HVAC, and building access systems."
            ),
            remediation=(
                "Ensure all ZigBee devices use AES-128 encryption (ZigBee PRO). "
                "Rotate network keys periodically. Replace default network keys "
                "shipped with devices. Audit all ZigBee coordinator join policies — "
                "open join windows are a common attack vector."
            ),
            evidence={
                "pan_id_hex": pan_hex,
                "channel": info["channel"],
                "device_count": len(info["devices"]),
                "device_addresses": list(info["devices"])[:20],
                "packet_count": info["pkt_count"],
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [medium] zigbee_network_discovered: {pan_hex}")

    if all_keys:
        finding = Finding(
            type="zigbee_keys_recovered",
            severity="high",
            target_addr="ZigBee",
            description=(
                f"{len(all_keys)} ZigBee network key(s) recovered from passive "
                "channel monitoring. Keys were transmitted in plaintext during "
                "device join/re-join and captured without authentication."
            ),
            remediation=(
                "Use pre-installed link keys for all device joins — never "
                "transport network keys in the clear. Enable Install Code "
                "provisioning (ZigBee 3.0) to ensure encrypted key exchange."
            ),
            evidence={
                "key_count": len(all_keys),
                "keys_hex": [k.hex() for k in all_keys],
                "pan_ids_hex": [f"0x{p:04X}" for p in networks],
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [high] zigbee_keys_recovered: {len(all_keys)} key(s)")

    if decrypted_count > 0:
        pan_list = ", ".join(f"0x{p:04X}" for p in networks)
        finding = Finding(
            type="zigbee_traffic_decrypted",
            severity="high",
            target_addr="ZigBee",
            description=(
                f"{decrypted_count} ZigBee packet(s) automatically decrypted "
                f"using recovered network key(s). PAN(s): {pan_list}. "
                "Application-layer commands and sensor readings may be exposed."
            ),
            remediation=(
                "Rotate network keys immediately. Implement application-layer "
                "encryption in addition to ZigBee network-layer AES-128 where "
                "data sensitivity warrants it."
            ),
            evidence={
                "decrypted_packet_count": decrypted_count,
                "sample_payloads_hex": decrypted_sample,
                "pan_ids_hex": [f"0x{p:04X}" for p in networks],
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [high] zigbee_traffic_decrypted: {decrypted_count} packet(s)"
        )

    _print_summary(networks, all_keys, decrypted_count)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(
    networks: dict,
    keys: list[bytes],
    decrypted: int,
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 11 SUMMARY -- IEEE 802.15.4 / ZigBee Reconnaissance")
    print("─" * 76)
    print(f"  {'Channels scanned':<28}: {len(CHANNELS)} (11-26)")
    print(f"  {'Networks discovered':<28}: {len(networks)}")
    print(f"  {'Keys recovered':<28}: {len(keys)}")
    print(f"  {'Packets decrypted':<28}: {decrypted}")
    if networks:
        print()
        print("  Networks:")
        for pan_id, info in networks.items():
            print(
                f"    PAN 0x{pan_id:04X}  ch={info['channel']:<3}  "
                f"pkts={info['pkt_count']:<5}  "
                f"devices={len(info['devices'])}"
            )
    print("─" * 76 + "\n")
