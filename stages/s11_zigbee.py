"""
Stage 11 — IEEE 802.15.4 / ZigBee Reconnaissance

Uses the WHAD Python API to scan all 16 802.15.4 channels (11–26) for ZigBee
network activity.  Two operator-selectable modes:

  Passive (Sniffer):
    - Discovers ZigBee networks by PAN ID and device addresses
    - Automatically enables decryption and extracts recovered keys
    - Generates Findings for discovered networks, recovered keys, decrypted traffic

  Coordinator (rogue coordinator):
    - Creates a new ZigBee PAN with a known network key
    - Opens a join window on the highest-activity channel from the passive scan
    - Waits for end devices to join the rogue coordinator
    - Captures key material exchanged during association
    - Tests whether the environment enforces Install Code / pre-configured link keys
    - Finding: zigbee_coordinator_join (high if any device joins without install code)

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
from core.vulndb import match_zigbee, VulnMatch
import config

log = get_logger("s11_zigbee")

# 802.15.4 channels in the 2.4 GHz band (11–26)
CHANNELS = list(range(11, 27))

ZIGBEE_PER_CH_SECS = config.ZIGBEE_PER_CH_SECS  # dwell per channel
ZIGBEE_SCAN_SECS   = config.ZIGBEE_SCAN_SECS     # informational total
ZIGBEE_COORD_SECS  = config.ZIGBEE_COORD_SECS    # coordinator join window


# ---------------------------------------------------------------------------
# Energy Detection channel survey (Gap 1)
# ---------------------------------------------------------------------------

def _ed_channel_survey(dongle: WhadDongle) -> dict[int, Any]:
    """Run an energy detection scan on channels 11–26 using a ZigBee Coordinator.

    Returns a dict mapping channel number to ED value, or an empty dict if the
    hardware does not support perform_ed_scan().
    """
    ed_levels: dict[int, Any] = {}
    try:
        from whad.zigbee.connector.coordinator import Coordinator
        coord = Coordinator(dongle.device)
        coord.start()
        for ch in range(11, 27):
            try:
                ed = coord.perform_ed_scan(channel=ch)
                if ed is not None:
                    ed_levels[ch] = ed
                    log.debug(f"[S11][coord] ED scan ch{ch}: {ed}")
            except (AttributeError, NotImplementedError):
                log.debug("[S11][coord] perform_ed_scan() not supported on this hardware")
                continue
            except Exception as exc:
                log.debug(f"[S11][coord] perform_ed_scan() error: {exc}")
        try:
            coord.stop()
        except Exception:
            pass
    except ImportError:
        log.debug("[S11] whad.zigbee.connector.coordinator not available — ED survey skipped")
    except Exception as exc:
        log.debug(f"[S11] ED survey failed: {type(exc).__name__}: {exc}")
    return ed_levels


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: WhadDongle, engagement_id: str, mode: str = "passive") -> None:
    """Scan 802.15.4 channels 11-26 for ZigBee networks.

    Args:
        dongle: Active WHAD dongle.
        engagement_id: Engagement ID for Finding storage.
        mode: "passive" (default), "coordinator" (rogue PAN), or "enddevice" (join a real PAN).
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

    # Gap 1: ED scan survey — rank channels by energy before the sniffer pass.
    ed_levels = _ed_channel_survey(dongle)
    if ed_levels:
        hot = sorted(ed_levels, key=lambda c: ed_levels[c], reverse=True)
        log.info(
            "[S11] ED survey complete. Hot channels (descending energy): "
            + ", ".join(f"ch{c}={ed_levels[c]}" for c in hot[:6])
        )
        scan_order = hot + [c for c in CHANNELS if c not in hot]
    else:
        scan_order = list(CHANNELS)

    # {pan_id: {"channel": int, "devices": set[str], "pkt_count": int}}
    networks: dict[int, dict] = {}
    all_keys: list[bytes] = []
    decrypted_count = 0
    decrypted_sample: list[str] = []

    for ch in scan_order:
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

        # CVE matching: keys recovered in plaintext during join
        for vm in match_zigbee(key_in_plaintext=True):
            cve_finding = Finding(
                type="cve_match",
                severity=vm.severity,
                target_addr="ZigBee",
                description=f"{vm.cve + ': ' if vm.cve else ''}{vm.name} — {vm.summary}",
                remediation=vm.remediation,
                evidence={
                    "cve": vm.cve,
                    "vuln_name": vm.name,
                    "tags": list(vm.tags),
                    "references": list(vm.references),
                    "keys_recovered": len(all_keys),
                },
                engagement_id=engagement_id,
            )
            insert_finding(cve_finding)
            log.info(f"FINDING [{vm.severity}] cve_match: {vm.cve or vm.name}")

        # CVE matching: check for default Trust Center key
        _DEFAULT_TC_KEY = bytes.fromhex("5A6967426565416C6C69616E63653039")
        for k in all_keys:
            if k == _DEFAULT_TC_KEY:
                for vm in match_zigbee(default_tc_key=True):
                    cve_finding = Finding(
                        type="cve_match",
                        severity=vm.severity,
                        target_addr="ZigBee",
                        description=f"{vm.cve + ': ' if vm.cve else ''}{vm.name} — {vm.summary}",
                        remediation=vm.remediation,
                        evidence={
                            "cve": vm.cve,
                            "vuln_name": vm.name,
                            "tags": list(vm.tags),
                            "references": list(vm.references),
                            "default_tc_key_hex": k.hex(),
                        },
                        engagement_id=engagement_id,
                    )
                    insert_finding(cve_finding)
                    log.info(f"FINDING [{vm.severity}] cve_match: {vm.cve or vm.name} (default TC key)")
                break  # only emit once even if key appears multiple times

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

        # CVE matching: unencrypted transport (traffic was decryptable)
        for vm in match_zigbee(unencrypted_transport=True):
            cve_finding = Finding(
                type="cve_match",
                severity=vm.severity,
                target_addr="ZigBee",
                description=f"{vm.cve + ': ' if vm.cve else ''}{vm.name} — {vm.summary}",
                remediation=vm.remediation,
                evidence={
                    "cve": vm.cve,
                    "vuln_name": vm.name,
                    "tags": list(vm.tags),
                    "references": list(vm.references),
                    "decrypted_packet_count": decrypted_count,
                },
                engagement_id=engagement_id,
            )
            insert_finding(cve_finding)
            log.info(f"FINDING [{vm.severity}] cve_match: {vm.cve or vm.name}")

    _print_summary(networks, all_keys, decrypted_count)

    # Coordinator mode: open a rogue ZigBee PAN on the most active channel
    # and wait for end devices to join without an install code.
    if mode == "coordinator":
        best_ch = _best_channel(networks)
        _run_coordinator(dongle, engagement_id, best_ch)

    # EndDevice mode: join a real ZigBee network as a device, capture group traffic.
    if mode == "enddevice":
        if networks:
            best_pan, best_info = max(
                networks.items(), key=lambda kv: kv[1]["pkt_count"]
            )
            _run_enddevice(dongle, engagement_id, best_info["channel"], best_pan)
        else:
            log.warning(
                "[S11] EndDevice mode: no ZigBee networks found in passive scan. "
                "Specify channel manually or run passive scan first."
            )


# ---------------------------------------------------------------------------
# ZigBee Coordinator (rogue PAN)
# ---------------------------------------------------------------------------

def _coord_send_test_frame(coordinator) -> None:
    """Send a ZigBee beacon request from coordinator to enumerate nearby devices."""
    try:
        from scapy.contrib.zigbee import ZigBeeBeaconPayload, Dot15d4, Dot15d4FCS  # noqa: F401
        pkt = Dot15d4() / ZigBeeBeaconPayload()
        coordinator.send(pkt)
        log.debug("[S11][coord] test beacon injected via coordinator.send()")
    except (AttributeError, ImportError, Exception) as exc:
        log.debug(f"[S11][coord] coordinator.send() skipped: {exc}")


def _best_channel(networks: dict) -> int:
    """Return the channel with the most traffic, default 15 if nothing seen."""
    if not networks:
        return 15
    return max(networks, key=lambda pan: networks[pan]["pkt_count"])


def _run_coordinator(
    dongle: WhadDongle,
    engagement_id: str,
    channel: int,
) -> None:
    """Open a rogue ZigBee coordinator on `channel` and capture joining devices.

    Creates a ZigBee PAN using a known network key so any device that joins
    without install-code enforcement will exchange key material in plaintext.
    Finding: zigbee_coordinator_join (high severity per device that joins).
    """
    try:
        from whad.zigbee.connector.coordinator import Coordinator
    except ImportError:
        log.warning(
            "[S11][coord] whad.zigbee.connector.coordinator not importable — "
            "coordinator mode skipped. Upgrade WHAD for ZigBee Coordinator support."
        )
        return

    log.info(
        f"[S11][coord] Starting rogue ZigBee coordinator on channel {channel} "
        f"(join window: {ZIGBEE_COORD_SECS}s) ..."
    )
    log.info(
        "[S11][coord] Waiting for end devices to join. "
        "Devices that join without install-code enforcement will transmit "
        "their network key in plaintext during association."
    )

    joined_devices: list[dict] = []

    try:
        coord = Coordinator(dongle.device)
        coord.channel = channel

        # Set up join callback before starting.
        def _on_join(device_addr: str, key_material: bytes | None = None) -> None:
            entry = {
                "address": str(device_addr),
                "key_hex": key_material.hex() if key_material else None,
            }
            joined_devices.append(entry)
            log.info(
                f"[S11][coord] Device joined: {device_addr} "
                + (f"key={key_material.hex()}" if key_material else "(no key captured)")
            )

        # WHAD Coordinator may expose on_device_join or a similar callback hook.
        if hasattr(coord, "on_device_join"):
            coord.on_device_join = _on_join

        coord.start()

        # Gap 2: attempt proper network formation if the API supports it.
        try:
            if hasattr(coord, "start_network"):
                coord.start_network(channel=channel)
                log.info(f"[S11][coord] start_network() called on ch{channel}")
            elif hasattr(coord, "network_formation"):
                coord.network_formation()
                log.info("[S11][coord] network_formation() called")
        except Exception as exc:
            log.debug(f"[S11][coord] network init method failed: {exc}")

        # Open join permit — duration varies by WHAD version.
        try:
            coord.open_join_window(duration=ZIGBEE_COORD_SECS)
        except (AttributeError, TypeError):
            # Older API: just run for the window duration passively.
            log.debug(
                "[S11][coord] open_join_window() not available — "
                "listening passively for joins."
            )

        # Gap 3: inject a beacon request to solicit responses from nearby devices.
        _coord_send_test_frame(coord)

        deadline = time.time() + ZIGBEE_COORD_SECS
        import threading as _threading
        _coord_stop = _threading.Event()

        def _coord_stream_reader():
            try:
                for pkt in coord.stream():
                    if _coord_stop.is_set():
                        return
                    addr = getattr(pkt, "src_addr", None) or getattr(pkt, "source", None)
                    if addr:
                        key_bytes = getattr(pkt, "network_key", None)
                        _on_join(str(addr), bytes(key_bytes) if key_bytes else None)
            except (AttributeError, TypeError):
                # stream() not available — wait passively until stop event
                _coord_stop.wait(timeout=ZIGBEE_COORD_SECS)
            except Exception as exc:
                if not _coord_stop.is_set():
                    log.debug(f"[S11][coord] stream: {type(exc).__name__}: {exc}")

        t = _threading.Thread(target=_coord_stream_reader, daemon=True)
        t.start()
        t.join(timeout=ZIGBEE_COORD_SECS)
        _coord_stop.set()
        try:
            coord.stop()
        except Exception:
            pass
        t.join(timeout=3.0)

    except Exception as exc:
        log.warning(
            f"[S11][coord] Coordinator init/start failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return
    finally:
        try:
            coord.stop()
        except Exception:
            pass

    log.info(
        f"[S11][coord] Join window closed. "
        f"{len(joined_devices)} device(s) joined."
    )

    if joined_devices:
        for dev in joined_devices:
            finding = Finding(
                type="zigbee_coordinator_join",
                severity="high",
                target_addr=dev["address"],
                description=(
                    f"ZigBee end device {dev['address']} joined a rogue coordinator "
                    f"on channel {channel} without requiring an install code. "
                    + (
                        f"Network key captured: {dev['key_hex']}."
                        if dev.get("key_hex")
                        else "No key material captured (device may use pre-installed key)."
                    )
                ),
                remediation=(
                    "Enable Install Code provisioning (ZigBee 3.0 mandatory feature) "
                    "on all end devices and the legitimate coordinator. "
                    "Install codes ensure the network key is never transmitted in "
                    "the clear during association. Reject join requests that lack a "
                    "valid install-code-derived link key."
                ),
                evidence={
                    "device_address": dev["address"],
                    "channel": channel,
                    "key_captured": dev.get("key_hex"),
                    "join_window_seconds": ZIGBEE_COORD_SECS,
                },
                engagement_id=engagement_id,
            )
            insert_finding(finding)
            log.info(
                f"FINDING [high] zigbee_coordinator_join: {dev['address']}"
            )

    log.info("\n" + "─" * 76)
    log.info("  STAGE 11 (coordinator) — ZigBee Rogue Coordinator")
    log.info("─" * 76)
    log.info(f"  {'Channel':<28}: {channel}")
    log.info(f"  {'Join window':<28}: {ZIGBEE_COORD_SECS}s")
    log.info(f"  {'Devices that joined':<28}: {len(joined_devices)}")
    for d in joined_devices:
        key_str = d['key_hex'] if d.get('key_hex') else "(no key)"
        log.info(f"    {d['address']}  key={key_str}")
    log.info("─" * 76 + "\n")


# ---------------------------------------------------------------------------
# ZigBee EndDevice (join a real PAN, capture group traffic)
# ---------------------------------------------------------------------------

def _enddev_send_test_frame(end_device) -> None:
    """Send a ZigBee data frame from the joined end device."""
    try:
        from scapy.contrib.zigbee import ZigBee
        pkt = ZigBee(frametype=0b00)  # data frame
        end_device.send(pkt)
        log.debug("[S11][end] test data frame sent via end_device.send()")
    except (AttributeError, ImportError, Exception) as exc:
        log.debug(f"[S11][end] end_device.send() skipped: {exc}")


def _run_enddevice(
    dongle: WhadDongle,
    engagement_id: str,
    channel: int,
    pan_id: int,
) -> None:
    """Join a real ZigBee network as an EndDevice and capture group/broadcast traffic.

    Uses whad.zigbee.connector.enddevice.EndDevice. On successful association the
    device receives broadcast/group frames and can inject application commands.

    Finding: zigbee_enddevice_joined (critical) — we joined without a valid link key,
    proving the network does not enforce install-code or pre-configured key policy.
    """
    try:
        from whad.zigbee.connector.enddevice import EndDevice
    except ImportError:
        log.warning(
            "[S11] whad.zigbee.connector.enddevice not importable — "
            "EndDevice mode requires WHAD with ZigBee EndDevice support."
        )
        return

    log.info(
        f"[S11] EndDevice joining PAN 0x{pan_id:04X} on channel {channel} ..."
    )
    log.info(
        f"\n  [S11] ZigBee EndDevice join: PAN 0x{pan_id:04X}  channel {channel}"
    )

    joined = False
    frames_received: list[str] = []
    join_timeout = getattr(config, "ZIGBEE_COORD_SECS", 60)

    try:
        enddevice = EndDevice(dongle.device)
        enddevice.channel = channel
        enddevice.start()

        # Gap 4: try the high-level discover_networks() API before manual channel scan.
        try:
            networks = enddevice.discover_networks()
            if networks:
                log.info(
                    f"[S11][end] discover_networks() found {len(list(networks))} network(s)"
                )
        except (AttributeError, NotImplementedError, TypeError):
            log.debug("[S11][end] discover_networks() not available — using manual scan")
        except Exception as exc:
            log.debug(f"[S11][end] discover_networks() error: {exc}")

        # Attempt association — API varies; try join(pan_id) then associate()
        for method_name in ("join", "associate", "connect"):
            fn = getattr(enddevice, method_name, None)
            if fn is None:
                continue
            try:
                result = fn(pan_id)
                joined = bool(result) if isinstance(result, bool) else True
                log.info(f"[S11] EndDevice.{method_name}(0x{pan_id:04X}) → {result}")
                break
            except Exception as exc:
                log.debug(f"[S11] {method_name}(0x{pan_id:04X}): {exc}")

        if not joined:
            # Some EndDevice implementations auto-associate on start()
            # — check after a brief wait
            time.sleep(2)
            joined = bool(
                getattr(enddevice, "associated", False)
                or getattr(enddevice, "joined", False)
                or getattr(enddevice, "is_joined", False)
            )

        if not joined:
            log.info(
                "[S11] EndDevice did not associate. "
                "Network may require install codes or pre-configured link keys."
            )
            _record_enddevice_rejected(engagement_id, channel, pan_id)
            return

        log.info(f"[S11] *** Joined ZigBee PAN 0x{pan_id:04X} as EndDevice! ***")
        log.info(f"  [S11] Association accepted! Listening for group traffic ...")

        # Gap 5: inject a test application data frame to probe injection capability.
        _enddev_send_test_frame(enddevice)

        deadline = time.time() + join_timeout
        for pkt in _enddevice_stream(enddevice, deadline):
            hex_repr = bytes(pkt).hex() if pkt else ""
            if hex_repr:
                frames_received.append(hex_repr[:64])
                log.info(f"[S11] Frame: {hex_repr[:64]}")
                if len(frames_received) >= 50:
                    break

    except Exception as exc:
        log.warning(f"[S11] EndDevice error: {type(exc).__name__}: {exc}")
        return
    finally:
        try:
            enddevice.stop()
        except Exception:
            pass

    if joined:
        _record_enddevice_joined(engagement_id, channel, pan_id, frames_received)


def _enddevice_stream(enddevice, deadline: float):
    """Yield packets from an EndDevice until deadline, handling API variations."""
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            # Stream/sniff API
            fn = getattr(enddevice, "stream", None) or getattr(enddevice, "sniff", None)
            if fn:
                for pkt in fn(timeout=min(3.0, remaining)):
                    yield pkt
                    if time.time() >= deadline:
                        return
            else:
                # wait_packet API
                wpkt = getattr(enddevice, "wait_packet", None)
                if wpkt:
                    pkt = wpkt(timeout=min(2.0, remaining))
                    if pkt:
                        yield pkt
                else:
                    time.sleep(1.0)
        except StopIteration:
            break
        except Exception as exc:
            log.debug(f"[S11] EndDevice stream: {exc}")
            time.sleep(0.5)


def _record_enddevice_joined(
    engagement_id: str, channel: int, pan_id: int, frames: list[str]
) -> None:
    insert_finding(Finding(
        type="zigbee_enddevice_joined",
        severity="critical",
        target_addr=f"zigbee_pan_{pan_id:04x}",
        description=(
            f"Successfully joined ZigBee PAN 0x{pan_id:04X} on channel {channel} "
            f"as an EndDevice without a pre-configured link key or install code. "
            f"{len(frames)} broadcast/group frame(s) received after association. "
            "An attacker can inject ZigBee application commands as a legitimate device."
        ),
        remediation=(
            "Enable ZigBee Trust Center Link Key (TCLK) policy requiring install codes "
            "(ZigBee 3.0 mandatory). Disable permit joining except during commissioning. "
            "Audit all devices allowed to join. Use ZigBee Security Level 5 (AES-128)."
        ),
        evidence={
            "pan_id": f"0x{pan_id:04X}",
            "channel": channel,
            "frames_received": len(frames),
            "sample_frames": frames[:5],
        },
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [critical] zigbee_enddevice_joined: PAN 0x{pan_id:04X}")


def _record_enddevice_rejected(
    engagement_id: str, channel: int, pan_id: int
) -> None:
    insert_finding(Finding(
        type="zigbee_enddevice_rejected",
        severity="info",
        target_addr=f"zigbee_pan_{pan_id:04x}",
        description=(
            f"ZigBee EndDevice join attempt to PAN 0x{pan_id:04X} on channel {channel} "
            "was rejected. Network may enforce install codes or pre-configured link keys."
        ),
        remediation=(
            "Good — install code enforcement is active. "
            "Verify all devices use unique install codes and the Trust Center "
            "enforces TCLK uniqueness. Periodic audit of joined device list."
        ),
        evidence={"pan_id": f"0x{pan_id:04X}", "channel": channel},
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [info] zigbee_enddevice_rejected: PAN 0x{pan_id:04X}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(
    networks: dict,
    keys: list[bytes],
    decrypted: int,
) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 11 SUMMARY -- IEEE 802.15.4 / ZigBee Reconnaissance")
    log.info("─" * 76)
    log.info(f"  {'Channels scanned':<28}: {len(CHANNELS)} (11-26)")
    log.info(f"  {'Networks discovered':<28}: {len(networks)}")
    log.info(f"  {'Keys recovered':<28}: {len(keys)}")
    log.info(f"  {'Packets decrypted':<28}: {decrypted}")
    if networks:

        log.info("  Networks:")
        for pan_id, info in networks.items():
            log.info(
                f"    PAN 0x{pan_id:04X}  ch={info['channel']:<3}  "
                f"pkts={info['pkt_count']:<5}  "
                f"devices={len(info['devices'])}"
            )
    log.info("─" * 76 + "\n")
