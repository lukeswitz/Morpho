"""
Stage 17 — YardStickOne sub-GHz PHY Survey

Uses the WHAD Python API (whad.phy.Sniffer) to map RF activity across
sub-GHz ISM bands via a YardStickOne (300-928 MHz).

YardStickOne supports three frequency sub-bands:
  300-348 MHz  — 433 MHz-adjacent devices, legacy ISM
  391-464 MHz  — 433 MHz ISM band (garage doors, remotes, weather stations)
  782-928 MHz  — 868/915 MHz ISM (Z-Wave, LoRa devices, smart meters, alarms)

This reveals RF transmitters invisible to BLE/ZigBee/ESB scanners:
  - Wireless alarm systems (433/868 MHz)
  - Smart meter mesh networks (868/915 MHz)
  - Z-Wave home automation nodes
  - Wireless doorbells and remote controls
  - Proprietary sensor networks
  - Sub-GHz covert transmitters / RF exfiltration channels

Passive only — receive only, no transmission.
"""

from __future__ import annotations

import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s17_subghz")

# YardStickOne supported frequency sub-bands (MHz)
# https://greatscottgadgets.com/yardstickone/
_BAND_300 = list(range(300, 349, 2))   # 300-348 MHz, 25 frequencies
_BAND_400 = list(range(391, 465, 2))   # 391-464 MHz, 37 frequencies
_BAND_900 = list(range(782, 929, 2))   # 782-928 MHz, 74 frequencies
_ALL_FREQS = _BAND_300 + _BAND_400 + _BAND_900  # 136 total

# Modulation parameters for GFSK (covers most sub-GHz ISM devices)
_GFSK_DATARATE  = 50_000    # 50 kbps — common for Z-Wave, 433 MHz remotes
_GFSK_DEVIATION = 20_000    # 20 kHz deviation

# OOK (On-Off Keying) / ASK sweep — high-priority frequencies only.
# Most 433 MHz ISM remotes, garage doors, doorbells, and alarm sensors use OOK,
# not GFSK. A GFSK sweep will not decode them. We do a focused OOK pass over
# the most-used OOK center frequencies rather than a full band sweep.
_OOK_FREQS_MHZ = [
    315,                    # North American remotes, keyfobs, sensors
    433, 434,               # 433.92 MHz ISM — most common worldwide OOK band
    868,                    # EU 868 MHz (also used by OOK alarm sensors)
    915,                    # US 915 MHz ISM OOK sensors
]
_OOK_DATARATE = 4_000       # 4 kbps typical for OOK remotes

SUBGHZ_PER_FREQ_SECS = config.SUBGHZ_PER_FREQ_SECS
SUBGHZ_SWEEP_SECS    = config.SUBGHZ_SWEEP_SECS

# Band width for aggregating results in the summary (MHz)
_BAND_STEP_MHZ = 5


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: WhadDongle, engagement_id: str) -> None:
    """Sweep sub-GHz ISM bands and map RF activity via YardStickOne.

    Args:
        dongle: YardStickOne WHAD dongle.
        engagement_id: Engagement ID for Finding storage.
    """
    PhySniffer = None
    for _phy_path in ("whad.phy", "whad.phy.connector.sniffer"):
        try:
            import importlib as _il
            _mod = _il.import_module(_phy_path)
            if hasattr(_mod, "Sniffer"):
                PhySniffer = _mod.Sniffer
                break
        except ImportError:
            continue
    if PhySniffer is None:
        log.warning("[S17] whad.phy not available — stage skipped.")
        return

    try:
        from whad.phy.sniffing import SnifferConfiguration
    except ImportError:
        try:
            from whad.phy import SnifferConfiguration
        except ImportError:
            log.warning("[S17] SnifferConfiguration not importable — stage skipped.")
            return

    log.info(
        f"[S17] Sweeping sub-GHz ISM bands "
        f"({len(_ALL_FREQS)} frequencies × {SUBGHZ_PER_FREQ_SECS}s = "
        f"~{len(_ALL_FREQS) * SUBGHZ_PER_FREQ_SECS}s) ..."
    )
    log.info(
        "[S17] Covering 300-348 MHz, 391-464 MHz, 782-928 MHz "
        "(alarms, Z-Wave, LoRa-adjacent, smart meters, remotes)."
    )

    # {band_start_mhz: {"pkt_count": int, "peak_rssi": int|None, "freqs_active": set}}
    band_activity: dict[int, dict] = {}
    total_packets = 0

    for freq_mhz in _ALL_FREQS:
        freq_hz = freq_mhz * 1_000_000
        log.debug(f"[S17] {freq_mhz} MHz ...")

        try:
            cfg = SnifferConfiguration()
            cfg.frequency  = freq_hz
            cfg.modulation = "GFSK"
            cfg.datarate   = _GFSK_DATARATE
            cfg.deviation  = _GFSK_DEVIATION
            cfg.max_pkt_size = 255

            sniffer = PhySniffer(dongle.device)
            sniffer.configuration = cfg

            pkts_here = 0
            peak_rssi: int | None = None
            deadline = time.time() + SUBGHZ_PER_FREQ_SECS

            for pkt in sniffer.sniff(timeout=SUBGHZ_PER_FREQ_SECS):
                pkts_here += 1
                total_packets += 1
                rssi = getattr(pkt, "rssi", None)
                if rssi is not None:
                    rssi = int(rssi)
                    if peak_rssi is None or rssi > peak_rssi:
                        peak_rssi = rssi
                if time.time() >= deadline:
                    break

            if pkts_here > 0:
                band_start = (freq_mhz // _BAND_STEP_MHZ) * _BAND_STEP_MHZ
                if band_start not in band_activity:
                    band_activity[band_start] = {
                        "pkt_count": 0,
                        "peak_rssi": None,
                        "freqs_active": set(),
                    }
                b = band_activity[band_start]
                b["pkt_count"] += pkts_here
                b["freqs_active"].add(freq_mhz)
                if peak_rssi is not None:
                    if b["peak_rssi"] is None or peak_rssi > b["peak_rssi"]:
                        b["peak_rssi"] = peak_rssi
                log.info(
                    f"[S17] {freq_mhz} MHz: {pkts_here} pkt(s)"
                    + (f", RSSI={peak_rssi} dBm" if peak_rssi else "")
                )

            try:
                sniffer.stop()
            except Exception:
                pass

        except Exception as exc:
            log.debug(f"[S17] {freq_mhz} MHz error: {type(exc).__name__}: {exc}")

    # --- Generate Findings ---

    if not band_activity:
        log.info("[S17] No sub-GHz RF activity detected across swept bands.")
        _print_summary(band_activity, total_packets)
        return

    log.info(
        f"[S17] {len(band_activity)} active band(s) found, "
        f"{total_packets} packet(s) total."
    )

    for band_mhz, info in sorted(band_activity.items()):
        band_label = f"{band_mhz}–{band_mhz + _BAND_STEP_MHZ} MHz"
        freqs_str  = ", ".join(f"{f} MHz" for f in sorted(info["freqs_active"]))
        rssi_str   = f"{info['peak_rssi']} dBm" if info["peak_rssi"] else "unknown"
        protocol_hint = _protocol_hint(band_mhz)

        finding = Finding(
            type="phy_subghz_rf_activity",
            severity="info",
            target_addr=band_label,
            description=(
                f"Sub-GHz RF activity detected in {band_label}. "
                f"{info['pkt_count']} packet(s) captured at {freqs_str}. "
                f"Peak RSSI: {rssi_str}. "
                f"{protocol_hint}"
            ),
            remediation=(
                "Identify the RF source using a protocol-aware decoder (e.g. rtl_433, "
                "Universal Radio Hacker). If the source is an unauthorised device or "
                "covert transmitter, investigate and remediate. Activity in quiet bands "
                "may indicate unauthorised sensors or RF-based data exfiltration."
            ),
            evidence={
                "band_mhz": band_label,
                "packet_count": info["pkt_count"],
                "peak_rssi_dbm": info["peak_rssi"],
                "active_frequencies_mhz": sorted(info["freqs_active"]),
                "likely_protocols": protocol_hint,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [info] phy_subghz_rf_activity: {band_label} "
            f"({info['pkt_count']} pkts)"
        )

    _print_summary(band_activity, total_packets)

    # Second pass: focused OOK sweep over key ISM frequencies.
    # GFSK cannot demodulate OOK signals — this complementary pass catches
    # wireless remotes, doorbells, alarm sensors, and garage door openers.
    log.info(
        f"[S17] OOK sweep: {_OOK_FREQS_MHZ} MHz "
        f"({SUBGHZ_PER_FREQ_SECS}s each) ..."
    )
    ook_hits = _ook_sweep(dongle, PhySniffer, SnifferConfiguration, engagement_id)
    if ook_hits:
        log.info(f"[S17] OOK sweep: {len(ook_hits)} active frequency/ies.")
    else:
        log.info("[S17] OOK sweep: no OOK activity detected.")


# ---------------------------------------------------------------------------
# OOK sweep
# ---------------------------------------------------------------------------

def _ook_sweep(
    dongle: WhadDongle,
    PhySniffer: type,
    SnifferConfiguration: type,
    engagement_id: str,
) -> list[int]:
    """Sweep _OOK_FREQS_MHZ using OOK/ASK modulation.

    OOK (On-Off Keying) is used by the majority of 433 MHz wireless remotes,
    doorbells, alarm sensors, and garage door openers — devices that would be
    invisible to a GFSK sweep. Returns list of active frequencies (MHz).
    """
    active: list[int] = []

    for freq_mhz in _OOK_FREQS_MHZ:
        freq_hz = freq_mhz * 1_000_000
        pkts_here = 0
        peak_rssi: int | None = None

        # Try OOK, fall back to ASK if the modulation string is unrecognized.
        for mod_name in ("OOK", "ASK"):
            try:
                cfg = SnifferConfiguration()
                cfg.frequency    = freq_hz
                cfg.modulation   = mod_name
                cfg.datarate     = _OOK_DATARATE
                cfg.max_pkt_size = 255

                sniffer = PhySniffer(dongle.device)
                sniffer.configuration = cfg

                deadline = time.time() + SUBGHZ_PER_FREQ_SECS
                for pkt in sniffer.sniff(timeout=SUBGHZ_PER_FREQ_SECS):
                    pkts_here += 1
                    rssi = getattr(pkt, "rssi", None)
                    if rssi is not None:
                        rssi = int(rssi)
                        if peak_rssi is None or rssi > peak_rssi:
                            peak_rssi = rssi
                    if time.time() >= deadline:
                        break

                try:
                    sniffer.stop()
                except Exception:
                    pass
                break  # modulation was accepted; no need to try ASK fallback

            except Exception as exc:
                err = str(exc).lower()
                if "modulation" in err or "invalid" in err or "unsupported" in err:
                    log.debug(f"[S17][OOK] {mod_name} not accepted for {freq_mhz} MHz: {exc}")
                    continue
                log.debug(f"[S17][OOK] {freq_mhz} MHz ({mod_name}): {type(exc).__name__}: {exc}")
                break

        if pkts_here > 0:
            active.append(freq_mhz)
            log.info(
                f"[S17][OOK] {freq_mhz} MHz: {pkts_here} pkt(s)"
                + (f", RSSI={peak_rssi} dBm" if peak_rssi else "")
            )
            from core.models import Finding
            from core.db import insert_finding
            finding = Finding(
                type="phy_subghz_ook_activity",
                severity="info",
                target_addr=f"{freq_mhz} MHz",
                description=(
                    f"OOK/ASK RF activity detected at {freq_mhz} MHz. "
                    f"{pkts_here} packet(s) captured."
                    + (f" Peak RSSI: {peak_rssi} dBm." if peak_rssi else "")
                    + f" {_ook_hint(freq_mhz)}"
                ),
                remediation=(
                    "Identify the transmitter using a protocol decoder (rtl_433, "
                    "Universal Radio Hacker, or rpitx). Unencrypted OOK remotes can "
                    "be replayed trivially — replace with rolling-code or AES-encrypted "
                    "devices where security is required."
                ),
                evidence={
                    "frequency_mhz": freq_mhz,
                    "packet_count": pkts_here,
                    "peak_rssi_dbm": peak_rssi,
                    "modulation": "OOK/ASK",
                },
                engagement_id=engagement_id,
            )
            insert_finding(finding)
            log.info(f"FINDING [info] phy_subghz_ook_activity: {freq_mhz} MHz")

            # Focused PCAP capture: re-tune to this frequency and record for
            # SUBGHZ_RECORD_SECS seconds. Print a replay command hint.
            _record_ook_signal(
                dongle, PhySniffer, SnifferConfiguration,
                freq_mhz, engagement_id
            )

    return active


def _record_ook_signal(
    dongle: WhadDongle,
    PhySniffer: type,
    SnifferConfiguration: type,
    freq_mhz: int,
    engagement_id: str,
) -> None:
    """Capture an OOK signal PCAP at the given frequency for offline replay PoC."""
    import config as _cfg
    freq_hz = freq_mhz * 1_000_000
    cap_path = pcap_path(engagement_id, 17, f"ook_{freq_mhz}mhz")

    record_secs = getattr(_cfg, "SUBGHZ_RECORD_SECS", 5)
    log.info(f"[S17][OOK] Recording {record_secs}s at {freq_mhz} MHz → {cap_path}")
    try:
        cfg = SnifferConfiguration()
        cfg.frequency    = freq_hz
        cfg.modulation   = "OOK"
        cfg.datarate     = _OOK_DATARATE
        cfg.max_pkt_size = 255

        sniffer = PhySniffer(dongle.device)
        sniffer.configuration = cfg

        monitor = attach_monitor(sniffer, cap_path)
        deadline = time.time() + record_secs
        for _ in sniffer.sniff(timeout=record_secs):
            if time.time() >= deadline:
                break

        detach_monitor(monitor)
        try:
            sniffer.stop()
        except Exception:
            pass

        iface = getattr(_cfg, "PHY_SUBGHZ_INTERFACE", "yardstickone0")
        if cap_path.exists() and cap_path.stat().st_size > 0:
            log.info(
                f"[S17][OOK] Signal PCAP: {cap_path}\n"
                f"  Replay PoC: wplay --flush {cap_path} phy | "
                f"winject -i {iface} phy --frequency {freq_hz} --modulation OOK"
            )
        else:
            log.debug(f"[S17][OOK] No signal recorded at {freq_mhz} MHz (PCAP empty).")
    except Exception as exc:
        log.debug(f"[S17][OOK] Record {freq_mhz} MHz: {type(exc).__name__}: {exc}")



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ook_hint(freq_mhz: int) -> str:
    """Return a contextual hint for a specific OOK frequency."""
    if freq_mhz == 315:
        return "315 MHz OOK: North American keyfobs, garage door openers, RF remotes."
    if freq_mhz in (433, 434):
        return (
            "433.92 MHz OOK: worldwide ISM — wireless doorbells, alarm sensors, "
            "weather stations, garage door openers, RC car remotes, smart plugs."
        )
    if freq_mhz == 868:
        return (
            "868 MHz OOK: EU ISM — wireless alarm sensors, smoke detectors, "
            "door/window contacts (commonly used by Bosch, Pyronix, Honeywell alarms)."
        )
    if freq_mhz == 915:
        return "915 MHz OOK: US ISM — wireless sensors, alarm contacts, smart home devices."
    return "OOK/ASK ISM-band device detected."


def _protocol_hint(band_mhz: int) -> str:
    """Return a human-readable protocol hint based on band start MHz."""
    if 300 <= band_mhz < 350:
        return "Possible protocols: legacy ISM-band sensors, 315 MHz remotes."
    if 390 <= band_mhz < 470:
        return (
            "Possible protocols: 433 MHz ISM (wireless doorbells, weather stations, "
            "garage doors, alarm sensors, RC car remotes)."
        )
    if 860 <= band_mhz < 870:
        return (
            "Possible protocols: Z-Wave EU (868.4 MHz), LoRa EU868, "
            "smart meter mesh (DLMS/COSEM), wireless alarm systems."
        )
    if 900 <= band_mhz < 930:
        return (
            "Possible protocols: Z-Wave US (908.4 MHz), LoRa US915, "
            "ISM-band sensors, DECT-band adjacent devices."
        )
    if 780 <= band_mhz < 860:
        return "Possible protocols: sub-GHz proprietary sensors, paging systems."
    return "Unknown sub-GHz protocol range."


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(band_activity: dict, total_packets: int) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 17 SUMMARY -- sub-GHz PHY Survey (YardStickOne)")
    print("─" * 76)
    print(f"  {'Frequencies swept':<28}: {len(_ALL_FREQS)}")
    print(f"  {'Bands covered':<28}: 300-348, 391-464, 782-928 MHz")
    print(f"  {'Active 5 MHz bands':<28}: {len(band_activity)}")
    print(f"  {'Total packets captured':<28}: {total_packets}")
    if band_activity:
        print()
        print("  Active bands:")
        for band_mhz, info in sorted(band_activity.items()):
            rssi = f"{info['peak_rssi']} dBm" if info["peak_rssi"] else "?"
            print(
                f"    {band_mhz:4d}–{band_mhz + _BAND_STEP_MHZ} MHz  "
                f"pkts={info['pkt_count']:<5}  RSSI={rssi}"
            )
    else:
        print("  Result: no sub-GHz RF activity detected on swept frequencies.")
    print("─" * 76 + "\n")
