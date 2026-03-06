"""
Stage 12 — PHY / ISM Band Survey

Uses the WHAD Python API (whad.phy.Sniffer) to map RF activity across the
2.4 GHz ISM band (2402–2480 MHz) and optionally sub-GHz bands.

Supported modulations: GFSK, FSK, ASK/OOK, BPSK, QPSK, LoRa (hardware-dependent).
The stage sweeps in 2 MHz steps, dwells at each frequency, and aggregates packet
activity into 5 MHz reporting bands.

This reveals RF transmitters that are invisible to BLE/ZigBee scanners:
  - Proprietary sensor networks (ISM-band GFSK devices)
  - Baby monitors / video senders (analog or digital)
  - Non-standard RF modules (RFM69, CC1101, nRF24L01, etc.)
  - Interference sources and covert RF channels

Passive only — receive only, no transmission.
"""

from __future__ import annotations

import time
from typing import Any

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s12_phy")

# 2.4 GHz ISM band: 2402–2480 MHz in 2 MHz steps
_2G4_FREQS_MHZ = list(range(2402, 2481, 2))

# Modulation parameters for GFSK (covers BLE, ZigBee, proprietary FSK)
_GFSK_DATARATE  = 1_000_000   # 1 Mbps
_GFSK_DEVIATION = 250_000     # 250 kHz

PHY_PER_FREQ_SECS = config.PHY_PER_FREQ_SECS  # dwell per frequency
PHY_SWEEP_SECS    = config.PHY_SWEEP_SECS      # informational total budget

# Band width for aggregating results in the summary (MHz)
_BAND_STEP_MHZ = 5


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: WhadDongle, engagement_id: str) -> None:
    """Sweep the 2.4 GHz ISM band and map RF activity.

    Args:
        dongle: Active WHAD dongle.
        engagement_id: Engagement ID for Finding storage.
    """
    PhySniffer = None
    SnifferConfiguration = None
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
        log.warning("[S12] whad.phy not available — stage skipped.")
        return
    try:
        from whad.phy.sniffing import SnifferConfiguration
    except ImportError:
        try:
            from whad.phy import SnifferConfiguration
        except ImportError:
            log.warning("[S12] SnifferConfiguration not importable — stage skipped.")
            return

    log.info(
        f"[S12] Sweeping 2.4 GHz ISM band "
        f"({len(_2G4_FREQS_MHZ)} frequencies × {PHY_PER_FREQ_SECS}s = "
        f"~{len(_2G4_FREQS_MHZ) * PHY_PER_FREQ_SECS}s) ..."
    )
    log.info("[S12] Any RF transmitter in the 2.4 GHz band will be detected.")

    # {band_start_mhz: {"pkt_count": int, "peak_rssi": int|None, "freqs_active": set}}
    band_activity: dict[int, dict] = {}
    total_packets = 0

    for freq_mhz in _2G4_FREQS_MHZ:
        freq_hz = freq_mhz * 1_000_000
        log.debug(f"[S12] {freq_mhz} MHz ...")

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
            deadline = time.time() + PHY_PER_FREQ_SECS

            for pkt in sniffer.sniff(timeout=PHY_PER_FREQ_SECS):
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
                    f"[S12] {freq_mhz} MHz: {pkts_here} pkt(s)"
                    + (f", RSSI={peak_rssi} dBm" if peak_rssi else "")
                )

            try:
                sniffer.stop()
            except Exception:
                pass

        except Exception as exc:
            log.debug(
                f"[S12] {freq_mhz} MHz error: {type(exc).__name__}: {exc}"
            )

    # --- Generate Findings ---

    if not band_activity:
        log.info("[S12] No RF activity detected across the 2.4 GHz ISM band.")
        _print_summary(band_activity, total_packets)
        return

    log.info(
        f"[S12] {len(band_activity)} active band(s) found, "
        f"{total_packets} packet(s) total."
    )

    for band_mhz, info in sorted(band_activity.items()):
        band_label = f"{band_mhz}–{band_mhz + _BAND_STEP_MHZ} MHz"
        freqs_str  = ", ".join(f"{f} MHz" for f in sorted(info["freqs_active"]))
        rssi_str   = f"{info['peak_rssi']} dBm" if info["peak_rssi"] else "unknown"

        finding = Finding(
            type="phy_rf_activity",
            severity="info",
            target_addr=band_label,
            description=(
                f"RF activity detected in {band_label} ISM band. "
                f"{info['pkt_count']} packet(s) captured at {freqs_str}. "
                f"Peak RSSI: {rssi_str}. "
                "Source may be BLE, ZigBee, proprietary ISM-band device, or interference."
            ),
            remediation=(
                "Identify the RF source using a protocol-aware decoder. "
                "If the source is an unauthorised device or covert transmitter, "
                "investigate and remediate. RF activity in otherwise quiet bands "
                "may indicate unauthorised sensors or data exfiltration channels."
            ),
            evidence={
                "band_mhz": band_label,
                "packet_count": info["pkt_count"],
                "peak_rssi_dbm": info["peak_rssi"],
                "active_frequencies_mhz": sorted(info["freqs_active"]),
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [info] phy_rf_activity: {band_label} "
            f"({info['pkt_count']} pkts)"
        )

    if band_activity:
        _capture_hot_frequencies(
            dongle, PhySniffer, SnifferConfiguration, band_activity, engagement_id
        )

    _print_summary(band_activity, total_packets)



# ---------------------------------------------------------------------------
# Focused PCAP capture for most-active frequencies
# ---------------------------------------------------------------------------

def _capture_hot_frequencies(
    dongle: WhadDongle,
    PhySniffer,
    SnifferConfiguration,
    band_activity: dict,
    engagement_id: str,
) -> None:
    """Capture a short PCAP for each of the N most-active ISM frequencies.

    For each active band, picks the most-trafficked member frequency, attaches
    a PcapWriterMonitor, and captures for config.PHY_CAPTURE_SECS seconds.
    The resulting PCAP file and a wplay replay command are logged for use in PoC.
    """
    import config as _cfg

    # Build list of (pkt_count, freq_mhz) sorted descending
    freq_scores: list[tuple[int, int]] = []
    for info in band_activity.values():
        best_freq = max(info["freqs_active"]) if info["freqs_active"] else None
        if best_freq:
            freq_scores.append((info["pkt_count"], best_freq))
    freq_scores.sort(reverse=True)

    top_n = freq_scores[: _cfg.PHY_CAPTURE_TOP_N]
    if not top_n:
        return

    log.info(
        f"[S12] Focused PCAP capture for top {len(top_n)} active frequency/"
        f"frequencies ({_cfg.PHY_CAPTURE_SECS}s each) ..."
    )

    for pkt_count, freq_mhz in top_n:
        freq_hz = freq_mhz * 1_000_000
        cap_path = pcap_path(engagement_id, 12, f"phy_{freq_mhz}mhz")
        log.info(f"[S12] Capturing {_cfg.PHY_CAPTURE_SECS}s at {freq_mhz} MHz → {cap_path}")

        try:
            cfg = SnifferConfiguration()
            cfg.frequency  = freq_hz
            cfg.modulation = "GFSK"
            cfg.datarate   = _GFSK_DATARATE
            cfg.deviation  = _GFSK_DEVIATION
            cfg.max_pkt_size = 255

            sniffer = PhySniffer(dongle.device)
            sniffer.configuration = cfg

            monitor = attach_monitor(sniffer, cap_path)
            import time as _time
            deadline = _time.time() + _cfg.PHY_CAPTURE_SECS

            for _ in sniffer.sniff(timeout=_cfg.PHY_CAPTURE_SECS):
                if _time.time() >= deadline:
                    break

            detach_monitor(monitor)
            try:
                sniffer.stop()
            except Exception:
                pass

            if cap_path.exists() and cap_path.stat().st_size > 0:
                log.info(
                    f"[S12] PCAP saved: {cap_path}  "
                    f"replay: wplay --flush {cap_path} phy | "
                    f"winject -i {_cfg.INTERFACE} phy --frequency {freq_hz}"
                )
            else:
                log.debug(f"[S12] No packets captured at {freq_mhz} MHz (PCAP empty).")
        except Exception as exc:
            log.debug(f"[S12] Focused capture {freq_mhz} MHz: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(band_activity: dict, total_packets: int) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 12 SUMMARY -- PHY / ISM Band Survey (2.4 GHz)")
    print("─" * 76)
    print(f"  {'Frequencies swept':<28}: {len(_2G4_FREQS_MHZ)}")
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
    print("─" * 76 + "\n")
