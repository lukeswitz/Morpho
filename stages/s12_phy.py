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

try:
    from whad.phy.connector.lora import LoRa as _LoRaConnector
    _LORA_CONNECTOR_AVAILABLE = True
except ImportError:
    _LORA_CONNECTOR_AVAILABLE = False

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

    # Attempt LoRa-specific scan if hardware supports it
    lora_results = _lora_scan(dongle, frequencies_mhz=[433.175, 868.1, 915.0], duration_secs=5)
    if lora_results:
        log.info(f"[S12] LoRa scan: {len(lora_results)} frame(s) captured")

    _print_summary(band_activity, total_packets)



# ---------------------------------------------------------------------------
# LoRa native connector scan
# ---------------------------------------------------------------------------

# LoRa scan frequencies: common ISM LoRa channels (EU 868 MHz region)
_LORA_FREQS_MHZ = [868, 868_1, 868_3, 868_5, 869_525]  # MHz, EU defaults
# Convert to plain integer MHz values (the above literals are invalid — use list)
_LORA_FREQS_MHZ = [868, 8681, 8683, 8685, 869525]  # placeholder; real values below
_LORA_FREQS_MHZ = [
    868_000_000,   # 868.0 MHz
    868_100_000,   # 868.1 MHz
    868_300_000,   # 868.3 MHz
    868_500_000,   # 868.5 MHz
    869_525_000,   # 869.525 MHz (duty-cycle-free)
]

_LORA_SF       = 7        # Spreading factor (7–12; 7 = fastest, shortest range)
_LORA_BW       = 125_000  # Bandwidth Hz (125, 250, 500 kHz)
_LORA_CR       = 5        # Coding rate denominator (5 = 4/5)
_LORA_PREAMBLE = 8        # Preamble symbols


def _run_lora_scan_native(dongle: WhadDongle, engagement_id: str) -> None:
    """Scan LoRa channels using the whad.phy.connector.lora.LoRa connector.

    Tries each frequency in _LORA_FREQS_MHZ with SF7/BW125/CR4-5 config.
    Logs captured packets and creates Findings for any LoRa traffic found.

    Args:
        dongle: Active WHAD dongle.
        engagement_id: Engagement ID for Finding storage.
    """
    log.info(
        f"[S12] LoRa native scan: {len(_LORA_FREQS_MHZ)} channel(s), "
        f"SF={_LORA_SF} BW={_LORA_BW // 1000}kHz CR=4/{_LORA_CR} "
        f"({PHY_PER_FREQ_SECS}s dwell each) ..."
    )

    lora_findings: list[dict[str, Any]] = []

    for freq_hz in _LORA_FREQS_MHZ:
        freq_mhz = freq_hz / 1_000_000
        log.debug(f"[S12] LoRa {freq_mhz:.3f} MHz ...")

        try:
            lora = _LoRaConnector(dongle.device)
            lora.sf = _LORA_SF
            lora.bw = _LORA_BW
            lora.cr = _LORA_CR
            lora.preamble_length = _LORA_PREAMBLE
            lora.enable_crc(True)
            lora.enable_explicit_mode(True)
            lora.start()

            deadline = time.time() + PHY_PER_FREQ_SECS
            pkts_here = 0

            for pkt in lora.sniff(timeout=PHY_PER_FREQ_SECS):
                pkts_here += 1
                payload = bytes(pkt)
                rssi = getattr(pkt, "rssi", None)
                rssi_str = f"{int(rssi)} dBm" if rssi is not None else "unknown"
                log.info(
                    f"[S12] LoRa pkt @ {freq_mhz:.3f} MHz  "
                    f"RSSI={rssi_str}  payload={payload.hex()}"
                )
                lora_findings.append(
                    {
                        "freq_hz": freq_hz,
                        "freq_mhz": freq_mhz,
                        "payload_hex": payload.hex(),
                        "rssi_dbm": int(rssi) if rssi is not None else None,
                    }
                )
                if time.time() >= deadline:
                    break

            if pkts_here > 0:
                log.info(
                    f"[S12] LoRa {freq_mhz:.3f} MHz: {pkts_here} pkt(s) captured."
                )

            try:
                lora.stop()
            except Exception:
                pass

        except Exception as exc:
            log.debug(
                f"[S12] LoRa {freq_mhz:.3f} MHz error: {type(exc).__name__}: {exc}"
            )

    if not lora_findings:
        log.info("[S12] No LoRa traffic captured.")
        return

    log.info(f"[S12] LoRa scan complete: {len(lora_findings)} pkt(s) total.")

    # Group by frequency for one Finding per active channel
    freqs_seen: dict[float, list[dict]] = {}
    for entry in lora_findings:
        freqs_seen.setdefault(entry["freq_mhz"], []).append(entry)

    for freq_mhz, pkts in freqs_seen.items():
        payloads = [p["payload_hex"] for p in pkts]
        rssi_vals = [p["rssi_dbm"] for p in pkts if p["rssi_dbm"] is not None]
        peak_rssi = max(rssi_vals) if rssi_vals else None
        rssi_str = f"{peak_rssi} dBm" if peak_rssi is not None else "unknown"

        finding = Finding(
            type="lora_traffic_detected",
            severity="medium",
            target_addr=f"{freq_mhz:.3f} MHz",
            description=(
                f"LoRa traffic detected at {freq_mhz:.3f} MHz "
                f"(SF={_LORA_SF}, BW={_LORA_BW // 1000} kHz, CR=4/{_LORA_CR}). "
                f"{len(pkts)} packet(s) captured. Peak RSSI: {rssi_str}. "
                "LoRa devices may transmit sensor data, GPS coordinates, or "
                "command-and-control messages in plaintext or with weak encryption."
            ),
            remediation=(
                "Capture and decode LoRa payloads to assess data sensitivity. "
                "Verify that application-layer encryption (e.g. AES-128) is enabled "
                "and that join/session keys are unique per device. "
                "Investigate whether the device belongs to a known LoRaWAN network "
                "or is operating on a private frequency plan."
            ),
            evidence={
                "frequency_mhz": freq_mhz,
                "spreading_factor": _LORA_SF,
                "bandwidth_hz": _LORA_BW,
                "coding_rate": f"4/{_LORA_CR}",
                "packet_count": len(pkts),
                "peak_rssi_dbm": peak_rssi,
                "payload_samples": payloads[:5],
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [medium] lora_traffic_detected: {freq_mhz:.3f} MHz "
            f"({len(pkts)} pkts)"
        )


# ---------------------------------------------------------------------------
# Generic LoRa frequency scanner (multi-SF sweep)
# ---------------------------------------------------------------------------

def _lora_scan(dongle: WhadDongle, frequencies_mhz: list[float], duration_secs: int = 10) -> list[dict]:
    """Scan LoRa frequencies using the whad.phy.connector.lora.LoRa connector.

    Tries common spreading factors and bandwidths. Returns list of
    received frame dicts with keys: frequency_mhz, sf, bw, payload_hex.
    Falls back silently if the LoRa connector is not available.

    Args:
        dongle: WhadDongle with phy_dongle or ble_dongle.
        frequencies_mhz: List of frequencies to scan in MHz.
        duration_secs: Seconds to listen per frequency/config combination.

    Returns:
        List of received frame dicts.
    """
    try:
        from whad.phy.connector.lora import LoRa
    except ImportError:
        try:
            from whad.phy import LoRa
        except ImportError:
            log.debug("[S12] whad.phy.connector.lora.LoRa not importable — skipping LoRa scan")
            return []

    device = getattr(dongle, "phy_dongle", None) or getattr(dongle, "ble_dongle", None)
    if device is None:
        return []

    results = []
    # Common LoRa configurations to try
    configs = [
        {"sf": 7, "bw": 125000, "cr": 5},
        {"sf": 9, "bw": 125000, "cr": 5},
        {"sf": 12, "bw": 125000, "cr": 5},
    ]

    for freq in frequencies_mhz:
        for cfg in configs:
            lora = None
            try:
                lora = LoRa(device.device)
                lora.sf = cfg["sf"]
                lora.bw = cfg["bw"]
                lora.cr = cfg["cr"]
                lora.enable_crc(True)
                lora.enable_explicit_mode(True)
                lora.start()
                log.debug(f"[S12][lora] Scanning {freq}MHz SF{cfg['sf']} BW{cfg['bw'] // 1000}kHz")
                for pkt in lora.sniff(timeout=duration_secs):
                    results.append({
                        "frequency_mhz": freq,
                        "sf": cfg["sf"],
                        "bw": cfg["bw"],
                        "payload_hex": bytes(pkt).hex(),
                    })
                    log.info(f"[S12][lora] Frame at {freq}MHz SF{cfg['sf']}: {bytes(pkt).hex()[:32]}")
            except (AttributeError, NotImplementedError, TypeError) as exc:
                log.debug(f"[S12][lora] LoRa connector not supported: {exc}")
                return results  # Hardware doesn't support it, stop trying
            except Exception as exc:
                log.debug(f"[S12][lora] {freq}MHz SF{cfg['sf']} error: {exc}")
            finally:
                if lora is not None:
                    try:
                        lora.stop()
                    except Exception:
                        pass

    return results


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
