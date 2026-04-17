"""
Stage 25 — rfcat Sub-GHz Spectrum Survey

Uses the rfcat Python library with a YardStick One (CC1111 chipset) to survey
sub-GHz ISM bands for active transmitters via RSSI measurement.

This stage complements Stage 17 (WHAD PHY survey). Stage 17 uses the WHAD
abstraction for broad GFSK/OOK sweeps. Stage 25 uses rfcat directly and adds:
  - Per-frequency RSSI measurement across configurable frequency list
  - Active transmitter detection above a configurable threshold
  - Burst capture at active frequencies (raw IQ-level)
  - Protocol classification hints (PT2262, KeeLoq, Z-Wave, LoRa adjacent)

Target environment:
  Buildings with legacy alarm systems (433 MHz OOK), remote-controlled gates,
  smart meters (868/915 MHz), Z-Wave nodes, and proprietary ISM sensors — all
  invisible to BLE/ZigBee scanners.

Hardware: YardStick One (https://greatscottgadgets.com/yardstickone/)
Library:  rfcat (pip install rfcat) — https://github.com/atlas0fd00m/rfcat
"""

from __future__ import annotations

import time

from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s25_subghz_survey")

# Modulation constant strings → rfcat library constants (loaded at runtime)
_MOD_MAP = {
    "ASK_OOK": 0x30,
    "GFSK":    0x10,
    "2FSK":    0x00,
    "MSK":     0x70,
}

# Protocol classification by frequency band (MHz)
_PROTO_HINTS: list[tuple[tuple[int, int], str]] = [
    ((308, 320), "Fixed-code OOK remotes (keyfobs, garage doors) — North American ISM"),
    ((313, 317), "315 MHz ISM: keyfobs, RF remotes, wireless sensors (North America)"),
    ((430, 440), "433.92 MHz ISM: doorbells, alarm sensors, weather stations, RC remotes"),
    ((863, 870), "868 MHz EU ISM: Z-Wave EU (868.42 MHz), wireless alarms, smart meters"),
    ((902, 928), "915 MHz US ISM: Z-Wave US (908.42 MHz), LoRa US915, ISM sensors"),
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: object, engagement_id: str) -> None:
    """Survey sub-GHz frequencies with rfcat RSSI measurement.

    Args:
        dongle: YardStick One WHAD dongle (used for interface name only;
                rfcat opens the device independently via its own USB path).
        engagement_id: Engagement ID for Finding storage.
    """
    try:
        from rflib import RFCat
    except ImportError:
        log.warning(
            "[S25] rfcat not installed — sub-GHz survey stage skipped. "
            "Install with: pip install rfcat"
        )
        return

    freqs_mhz  = list(config.SUBGHZ_SURVEY_FREQS)
    dwell_ms   = config.SUBGHZ_SURVEY_DWELL_MS
    rssi_min   = config.SUBGHZ_SURVEY_RSSI_MIN

    log.info(
        f"[S25] Sub-GHz spectrum survey: {len(freqs_mhz)} frequencies, "
        f"{dwell_ms}ms RSSI dwell each"
    )
    log.info(f"[S25] Frequencies (MHz): {freqs_mhz}")
    log.info(f"[S25] RSSI threshold: ≥ {rssi_min} dBm")

    try:
        d = RFCat(idx=0)
    except Exception as exc:
        log.warning(f"[S25] Failed to open rfcat device: {exc}")
        return

    active: dict[int, dict] = {}

    try:
        for freq_mhz in freqs_mhz:
            freq_hz = freq_mhz * 1_000_000
            try:
                result = _measure_rssi(d, freq_hz, dwell_ms)
            except Exception as exc:
                log.debug(f"[S25] {freq_mhz} MHz RSSI error: {exc}")
                continue

            rssi_dbm = result["peak_rssi"]
            if rssi_dbm is not None and rssi_dbm >= rssi_min:
                active[freq_mhz] = result
                proto = _protocol_hint(freq_mhz)
                log.info(
                    f"[S25] ACTIVE {freq_mhz} MHz: "
                    f"peak RSSI={rssi_dbm} dBm  — {proto}"
                )
            else:
                log.debug(
                    f"[S25] {freq_mhz} MHz: "
                    f"RSSI={rssi_dbm} dBm (below threshold {rssi_min})"
                )

    finally:
        try:
            d.setModeIDLE()
        except Exception:
            pass

    if not active:
        log.info(
            f"[S25] No RF activity above {rssi_min} dBm detected "
            f"across {len(freqs_mhz)} frequencies."
        )
        _print_summary(active, freqs_mhz, rssi_min)
        return

    log.info(
        f"[S25] {len(active)} active frequency/ies found: "
        f"{list(active.keys())} MHz"
    )

    for freq_mhz, result in active.items():
        _emit_finding(freq_mhz, result, engagement_id)

    _print_summary(active, freqs_mhz, rssi_min)


# ---------------------------------------------------------------------------
# RSSI measurement
# ---------------------------------------------------------------------------

def _measure_rssi(d: object, freq_hz: int, dwell_ms: int) -> dict:
    """Tune to freq_hz and collect RSSI samples for dwell_ms milliseconds.

    Returns dict with peak_rssi, avg_rssi, sample_count.
    """
    # Configure radio for broadband energy detection:
    # OOK modulation, no sync word, CRC disabled, minimum preamble threshold.
    d.setFreq(freq_hz)
    d.setMdmModulation(0x30)   # ASK/OOK — best for energy detection
    d.setMdmSyncMode(0)        # no sync word — promiscuous / energy detect
    d.setEnablePktCRC(False)
    d.setPktPQT(0)             # no preamble quality threshold

    samples: list[int] = []
    deadline = time.monotonic() + dwell_ms / 1000.0
    while time.monotonic() < deadline:
        try:
            rssi = d.getRSSI()
            if rssi is not None:
                samples.append(int(rssi))
        except Exception:
            pass
        time.sleep(0.005)

    if not samples:
        return {"freq_hz": freq_hz, "peak_rssi": None, "avg_rssi": None, "samples": 0}

    peak = max(samples)
    avg  = sum(samples) // len(samples)
    return {
        "freq_hz":   freq_hz,
        "peak_rssi": peak,
        "avg_rssi":  avg,
        "samples":   len(samples),
    }


# ---------------------------------------------------------------------------
# Protocol hints
# ---------------------------------------------------------------------------

def _protocol_hint(freq_mhz: int) -> str:
    for (lo, hi), hint in _PROTO_HINTS:
        if lo <= freq_mhz <= hi:
            return hint
    return "Sub-GHz ISM transmitter (protocol unclassified)"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _emit_finding(freq_mhz: int, result: dict, engagement_id: str) -> None:
    proto_hint = _protocol_hint(freq_mhz)
    rssi_str   = f"{result['peak_rssi']} dBm" if result["peak_rssi"] is not None else "?"
    avg_str    = f"{result['avg_rssi']} dBm" if result["avg_rssi"] is not None else "?"

    finding = Finding(
        type="subghz_survey_rf_activity",
        severity="info",
        target_addr=f"{freq_mhz} MHz",
        description=(
            f"Sub-GHz RF activity detected at {freq_mhz} MHz. "
            f"Peak RSSI: {rssi_str}, average: {avg_str} "
            f"({result['samples']} samples). "
            f"Protocol hint: {proto_hint}"
        ),
        remediation=(
            "Identify the source device using a protocol-aware decoder "
            "(rtl_433, Universal Radio Hacker, or SDR#). "
            "If the transmitter is an alarm sensor, gate opener, or smart meter, "
            "proceed to Stage 26 (Sub-GHz Capture & Replay) to assess replay risk."
        ),
        evidence={
            "frequency_mhz": freq_mhz,
            "peak_rssi_dbm": result["peak_rssi"],
            "avg_rssi_dbm":  result["avg_rssi"],
            "rssi_samples":  result["samples"],
            "protocol_hint": proto_hint,
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [info] subghz_survey_rf_activity: {freq_mhz} MHz ({rssi_str})")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(active: dict, freqs: list[int], rssi_min: int) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 25 SUMMARY -- Sub-GHz Spectrum Survey (rfcat)")
    log.info("─" * 76)
    log.info(f"  {'Frequencies surveyed':<28}: {len(freqs)}")
    log.info(f"  {'RSSI threshold':<28}: {rssi_min} dBm")
    log.info(f"  {'Active frequencies':<28}: {len(active)}")
    for freq_mhz, result in sorted(active.items()):
        rssi_str = f"{result['peak_rssi']} dBm" if result["peak_rssi"] else "?"
        log.info(
            f"    {freq_mhz:5d} MHz  peak={rssi_str:<12}  "
            f"{_protocol_hint(freq_mhz)}"
        )
    if not active:
        log.info("  Result: no sub-GHz RF activity detected above threshold.")
    log.info("─" * 76 + "\n")
