"""
Stage 21 — Bluetooth Classic (BR/EDR) Scout

Discovers Bluetooth Classic (BR/EDR) devices and enumerates their SDP service
profiles. If an Ubertooth One is present it is used for passive BR/EDR piconet
sniffing. Falls back gracefully if no BR/EDR-capable hardware is found.

Three probe paths (in order of priority):
  1. Ubertooth One — passive piconet sniff (ubertooth-rx / ubertooth-br)
  2. HCI adapter   — hcitool scan + sdptool browse (requires hci* device in dongle caps)
  3. BlueZ CLI     — hciconfig + hcitool as subprocess fallback

Findings:
  btc_device_found        (info)     — BR/EDR device visible
  btc_exposed_services    (medium)   — services browseable without auth
  btc_weak_security_mode  (high)     — device advertises PIN/insecure pairing mode
  btc_piconet_sniffed     (high)     — raw BR/EDR traffic captured by Ubertooth
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import threading
from datetime import datetime, timezone

from core.dongle import WhadDongle, HardwareMap
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path
from core.vulndb import match_btclassic_service, get_btclassic_generic_vulns, get_braktooth_vulns, VulnMatch
import config

log = get_logger("s21_btclassic")

_SCAN_SECS      = config.BTCLASSIC_SCAN_SECS
_SDP_TIMEOUT    = config.BTCLASSIC_SDP_TIMEOUT
_UBERTOOTH_SECS = 60   # ubertooth piconet sniff window
_MAX_SDP_DEVS   = 8    # cap how many devices we run sdptool against


# ── Known vulnerable / interesting SDP service UUIDs ──────────────────────────
_RISKY_SVCS: dict[str, str] = {
    "0x1101": "Serial Port Profile (SPP) — unauthenticated data channel",
    "0x1105": "OBEX Object Push — file transfer without pairing",
    "0x1106": "OBEX File Transfer",
    "0x1115": "BNEP/PAN — network access",
    "0x1116": "NAP — network access point",
    "0x1117": "GN — group network",
}


# ── Entry point ────────────────────────────────────────────────────────────────

def run(
    hw: HardwareMap,
    engagement_id: str,
) -> None:
    """Run Bluetooth Classic scout.

    Uses Ubertooth (hw.ubertooth_dongle), HCI (hw.ble_dongle if type=hci),
    or falls back to subprocess hcitool on any available hci interface.
    """
    has_hci       = _has_hci_interface()
    has_ubertooth = hw.ubertooth_dongle is not None

    if not has_hci and not has_ubertooth:
        log.warning(
            "[S21] No BR/EDR capable hardware detected. "
            "Need an HCI adapter (hci0) or Ubertooth One. Stage skipped."
        )
        _print_no_hardware()
        return

    devices: list[dict] = []

    # --- Phase 1: active scan (hcitool) ---
    if has_hci:
        log.info(f"[S21] Scanning for BR/EDR devices ({_SCAN_SECS}s) ...")
        devices = _hcitool_scan(_SCAN_SECS)
        log.info(f"[S21] BR/EDR scan complete: {len(devices)} device(s) found")

    # --- Phase 2: SDP service enumeration ---
    if devices:
        _sdp_browse_all(devices, engagement_id)

    # --- Phase 3: Ubertooth passive piconet sniff ---
    if has_ubertooth:
        _ubertooth_sniff(hw.ubertooth_dongle, engagement_id)

    if not devices and not has_ubertooth:
        log.info("[S21] No BR/EDR devices found.")

    _print_summary(devices)

    if devices:
        _record_devices_finding(devices, engagement_id)

    # Flag generic BR/EDR CVEs (BIAS, BLURtooth, BrakTooth) for every discoverable device.
    generic_vulns = get_btclassic_generic_vulns() + get_braktooth_vulns()
    for dev in devices:
        for vm in generic_vulns:
            insert_finding(Finding(
                type="cve_match",
                severity=vm.severity,
                target_addr=dev["addr"],
                description=(
                    f"{vm.name}: {vm.summary} "
                    f"(discoverable device {dev['addr']} "
                    f"[{dev.get('name', 'unnamed')}])"
                    + (f" [{vm.cve}]" if vm.cve else "")
                ),
                remediation=vm.remediation,
                evidence={
                    "cve": vm.cve, "vuln_name": vm.name,
                    "tags": list(vm.tags), "references": list(vm.references),
                    "addr": dev["addr"],
                    "device_name": dev.get("name", ""),
                },
                engagement_id=engagement_id,
            ))
            log.info(
                f"FINDING [{vm.severity}] cve_match: {dev['addr']} — "
                f"{vm.name}" + (f" ({vm.cve})" if vm.cve else "")
            )


# ── BR/EDR device scan ─────────────────────────────────────────────────────────

def _has_hci_interface() -> bool:
    """Return True if any hci* interface is visible on the system."""
    if shutil.which("hcitool") is None:
        return False
    try:
        out = subprocess.run(
            ["hciconfig"],
            capture_output=True, text=True, timeout=5
        ).stdout
        return bool(re.search(r"\bhci\d+\b", out))
    except Exception:
        return False


def _hcitool_scan(duration: int) -> list[dict]:
    """Run `hcitool scan` and return list of {addr, name} dicts."""
    devices: list[dict] = []
    try:
        # --length units are 1.28 seconds (Bluetooth inquiry periods).
        # duration // 1280 was wrong (gave 0 for 30s → only 1.28s scan).
        # Correct: duration * 100 // 128  (e.g. 30s → 23 units → 29.4s)
        length_units = max(1, duration * 100 // 128)
        result = subprocess.run(
            ["hcitool", "scan", "--flush", "--length", str(length_units)],
            capture_output=True, text=True, timeout=duration + 10,
        )
        for line in result.stdout.splitlines():
            m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(.*)", line)
            if m:
                devices.append({"addr": m.group(1).upper(), "name": m.group(2).strip()})
                log.info(f"[S21] BR/EDR device: {m.group(1).upper()}  {m.group(2).strip()}")
    except subprocess.TimeoutExpired:
        log.debug("[S21] hcitool scan timed out")
    except Exception as exc:
        log.warning(f"[S21] hcitool scan error: {type(exc).__name__}: {exc}")
    return devices


# ── SDP service browse ─────────────────────────────────────────────────────────

def _sdp_browse_all(devices: list[dict], engagement_id: str) -> None:
    """Run sdptool browse against each device and record service findings."""
    if shutil.which("sdptool") is None:
        log.debug("[S21] sdptool not in PATH — skipping SDP browse")
        return

    for dev in devices[:_MAX_SDP_DEVS]:
        addr = dev["addr"]
        log.info(f"[S21] SDP browse: {addr} ...")
        services = _sdp_browse(addr)
        dev["services"] = services

        risky = [s for s in services if _is_risky_service(s)]
        if risky:
            dev["risky_services"] = risky
            _record_service_finding(dev, risky, engagement_id)

        # Match each SDP service UUID against the CVE vulnerability database.
        for svc in services:
            svc_uuid = svc.get("uuid", "")
            if not svc_uuid:
                continue
            cve_hits = match_btclassic_service(svc_uuid)
            for vm in cve_hits:
                insert_finding(Finding(
                    type="cve_match",
                    severity=vm.severity,
                    target_addr=addr,
                    description=(
                        f"{vm.name}: {vm.summary} "
                        f"(service {svc.get('name', '?')} uuid={svc_uuid} "
                        f"on {addr} [{dev.get('name', 'unnamed')}])"
                        + (f" [{vm.cve}]" if vm.cve else "")
                    ),
                    remediation=vm.remediation,
                    evidence={
                        "cve": vm.cve, "vuln_name": vm.name,
                        "tags": list(vm.tags), "references": list(vm.references),
                        "addr": addr, "service_uuid": svc_uuid,
                        "service_name": svc.get("name", ""),
                    },
                    engagement_id=engagement_id,
                ))
                log.info(
                    f"FINDING [{vm.severity}] cve_match: {addr} — "
                    f"{vm.name}" + (f" ({vm.cve})" if vm.cve else "")
                )

        # Check for insecure auth mode in sdptool output
        auth_mode = _extract_auth_mode(services)
        if auth_mode:
            dev["auth_mode"] = auth_mode
            if _auth_mode_weak(auth_mode):
                _record_weak_auth_finding(dev, auth_mode, engagement_id)


def _sdp_browse(addr: str) -> list[dict]:
    """Return list of SDP service record dicts from sdptool browse."""
    services: list[dict] = []
    try:
        result = subprocess.run(
            ["sdptool", "browse", "--xml", addr],
            capture_output=True, text=True, timeout=_SDP_TIMEOUT,
        )
        raw = result.stdout

        # Parse XML service records (handle non-XML output gracefully)
        if "<record>" in raw:
            for rec in raw.split("<record>")[1:]:
                entry = _parse_sdp_xml_record(rec)
                if entry:
                    services.append(entry)
                    log.info(
                        f"[S21]   SDP: {entry.get('name','?')} "
                        f"uuid={entry.get('uuid','?')}"
                    )
        else:
            # Plain-text sdptool output
            for blk in re.split(r"(?=Service Name:)", raw):
                entry = _parse_sdp_text_block(blk)
                if entry:
                    services.append(entry)
                    log.info(
                        f"[S21]   SDP: {entry.get('name','?')} "
                        f"uuid={entry.get('uuid','?')}"
                    )
    except subprocess.TimeoutExpired:
        log.debug(f"[S21] sdptool browse {addr} timed out")
    except Exception as exc:
        log.debug(f"[S21] sdptool browse {addr}: {exc}")
    return services


def _parse_sdp_xml_record(xml: str) -> dict | None:
    """Extract name, uuid, and channel from an SDP XML record fragment."""
    entry: dict = {}
    m = re.search(r'<text value="([^"]+)"', xml)
    if m:
        entry["name"] = m.group(1)
    uuid_m = re.search(r'<uuid value="(0x[0-9a-fA-F]+)"', xml)
    if uuid_m:
        entry["uuid"] = uuid_m.group(1).lower()
    ch_m = re.search(r'<uint8 value="(0x[0-9a-fA-F]+)"', xml)
    if ch_m:
        entry["channel"] = int(ch_m.group(1), 16)
    if entry:
        entry["raw"] = xml[:120]
    return entry or None


def _parse_sdp_text_block(blk: str) -> dict | None:
    """Extract name and UUID from plain-text sdptool block."""
    entry: dict = {}
    nm = re.search(r"Service Name:\s*(.+)", blk)
    if nm:
        entry["name"] = nm.group(1).strip()
    uuid_m = re.search(r"UUID\s*:\s*(0x[0-9a-fA-F]+)", blk)
    if uuid_m:
        entry["uuid"] = uuid_m.group(1).lower()
    ch_m = re.search(r"Channel:\s*(\d+)", blk)
    if ch_m:
        entry["channel"] = int(ch_m.group(1))
    return entry if entry else None


def _is_risky_service(svc: dict) -> bool:
    uuid = svc.get("uuid", "")
    return any(uuid == k.lower() for k in _RISKY_SVCS)


def _extract_auth_mode(services: list[dict]) -> str | None:
    """Look for security mode information across all service records."""
    for svc in services:
        raw = svc.get("raw", "")
        m = re.search(r"auth.*?(\w+)", raw, re.I)
        if m:
            return m.group(1)
    return None


def _auth_mode_weak(mode: str) -> bool:
    weak_terms = {"open", "none", "0", "noauth", "no_auth", "none"}
    return mode.lower() in weak_terms


# ── Ubertooth BR/EDR sniff ─────────────────────────────────────────────────────

def _ubertooth_sniff(ubertooth_dongle: WhadDongle, engagement_id: str) -> None:
    """Passive BR/EDR piconet sniff using ubertooth-rx or ubertooth-br."""
    log.info(f"[S21] Ubertooth passive BR/EDR sniff ({_UBERTOOTH_SECS}s) ...")
    log.info(f"\n  [S21] Ubertooth passive BR/EDR sniff — {_UBERTOOTH_SECS}s")
    log.info("       Listening for BR/EDR piconet traffic on frequency hop ...")

    tool = None
    for candidate in ("ubertooth-br", "ubertooth-rx"):
        if shutil.which(candidate):
            tool = candidate
            break

    if tool is None:
        log.warning(
            "[S21] ubertooth-br and ubertooth-rx not found in PATH. "
            "Install ubertooth-utils to enable BR/EDR sniffing."
        )
        return

    _pcap = pcap_path(engagement_id, 21, "btclassic")

    if tool == "ubertooth-br":
        cmd = ["ubertooth-br", "-t", str(_UBERTOOTH_SECS), "-o", str(_pcap)]
    else:
        cmd = ["ubertooth-rx", "-f", "-t", str(_UBERTOOTH_SECS)]

    log.info(f"[S21] Running: {' '.join(cmd)}")

    stdout_lines: list[str] = []
    packets_seen = 0

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.time() + _UBERTOOTH_SECS + 5
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            line = line.rstrip()
            stdout_lines.append(line)
            log.debug(f"[ubertooth] {line}")
            if re.search(r"(packet|pkt|LAP|UAP|bdaddr)", line, re.I):
                packets_seen += 1
                log.info(f"  [ubertooth] {line}")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    except Exception as exc:
        log.warning(f"[S21] Ubertooth run error: {type(exc).__name__}: {exc}")
        return

    log.info(f"[S21] Ubertooth sniff done. Packets/events seen: {packets_seen}")

    if packets_seen > 0:
        _record_piconet_finding(engagement_id, packets_seen, stdout_lines[:20], str(_pcap))
    else:
        log.info("[S21] Ubertooth: no BR/EDR traffic detected.")


# ── Findings ───────────────────────────────────────────────────────────────────

def _record_devices_finding(devices: list[dict], engagement_id: str) -> None:
    insert_finding(Finding(
        type="btc_device_found",
        severity="info",
        target_addr="btclassic",
        description=(
            f"{len(devices)} Bluetooth Classic (BR/EDR) device(s) discovered. "
            "BR/EDR devices are discoverable — name, address, and class are exposed. "
            "Active scan confirmed devices in range."
        ),
        remediation=(
            "Set devices to non-discoverable mode when not actively pairing. "
            "Enable Secure Simple Pairing (SSP) with numeric comparison. "
            "Disable legacy PIN pairing where possible."
        ),
        evidence={"devices": [{"addr": d["addr"], "name": d.get("name", "")} for d in devices]},
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [info] btc_device_found: {len(devices)} device(s)")


def _record_service_finding(dev: dict, risky: list[dict], engagement_id: str) -> None:
    svc_descriptions = [
        f"{s.get('name','?')} ({s.get('uuid','')}): {_RISKY_SVCS.get(s.get('uuid',''), 'risky')}"
        for s in risky
    ]
    insert_finding(Finding(
        type="btc_exposed_services",
        severity="medium",
        target_addr=dev["addr"],
        description=(
            f"BR/EDR device {dev['addr']} ({dev.get('name','unnamed')}) exposes "
            f"{len(risky)} potentially insecure SDP service(s): "
            + "; ".join(svc_descriptions[:3])
        ),
        remediation=(
            "Disable SPP, OBEX, and PAN services if not required. "
            "Require authentication before service access. "
            "Use Bluetooth profiles with mandatory encryption."
        ),
        evidence={
            "addr": dev["addr"],
            "name": dev.get("name"),
            "risky_services": risky,
        },
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [medium] btc_exposed_services: {dev['addr']}")


def _record_weak_auth_finding(dev: dict, auth_mode: str, engagement_id: str) -> None:
    insert_finding(Finding(
        type="btc_weak_security_mode",
        severity="high",
        target_addr=dev["addr"],
        description=(
            f"BR/EDR device {dev['addr']} ({dev.get('name','unnamed')}) "
            f"reports weak or open authentication mode: {auth_mode!r}. "
            "Devices accepting unauthenticated connections are vulnerable to "
            "BlueBorne, KNOB, and legacy PIN brute-force attacks."
        ),
        remediation=(
            "Enable Bluetooth Security Mode 4 (Secure Simple Pairing). "
            "Disable legacy PIN mode. Require Numeric Comparison or Passkey Entry. "
            "Apply firmware patches for BlueBorne / KNOB CVEs."
        ),
        evidence={"addr": dev["addr"], "auth_mode": auth_mode},
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [high] btc_weak_security_mode: {dev['addr']} mode={auth_mode}")


def _record_piconet_finding(
    engagement_id: str, packets: int, lines: list[str], pcap: str
) -> None:
    insert_finding(Finding(
        type="btc_piconet_sniffed",
        severity="high",
        target_addr="btclassic",
        description=(
            f"Ubertooth One passively captured {packets} BR/EDR piconet event(s). "
            "Frequency-hopping BR/EDR traffic was decoded. "
            "An attacker in range can recover piconet parameters (LAP/UAP/NAP/BD_ADDR) "
            "and attempt session key recovery for unencrypted links."
        ),
        remediation=(
            "Ensure all BR/EDR connections use encryption (LMP_encryption_mode=1). "
            "Enable Secure Connections (eSCO/eSCO-S). "
            "Monitor for unexpected BR/EDR scanners in the area."
        ),
        evidence={"packets_seen": packets, "sample_output": lines[:10]},
        pcap_path=pcap,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [high] btc_piconet_sniffed: {packets} events")


# ── Summary ────────────────────────────────────────────────────────────────────

def _print_summary(devices: list[dict]) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 21 SUMMARY -- Bluetooth Classic (BR/EDR) Scout")
    log.info("─" * 76)
    log.info(f"  {'Devices found':<22}: {len(devices)}")
    if devices:

        log.info(f"  {'ADDRESS':<20}  {'NAME':<24}  SERVICES")
        log.info("  " + "─" * 64)
        for d in devices[:20]:
            svcs = len(d.get("services", []))
            risky = len(d.get("risky_services", []))
            risky_tag = f" [{risky} risky!]" if risky else ""
            log.info(
                f"  {d['addr']:<20}  {d.get('name','(unnamed)')[:24]:<24}  "
                f"{svcs} service(s){risky_tag}"
            )
    log.info("─" * 76 + "\n")


def _print_no_hardware() -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 21 — Bluetooth Classic Scout (skipped)")
    log.info("─" * 76)
    log.info("  No BR/EDR hardware detected:")
    log.info("    — HCI adapter (hci0): not found or BlueZ not running")
    log.info("    — Ubertooth One: not connected (--ubertooth-interface ubertooth0)")

    log.info("  To enable this stage, connect one of the above and rerun.")
    log.info("─" * 76 + "\n")
