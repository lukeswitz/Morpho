"""
Stage 14 — Enhanced ShockBurst (ESB) Raw Scanner

Passive channel-hop scan across ESB channels (2402–2480 MHz). Captures device
addresses and payload metadata for ESB devices NOT using Logitech Unifying
framing (those are handled by Stage 10).

WHAD's whad.esb.Scanner has a known kwargs mismatch on older firmware versions
(super().sniff() TypeError). This stage handles that crash gracefully and reports
a clear diagnostic. If the API is functional, it records all discovered ESB devices
as findings with channel and packet count evidence.
"""

from __future__ import annotations

import math
import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s14_esb")

# ESB channel sweep: 2402–2480 MHz in 5 MHz steps → 16 channels
_ESB_CHANNELS: list[int] = list(range(2, 81, 5))  # offsets from 2400 MHz

try:
    from whad.esb import Scanner as _EsbScanner
    _ESB_IMPORTABLE = True
except ImportError:
    _EsbScanner = None  # type: ignore[assignment,misc]
    _ESB_IMPORTABLE = False

try:
    from whad.esb import Sniffer as _EsbSniffer
    _ESB_SNIFFER_IMPORTABLE = True
except ImportError:
    _EsbSniffer = None  # type: ignore[assignment,misc]
    _ESB_SNIFFER_IMPORTABLE = False

def _patch_connector_sniff() -> bool:
    """Patch Connector.sniff() to accept and drop ESB-specific kwargs.

    whad.esb.Scanner.__init__ calls super().sniff(show_acknowledgements=True,
    address=...) but the base Connector.sniff() only accepts (messages, timeout).
    Known bug tracked in whad-client issue #288, targeted for v1.3.0.
    This patch lets Scanner instantiate cleanly on v1.2.x.
    """
    try:
        from whad.device.connector import Connector
        orig = Connector.sniff
        if getattr(orig, "_esb_patched", False):
            return True
        def _patched(self, messages=None, timeout=None, **_kwargs):
            return orig(self, messages=messages, timeout=timeout)
        _patched._esb_patched = True  # type: ignore[attr-defined]
        Connector.sniff = _patched  # type: ignore[method-assign]
        return True
    except Exception:
        return False


# ── Entry point ───────────────────────────────────────────────────────────────

def run(dongle: WhadDongle, engagement_id: str) -> None:
    if not _ESB_IMPORTABLE and not _ESB_SNIFFER_IMPORTABLE:
        log.warning(
            "[S14] whad.esb module not importable on this installation. "
            "ESB raw scan skipped."
        )
        return

    # RfStorm (nRF24L01+) uses whad.esb.Sniffer with channel=None — loops all
    # 0-100 channels natively and is stable on installed WHAD.
    # nRF52840 (butterfly) uses whad.esb.Scanner which requires a monkey-patch
    # to work around a kwargs mismatch bug in super().sniff().
    if dongle.caps.device_type == "rfstorm" and _ESB_SNIFFER_IMPORTABLE:
        log.info("[S14] RfStorm device — using ESB Sniffer (channel=None, stable path).")
        _scan_with_sniffer(dongle, engagement_id)
    else:
        log.info("[S14] Using ESB Scanner path (nRF52840 / fallback).")
        _scan_with_scanner(dongle, engagement_id)


def _scan_with_sniffer(dongle: WhadDongle, engagement_id: str) -> None:
    """ESB Sniffer path — stable on RfStorm; loops all channels automatically."""
    log.info(
        f"[S14][sniffer] ESB Sniffer — scanning all channels "
        f"({config.ESB_SCAN_SECS}s total) ..."
    )

    devices: dict[str, dict] = {}
    plaintext_addrs: dict[str, list[str]] = {}

    try:
        sniffer = _EsbSniffer(dongle.device)
        sniffer.channel = None  # None → scan all channels 0-100
        sniffer.start()
    except Exception as exc:
        log.warning(f"[S14][sniffer] ESB Sniffer init/start failed: {type(exc).__name__}: {exc}")
        return

    deadline = time.time() + config.ESB_SCAN_SECS
    try:
        for pkt in sniffer.sniff():
            if time.time() >= deadline:
                break
            ch = getattr(pkt, "channel", getattr(pkt, "rf_channel", "?"))
            addr = _extract_addr(pkt)
            if addr:
                if addr not in devices:
                    devices[addr] = {"channels": set(), "packet_count": 0, "sample_hex": ""}
                    log.info(f"[S14][sniffer] New ESB device: {addr} on ch {ch}")
                devices[addr]["channels"].add(ch)
                devices[addr]["packet_count"] += 1
                if not devices[addr]["sample_hex"]:
                    try:
                        devices[addr]["sample_hex"] = bytes(pkt).hex()[:32]
                    except Exception:
                        pass
                payload = _extract_payload(pkt)
                if payload and _looks_plaintext(payload):
                    if addr not in plaintext_addrs:
                        plaintext_addrs[addr] = []
                        log.info(
                            f"[S14][sniffer] Low-entropy payload from {addr} "
                            f"(entropy={_entropy(payload):.2f}) — possible plaintext ESB"
                        )
                    plaintext_addrs[addr].append(payload.hex()[:32])
    except Exception as exc:
        log.debug(f"[S14][sniffer] sniff loop: {type(exc).__name__}: {exc}")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    _record_findings(engagement_id, devices, plaintext_addrs)
    _print_summary(devices, plaintext_addrs)


def _scan_with_scanner(dongle: WhadDongle, engagement_id: str) -> None:
    """ESB Scanner path — nRF52840 / fallback; requires monkey-patch on v1.2.x."""
    if not _ESB_IMPORTABLE:
        log.warning("[S14][scanner] whad.esb.Scanner not importable — skipping.")
        return

    if dongle.caps.device_type != "rfstorm":
        if not _patch_connector_sniff():
            log.warning("[S14][scanner] Could not patch Connector.sniff() — scan may fail.")

    log.info(
        f"[S14][scanner] ESB raw channel scan — {len(_ESB_CHANNELS)} channels "
        f"× {config.ESB_PER_CH_SECS}s dwell ({config.ESB_SCAN_SECS}s total) ..."
    )

    try:
        scanner = _EsbScanner(dongle.device)
    except TypeError as exc:
        log.warning(
            f"[S14][scanner] ESB Scanner API incompatible with this WHAD version: {exc}\n"
            "  Known issue: whad.esb.Scanner kwargs mismatch in super().sniff(). "
            "Upgrade WHAD to fix. ESB scan skipped."
        )
        return
    except Exception as exc:
        log.warning(f"[S14][scanner] ESB Scanner init failed: {type(exc).__name__}: {exc}")
        return

    try:
        scanner.start()
    except TypeError as exc:
        log.warning(f"[S14][scanner] ESB Scanner.start() TypeError: {exc} — skipping.")
        return
    except Exception as exc:
        log.warning(f"[S14][scanner] ESB Scanner.start() failed: {type(exc).__name__}: {exc}")
        return

    devices: dict[str, dict] = {}
    plaintext_addrs: dict[str, list[str]] = {}
    deadline = time.time() + config.ESB_SCAN_SECS
    scan_ok = True

    try:
        while time.time() < deadline and scan_ok:
            for ch in _ESB_CHANNELS:
                if time.time() >= deadline:
                    break
                try:
                    pkt = scanner.wait_packet(timeout=config.ESB_PER_CH_SECS)
                    if pkt is not None:
                        addr = _extract_addr(pkt)
                        if addr:
                            if addr not in devices:
                                devices[addr] = {
                                    "channels": set(),
                                    "packet_count": 0,
                                    "sample_hex": "",
                                }
                                log.info(f"[S14][scanner] New ESB device: {addr} on ch {ch}")
                            devices[addr]["channels"].add(ch)
                            devices[addr]["packet_count"] += 1
                            if not devices[addr]["sample_hex"]:
                                try:
                                    devices[addr]["sample_hex"] = bytes(pkt).hex()[:32]
                                except Exception:
                                    pass
                            payload = _extract_payload(pkt)
                            if payload and _looks_plaintext(payload):
                                if addr not in plaintext_addrs:
                                    plaintext_addrs[addr] = []
                                    log.info(
                                        f"[S14][scanner] Low-entropy payload from {addr} "
                                        f"(entropy={_entropy(payload):.2f} bits/byte)"
                                        " — possible unencrypted ESB traffic"
                                    )
                                plaintext_addrs[addr].append(payload.hex()[:32])
                except TypeError as exc:
                    log.warning(
                        f"[S14][scanner] ESB scan API crash on ch {ch}: {exc}\n"
                        "  Known issue: whad.esb.Scanner incompatible with this WHAD version."
                    )
                    scan_ok = False
                    break
                except AttributeError:
                    log.debug("[S14][scanner] wait_packet() not available — scan aborted.")
                    scan_ok = False
                    break
                except Exception as exc:
                    log.debug(f"[S14][scanner] ch {ch}: {type(exc).__name__}: {exc}")
    finally:
        try:
            scanner.stop()
        except Exception:
            pass

    _record_findings(engagement_id, devices, plaintext_addrs)
    _print_summary(devices, plaintext_addrs)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_addr(pkt) -> str | None:
    """Try common attribute names for ESB source address."""
    for attr in ("address", "src_address", "addr", "esb_address", "source"):
        val = getattr(pkt, attr, None)
        if val is not None:
            return str(val)
    return None


def _extract_payload(pkt) -> bytes | None:
    """Return the ESB application payload bytes from a captured packet."""
    for attr in ("payload", "app_payload", "pdu", "data"):
        val = getattr(pkt, attr, None)
        if val is not None:
            try:
                b = bytes(val)
                if b:
                    return b
            except Exception:
                pass
    try:
        raw = bytes(pkt)
        if len(raw) > 5:
            return raw[5:]
    except Exception:
        pass
    return None


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_plaintext(payload: bytes) -> bool:
    """Return True when Shannon entropy < 4.5 bits/byte (structured/unencrypted data)."""
    if len(payload) < 4:
        return False
    return _entropy(payload) < 4.5


# ── Findings ──────────────────────────────────────────────────────────────────

def _record_findings(
    engagement_id: str,
    devices: dict,
    plaintext_addrs: dict[str, list[str]],
) -> None:
    for addr, info in devices.items():
        insert_finding(Finding(
            type="esb_device_discovered",
            severity="info",
            target_addr=addr,
            description=(
                f"ESB device {addr} detected on channel(s) "
                f"{sorted(info['channels'])} — {info['packet_count']} packet(s). "
                "Non-Logitech ESB device: may be keyboard, mouse, game controller, "
                "drone controller, or industrial sensor using proprietary ESB framing."
            ),
            remediation=(
                "Verify device firmware uses AES-128 encryption and replay protection. "
                "Consider migrating to BLE or 802.15.4 with authenticated key exchange. "
                "For legacy devices, ensure physical proximity controls limit RF exposure."
            ),
            evidence={
                "channels": sorted(info["channels"]),
                "packet_count": info["packet_count"],
                "sample_payload_hex": info["sample_hex"],
            },
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info(f"FINDING [info] esb_device_discovered: {addr}")

    for addr, samples in plaintext_addrs.items():
        insert_finding(Finding(
            type="esb_unencrypted_traffic",
            severity="medium",
            target_addr=addr,
            description=(
                f"ESB device {addr} transmitted low-entropy payloads consistent with "
                f"unencrypted data ({len(samples)} sample(s)). "
                "Unencrypted ESB traffic exposes device state and commands to passive sniffing."
            ),
            remediation=(
                "Enable AES-128 encryption in the ESB application layer. "
                "Consider migrating to BLE or 802.15.4 with authenticated key exchange. "
                "Verify encryption is active on all transmitted channels."
            ),
            evidence={"plaintext_samples_hex": samples[:5]},
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info(f"FINDING [medium] esb_unencrypted_traffic: {addr}")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(devices: dict, plaintext_addrs: dict[str, list[str]]) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 14 SUMMARY -- ESB Raw Channel Scan")
    print("─" * 76)
    print(f"  {'Channels swept':<20}: {len(_ESB_CHANNELS)}")
    print(f"  {'ESB devices found':<20}: {len(devices)}")
    print(f"  {'Unencrypted traffic':<20}: {len(plaintext_addrs)} device(s)")
    if devices:
        print()
        print("  Detected devices:")
        for addr, info in sorted(devices.items()):
            chs = sorted(info["channels"])
            enc_flag = "  [PLAINTEXT]" if addr in plaintext_addrs else ""
            print(f"    {addr:<24}  channels={chs}  packets={info['packet_count']}{enc_flag}")
    else:
        print("  Result: no ESB devices detected on scanned channels.")
    print("─" * 76 + "\n")
