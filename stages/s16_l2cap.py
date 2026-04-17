"""
Stage 16 — L2CAP Connection-Oriented Channels (CoC) Security Test

LE L2CAP CoC (Bluetooth Core 4.1+) provides credit-based flow-control channels
above HCI for application data. Security issues include:

  - Unauthenticated CoC channels on dynamic PSMs (0x0080–0x00FF) accepting
    connections without pairing
  - Credit exhaustion / SDU fragmentation for DoS and buffer overflows  - CoC on unencrypted links exposing application data

Uses Linux AF_BLUETOOTH SOCK_SEQPACKET sockets (kernel >= 4.0). The host HCI
adapter (hci0 / config.PROXY_INTERFACE) connects to the target — not the WHAD
dongle, which does not natively expose raw L2CAP CoC.
"""

from __future__ import annotations

import socket
import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger, prompt_line
import config

log = get_logger("s16_l2cap")

_PROBE_PSMS: list[int] = [
    0x0023,  # ATT — should reject CoC
    0x0025,  # EATT (Bluetooth 5.1+ Enhanced ATT)
    0x0027,  # IPSP (IPv6 over BLE)
    0x0080, 0x0081, 0x0083, 0x00A0, 0x00C0, 0x00FF,  # dynamic PSM range
]

_FUZZ_SDUS: list[bytes] = [
    b"",
    b"\x00",
    b"\xff" * 20,
    b"\xff" * 512,
    b"A" * 244,
    b"\x00" * 1024,
    b"%s%s%n" * 5,
]

_CONNECT_TIMEOUT = config.L2CAP_CONNECT_TIMEOUT
_FUZZ_TIMEOUT    = config.L2CAP_FUZZ_TIMEOUT


def run(dongle: WhadDongle, engagement_id: str) -> None:
    if not _l2cap_available():
        log.warning(
            "[S16] AF_BLUETOOTH L2CAP CoC sockets unavailable. "
            "Requires Linux kernel >= 4.0 with Bluetooth subsystem. Stage skipped."
        )
        return

    target_addr = _prompt_target()
    if not target_addr:
        log.info("[S16] No target — skipped.")
        return

    addr_type = _prompt_addr_type()
    log.info(
        f"[S16] L2CAP CoC probe: target={target_addr} "
        f"addr_type={addr_type} hci={getattr(config, 'PROXY_INTERFACE', 'hci0')}"
    )
    log.info(f"[S16] Probing PSMs: {[hex(p) for p in _PROBE_PSMS]}")

    open_psms: list[int] = []
    fuzz_results: list[dict] = []

    for psm in _PROBE_PSMS:
        r = _probe_psm(target_addr, addr_type, psm)
        if r["accepted"]:
            open_psms.append(psm)
            log.info(f"[S16] PSM 0x{psm:04X} OPEN")
            fuzz = _fuzz_channel(target_addr, addr_type, psm)
            fuzz_results.append(fuzz)
            if fuzz["crash_suspected"]:
                log.info(f"[S16] PSM 0x{psm:04X} crash suspected after {fuzz['sdus_sent']} SDU(s)")
        else:
            log.debug(f"[S16] PSM 0x{psm:04X} rejected: {r['error']}")

    _record_findings(engagement_id, target_addr, open_psms, fuzz_results)
    _print_summary(target_addr, open_psms, fuzz_results)


def _probe_psm(addr: str, addr_type: str, psm: int) -> dict:
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        sock.settimeout(_CONNECT_TIMEOUT)
        at = 1 if "random" in addr_type.lower() else 0
        sock.connect((addr, psm, 0, at))
        sock.close()
        return {"accepted": True, "error": ""}
    except OSError as exc:
        return {"accepted": False, "error": str(exc)}
    except Exception as exc:
        return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}


def _fuzz_channel(addr: str, addr_type: str, psm: int) -> dict:
    fuzz: dict = {"psm": psm, "sdus_sent": 0, "errors": 0, "crash_suspected": False}
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        sock.settimeout(_FUZZ_TIMEOUT)
        at = 1 if "random" in addr_type.lower() else 0
        sock.connect((addr, psm, 0, at))
        for sdu in _FUZZ_SDUS:
            try:
                sock.send(sdu)
                fuzz["sdus_sent"] += 1
                time.sleep(0.05)
            except OSError:
                fuzz["crash_suspected"] = True
                fuzz["errors"] += 1
                break
            except Exception:
                fuzz["errors"] += 1
        sock.close()
    except OSError:
        if fuzz["sdus_sent"] > 0:
            fuzz["crash_suspected"] = True
        fuzz["errors"] += 1
    except Exception as exc:
        fuzz["errors"] += 1
        log.debug(f"[S16] fuzz PSM 0x{psm:04X}: {exc}")
    return fuzz


def _record_findings(
    engagement_id: str,
    target_addr: str,
    open_psms: list[int],
    fuzz_results: list[dict],
) -> None:
    if not open_psms:
        return
    crash_psms = [r["psm"] for r in fuzz_results if r.get("crash_suspected")]
    severity = "critical" if crash_psms else "high"
    insert_finding(Finding(
        type="l2cap_coc_open_psm",
        severity=severity,
        target_addr=target_addr,
        description=(
            f"L2CAP CoC accepted on {len(open_psms)} PSM(s) by {target_addr}: "
            f"{[hex(p) for p in open_psms]}. "
            + (
                f"Crash suspected on PSM(s) {[hex(p) for p in crash_psms]} after SDU fuzz. "
                "Possible buffer overflow in CoC PDU handler."
                if crash_psms
                else "No crash under SDU fuzz — unauthenticated channel may expose data."
            )
        ),
        remediation=(
            "Require LE Secure Connections pairing before accepting CoC connections. "
            "Validate SDU length against negotiated MTU/MPS before processing. "
            "Implement strict credit accounting — never process SDUs without credit."
        ),
        evidence={
            "target": target_addr,
            "open_psms_hex": [hex(p) for p in open_psms],
            "crash_psms_hex": [hex(p) for p in crash_psms],
            "fuzz_results": fuzz_results,
        },
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [{severity}] l2cap_coc_open_psm: {target_addr} — {len(open_psms)} open PSM(s)")


def _print_summary(
    target_addr: str,
    open_psms: list[int],
    fuzz_results: list[dict],
) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 16 SUMMARY -- L2CAP CoC Security Test")
    log.info("─" * 76)
    log.info(f"  {'Target':<22}: {target_addr}")
    log.info(f"  {'PSMs probed':<22}: {len(_PROBE_PSMS)}")
    log.info(f"  {'Open PSMs':<22}: {len(open_psms)}")
    if open_psms:
        for psm in open_psms:
            fr = next((r for r in fuzz_results if r["psm"] == psm), {})
            crash = "  *** CRASH ***" if fr.get("crash_suspected") else ""
            log.info(f"    PSM 0x{psm:04X}  sdus={fr.get('sdus_sent',0)}  errors={fr.get('errors',0)}{crash}")
    else:
        log.info("  Result: all PSMs rejected — no open CoC channels.")
    log.info("─" * 76 + "\n")


def _l2cap_available() -> bool:
    try:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        s.close()
        return True
    except (OSError, AttributeError):
        return False


def _prompt_target() -> str | None:
    log.info("\n  Stage 16 — L2CAP CoC Test")
    log.info("  BD address of target (uses hci0, not WHAD dongle):")
    try:
        raw = prompt_line("  Address [empty to skip]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return raw.upper() if raw else None


def _prompt_addr_type() -> str:
    try:
        c = prompt_line("  Address type [P]ublic / [R]andom [P]: ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        return "public"
    return "random" if c == "R" else "public"
