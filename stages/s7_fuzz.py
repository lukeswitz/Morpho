"""
Stage 7 — CLI GATT Fuzz

Uses WHAD's CLI pipeline to fuzz writable GATT characteristics:

  Phase 1 — Profile:
      wble-connect -i <iface> [-r] <addr> | wble-central profile
      Discovers all writable value handles on the target.

  Phase 2 — Fuzz:
      wble-connect -i <iface> [-r] <addr> | wble-central --file /tmp/s7_<eng>.gsh
      Executes a generated script of write/writecmd payloads against each handle.

The generated script exercises each writable handle with:
  write    : empty, 0x00×1, 0x00×20, 0xFF×20, 0xFF×200, 0xFF×512, sequential 0x00-0xFF
  writecmd : 0xFF×20, 0xFF×200  (write-without-response)

Crash detection: connection drop (wble-connect exits early / timeout), or subprocess
returns non-zero exit after sending payloads that completed Phase 1 normally.

Mirrors Stage 5's dongle lifecycle: close device before CLI, reopen in finally.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path
import config

log = get_logger("s7_fuzz")

PROFILE_TIMEOUT = 45    # seconds for profile phase
FUZZ_TIMEOUT    = 120   # seconds for fuzz script execution
SETTLE_SECS     = 2.0   # pause between Phase 1 and Phase 2

# Fuzz payloads: (label, command, hex_bytes_string)
# command is "write" (expects ATT response) or "writecmd" (no response)
_FUZZ_PAYLOADS: list[tuple[str, str, str]] = [
    ("empty",      "write",    ""),
    ("null_1",     "write",    "00"),
    ("null_20",    "write",    "00 " * 20),
    ("ff_20",      "write",    "ff " * 20),
    ("ff_200",     "write",    "ff " * 200),
    ("ff_512",     "write",    "ff " * 512),
    ("seq_256",    "write",    " ".join(f"{i:02x}" for i in range(256))),
    # write-without-response variants
    ("ff_20_nc",   "writecmd", "ff " * 20),
    ("ff_200_nc",  "writecmd", "ff " * 200),
]


def run(dongle: WhadDongle, target: Target, engagement_id: str) -> None:
    """Run the CLI GATT fuzz pipeline against a single target.

    Args:
        dongle: Active WhadDongle (closed for CLI, reopened in finally).
        target: Connectable target to fuzz.
        engagement_id: Engagement ID for PCAP naming and Finding storage.
    """
    if not _cli_available():
        log.error(
            "[S7] wble-connect or wble-central not found in PATH. "
            "Install WHAD tools: pip install whad"
        )
        return

    addr = target.bd_address
    rand_flag = "-r" if target.address_type != "public" else ""
    _pcap = pcap_path(engagement_id, 7, addr)

    # ── Phase 1: Profile ────────────────────────────────────────────────────
    log.info(f"[S7] Phase 1 — profiling {addr} to discover writable handles ...")
    dongle.device.close()
    time.sleep(0.5)

    profile_stdout = ""
    try:
        cmd_profile = (
            f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
            f"| wble-central profile"
        )
        log.debug(f"[S7] Profile cmd: {cmd_profile}")
        result = subprocess.run(
            cmd_profile,
            shell=True,
            capture_output=True,
            text=True,
            timeout=PROFILE_TIMEOUT,
        )
        profile_stdout = result.stdout
        if result.stderr.strip():
            log.debug(f"[S7] Profile stderr: {result.stderr.strip()[:160]}")
    except subprocess.TimeoutExpired:
        log.warning(f"[S7] Profile timed out after {PROFILE_TIMEOUT}s — skipping S7.")
        _reopen_dongle(dongle)
        return
    except Exception as exc:
        log.error(f"[S7] Profile subprocess error: {type(exc).__name__}: {exc}")
        _reopen_dongle(dongle)
        return
    finally:
        _reopen_dongle(dongle)

    writable_handles = _parse_writable_handles(profile_stdout)
    if not writable_handles:
        log.info(f"[S7] No writable handles found on {addr} — nothing to fuzz.")
        _record_finding(target, engagement_id, str(_pcap), [], 0, 0, False)
        _print_summary(target, [], 0, 0, False, str(_pcap))
        return

    log.info(
        f"[S7] Found {len(writable_handles)} writable handle(s): "
        f"{writable_handles} — building fuzz script ..."
    )

    # ── Phase 2: Generate script + Fuzz ─────────────────────────────────────
    script_path, total_writes = _write_fuzz_script(writable_handles, engagement_id)
    log.info(
        f"[S7] Phase 2 — fuzzing {addr} with {total_writes} writes "
        f"across {len(writable_handles)} handle(s) ..."
    )
    log.info(f"[S7] Script: {script_path}")

    time.sleep(SETTLE_SECS)
    dongle.device.close()
    time.sleep(0.5)

    fuzz_stdout = ""
    fuzz_stderr = ""
    fuzz_rc = -1
    crash_detected = False

    try:
        cmd_fuzz = (
            f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
            f"| wble-central --file {script_path} --output {_pcap}"
        )
        log.debug(f"[S7] Fuzz cmd: {cmd_fuzz}")
        result = subprocess.run(
            cmd_fuzz,
            shell=True,
            capture_output=True,
            text=True,
            timeout=FUZZ_TIMEOUT,
        )
        fuzz_stdout = result.stdout
        fuzz_stderr = result.stderr
        fuzz_rc = result.returncode
    except subprocess.TimeoutExpired:
        # Timeout mid-fuzz: could be hang from crash
        log.warning(
            f"[S7] Fuzz timed out after {FUZZ_TIMEOUT}s — "
            "device may have crashed or stopped responding."
        )
        crash_detected = True
    except Exception as exc:
        log.error(f"[S7] Fuzz subprocess error: {type(exc).__name__}: {exc}")
    finally:
        _reopen_dongle(dongle)

    if fuzz_stderr.strip():
        log.debug(f"[S7] Fuzz stderr: {fuzz_stderr.strip()[:200]}")

    # Heuristic crash detection from stdout
    if not crash_detected:
        crash_detected = _detect_crash(fuzz_stdout, fuzz_rc)

    writes_sent, error_count = _parse_fuzz_output(fuzz_stdout, total_writes)

    log.info(
        f"[S7] Fuzz complete: handles={len(writable_handles)}  "
        f"writes={writes_sent}/{total_writes}  errors={error_count}  "
        f"crash={crash_detected}  exit={fuzz_rc}"
    )

    # Clean up temp script
    try:
        Path(script_path).unlink(missing_ok=True)
    except Exception:
        pass

    _record_finding(
        target, engagement_id, str(_pcap),
        writable_handles, writes_sent, total_writes, error_count, crash_detected,
    )
    _print_summary(
        target, writable_handles, writes_sent, total_writes, error_count,
        crash_detected, str(_pcap),
    )


# ── Helpers ─────────────────────────────────────────────────────────────────

def _cli_available() -> bool:
    return (
        shutil.which("wble-connect") is not None
        and shutil.which("wble-central") is not None
    )


def _parse_writable_handles(profile_output: str) -> list[int]:
    """Extract value_handle integers for writable characteristics.

    wble-central profile output format (approximate):
      Characteristic 0x2A06 [handle=3, value_handle=4] read write
    """
    handles: list[int] = []
    for line in profile_output.splitlines():
        low = line.lower()
        if "characteristic" not in low:
            continue
        if "write" not in low:
            continue
        # Extract value_handle if present, fall back to handle
        vh_match = re.search(r"value_handle\s*=\s*(\d+)", line, re.I)
        h_match  = re.search(r"handle\s*=\s*(\d+)", line, re.I)
        if vh_match:
            handles.append(int(vh_match.group(1)))
        elif h_match:
            handles.append(int(h_match.group(1)))
    return handles


def _write_fuzz_script(handles: list[int], engagement_id: str) -> tuple[str, int]:
    """Generate a wble-central gsh fuzz script and write it to a temp file.

    Returns (script_path, total_write_count).
    """
    lines: list[str] = []
    for handle in handles:
        for _label, cmd, hex_payload in _FUZZ_PAYLOADS:
            payload = hex_payload.strip()
            if payload:
                lines.append(f"{cmd} {handle} hex {payload}")
            else:
                lines.append(f"{cmd} {handle} hex")

    script = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix=f"s7_{engagement_id}_", suffix=".gsh")
    try:
        import os
        os.write(fd, script.encode())
    finally:
        import os
        os.close(fd)
    return path, len(lines)


def _detect_crash(stdout: str, returncode: int) -> bool:
    """Heuristic: did the fuzz session end in a crash?"""
    lo = stdout.lower()
    crash_keywords = (
        "connection lost", "disconnected", "connection error",
        "connection failed", "lost connection",
    )
    return returncode not in (0, -1) or any(kw in lo for kw in crash_keywords)


def _parse_fuzz_output(stdout: str, expected_writes: int) -> tuple[int, int]:
    """Estimate writes completed and errors from wble-central stdout.

    Returns (writes_sent, error_count).
    """
    writes_sent = 0
    error_count = 0
    for line in stdout.splitlines():
        lo = line.lower()
        if "write" in lo and ("ok" in lo or "success" in lo or "sent" in lo):
            writes_sent += 1
        if "error" in lo or "fail" in lo or "refused" in lo:
            error_count += 1
    # If wble-central doesn't emit per-write acks, fall back to expected count
    if writes_sent == 0 and error_count == 0 and stdout.strip():
        writes_sent = expected_writes
    return writes_sent, error_count


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the WhadDevice after a CLI run, with retry."""
    for attempt in range(3):
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            return
        except Exception as exc:
            if attempt < 2:
                log.debug(
                    f"[S7] Reopen attempt {attempt + 1} failed "
                    f"({type(exc).__name__}: {exc!r}) — retrying in 1s ..."
                )
                time.sleep(1.0)
            else:
                log.warning(
                    f"[S7] Could not reopen WHAD device after 3 attempts: "
                    f"{type(exc).__name__}: {exc!r}"
                )


# ── Finding + summary ────────────────────────────────────────────────────────

def _assess(
    writable_handles: list[int],
    writes_sent: int,
    total_writes: int,
    error_count: int,
    crash_detected: bool,
    target: Target,
) -> tuple[str, str]:
    name_tag = f"{target.bd_address} ({target.name or 'unnamed'}, {target.device_class})"

    if not writable_handles:
        return "info", (
            f"GATT fuzz found no writable characteristics on {name_tag}."
        )

    if crash_detected:
        return "critical", (
            f"GATT fuzz triggered crash/disconnect on {name_tag}. "
            f"Device disconnected mid-script ({writes_sent}/{total_writes} writes). "
            "Indicates buffer overflow or unhandled exception in BLE GATT stack."
        )

    if writes_sent > 0 and error_count > writes_sent // 2:
        return "high", (
            f"GATT fuzz completed on {name_tag} with high error rate. "
            f"Writes: {writes_sent}, errors: {error_count} "
            f"({int(100 * error_count / writes_sent)}%). "
            "Edge-case input validation issues likely."
        )

    if error_count > 0:
        return "medium", (
            f"GATT fuzz completed on {name_tag} with some error responses. "
            f"Writes: {writes_sent}, errors: {error_count}."
        )

    return "low", (
        f"GATT fuzz completed on {name_tag} — device accepted all payloads "
        f"including 200-byte and 512-byte writes without error. "
        f"Missing payload length validation on {len(writable_handles)} handle(s)."
    )


def _record_finding(
    target: Target,
    engagement_id: str,
    pcap_path_str: str,
    writable_handles: list[int],
    writes_sent: int,
    total_writes: int,
    error_count: int,
    crash_detected: bool,
) -> None:
    severity, description = _assess(
        writable_handles, writes_sent, total_writes, error_count, crash_detected, target
    )
    finding = Finding(
        type="gatt_fuzz",
        severity=severity,
        target_addr=target.bd_address,
        description=description,
        remediation=(
            "Validate payload length against expected bounds before processing. "
            "Return ATT error 0x0D (Application Error) for malformed writes. "
            "Add watchdog recovery to prevent BLE stack hangs on malformed input."
        ),
        evidence={
            "writable_handles": writable_handles,
            "total_payloads_planned": total_writes,
            "writes_sent": writes_sent,
            "error_count": error_count,
            "crash_detected": crash_detected,
        },
        pcap_path=pcap_path_str,
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(
        f"FINDING [{severity}] gatt_fuzz: {target.bd_address} — "
        f"handles={len(writable_handles)}  writes={writes_sent}  "
        f"errors={error_count}  crash={crash_detected}"
    )


def _print_summary(
    target: Target,
    writable_handles: list[int],
    writes_sent: int,
    total_writes: int,
    error_count: int,
    crash_detected: bool,
    pcap_path_str: str,
) -> None:
    severity, _ = _assess(
        writable_handles, writes_sent, total_writes, error_count, crash_detected, target
    )
    print("\n" + "-" * 72)
    print("  STAGE 7 SUMMARY -- GATT Write Fuzzer (CLI)")
    print("-" * 72)
    print(f"  Target              : {target.bd_address}")
    print(f"  Name                : {target.name or '(unnamed)'}")
    print(f"  Device class        : {target.device_class}")
    print(f"  Writable handles    : {writable_handles or 'none'}")
    print(f"  Writes sent / total : {writes_sent} / {total_writes}")
    print(f"  Error responses     : {error_count}")
    print(
        f"  Crash detected      : "
        f"{'YES — device disconnected mid-fuzz!' if crash_detected else 'no'}"
    )
    print(f"  PCAP                : {pcap_path_str}")
    print(f"\n  Severity            : {severity.upper()}")
    if crash_detected:
        print(
            "  Why                 : Disconnect under fuzz — buffer overflow\n"
            "                        or unhandled exception in BLE GATT stack."
        )
    elif error_count == 0 and writes_sent > 0:
        print(
            "  Why                 : All payloads accepted including 200-512 byte\n"
            "                        writes — missing ATT payload length validation."
        )
    print("-" * 72 + "\n")
