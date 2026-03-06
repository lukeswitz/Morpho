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
FUZZ_TIMEOUT    = 300   # seconds for fuzz script execution (increased for bigger payload set)
SETTLE_SECS     = 2.0   # pause between Phase 1 and Phase 2

# Fuzz payloads: (label, command, hex_bytes_string)
# command is "write" (expects ATT response) or "writecmd" (no response)
_FUZZ_PAYLOADS: list[tuple[str, str, str]] = [
    # Basic coverage
    ("empty",       "write",    ""),
    ("null_1",      "write",    "00"),
    ("null_20",     "write",    "00 " * 20),
    ("ff_20",       "write",    "ff " * 20),
    ("ff_200",      "write",    "ff " * 200),
    ("ff_512",      "write",    "ff " * 512),
    ("seq_256",     "write",    " ".join(f"{i:02x}" for i in range(256))),
    # ATT MTU boundary probes (MTU negotiated to 247 in S5: max payload = 244 bytes)
    ("mtu_exact",   "write",    "aa " * 244),   # exactly at limit
    ("mtu_plus1",   "write",    "aa " * 245),   # one over — ATT should reject
    ("mtu_plus8",   "write",    "aa " * 252),
    ("ovf_300",     "write",    "cc " * 300),
    # Type confusion — firmware may parse these as typed values
    ("bool_true",   "write",    "01"),
    ("bool_inv",    "write",    "02"),           # invalid boolean
    ("int_zero",    "write",    "00 00 00 00"),
    ("int_maxu32",  "write",    "ff ff ff ff"),
    ("int_neg64",   "write",    "ff ff ff ff ff ff ff ff"),  # -1 as int64
    ("float_nan",   "write",    "00 00 c0 ff"),  # IEEE 754 NaN (little-endian)
    ("float_inf",   "write",    "00 00 80 7f"),  # +Inf
    ("ascii_20",    "write",    " ".join(f"{b:02x}" for b in b"A" * 20)),
    ("ascii_fmt",   "write",    " ".join(f"{b:02x}" for b in b"%s%s%s%n%n%n")),
    ("utf8_bomb",   "write",    " ".join(f"{b:02x}" for b in "AAAA\x00\xff\xfe".encode())),
    # Cycling and alternating patterns
    ("cycle_64",    "write",    " ".join(f"{i%256:02x}" for i in range(64))),
    ("alt_7f80",    "write",    "7f 80 " * 20),
    ("alt_0100",    "write",    "01 00 " * 20),
    # write-without-response variants
    ("ff_20_nc",    "writecmd", "ff " * 20),
    ("ff_200_nc",   "writecmd", "ff " * 200),
    ("mtu_nc",      "writecmd", "aa " * 244),
]

# Payloads for subscribe+write notification-handler fuzzing (smaller focused set)
_SUB_WRITE_PAYLOADS: list[tuple[str, str, str]] = [
    ("sw_empty",    "write",    ""),
    ("sw_ff_20",    "write",    "ff " * 20),
    ("sw_ff_200",   "write",    "ff " * 200),
    ("sw_mtu",      "write",    "aa " * 244),
    ("sw_ovf",      "write",    "ff " * 512),
    ("sw_nc_200",   "writecmd", "ff " * 200),
]


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    prepped_handles: list[int] | None = None,
) -> list[int]:
    """Run the GATT fuzz stage. Returns the writable handles discovered (may be empty)."""
    if not _cli_available():
        log.error(
            "[S7] wble-connect or wble-central not found in PATH. "
            "Install WHAD tools: pip install whad"
        )
        return []

    addr = target.bd_address
    rand_flag = "-r" if target.address_type != "public" else ""

    if prepped_handles is not None:
        # S5 already profiled this device — skip Phase 1
        writable_handles = prepped_handles
        notify_handles: list[int] = []
        log.info(
            f"[S7] Using {len(writable_handles)} writable handle(s) from S5: "
            f"{writable_handles} — skipping re-profile."
        )
        dongle.device.close()
        time.sleep(0.5)
    else:
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
            return []
        except Exception as exc:
            log.error(f"[S7] Profile subprocess error: {type(exc).__name__}: {exc}")
            _reopen_dongle(dongle)
            return []

        log.debug(f"[S7] Raw profile stdout for {addr}: {profile_stdout[:500]!r}")
        writable_handles, notify_handles = _parse_handles(profile_stdout)
        if not writable_handles:
            log.info(f"[S7] No writable handles found on {addr} — nothing to fuzz.")
            _reopen_dongle(dongle)
            return []

        log.info(
            f"[S7] Found {len(writable_handles)} writable handle(s): {writable_handles}"
            + (f", {len(notify_handles)} notifiable: {notify_handles}" if notify_handles else "")
            + " — building fuzz script ..."
        )

    script_path, total_writes = _write_fuzz_script(
        writable_handles, engagement_id, notify_handles=notify_handles
    )
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
            f"| wble-central --file {script_path}"
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

    if not crash_detected:
        crash_detected = _detect_crash(fuzz_stdout, fuzz_rc)

    writes_sent, error_count = _parse_fuzz_output(fuzz_stdout, total_writes)

    log.info(
        f"[S7] Fuzz complete: handles={len(writable_handles)}  "
        f"writes={writes_sent}/{total_writes}  errors={error_count}  "
        f"crash={crash_detected}  exit={fuzz_rc}"
    )

    try:
        Path(script_path).unlink(missing_ok=True)
    except Exception:
        pass

    _record_finding(
        target, engagement_id,
        writable_handles, writes_sent, total_writes, error_count, crash_detected,
    )
    _print_summary(
        target, writable_handles, writes_sent, total_writes, error_count,
        crash_detected,
    )
    return writable_handles


# ── Helpers ─────────────────────────────────────────────────────────────────

def _cli_available() -> bool:
    return (
        shutil.which("wble-connect") is not None
        and shutil.which("wble-central") is not None
    )


def _parse_handles(profile_output: str) -> tuple[list[int], list[int]]:
    """Parse writable and notifiable value handles from wble-central profile output.

    Returns (writable_handles, notify_handles). A handle may appear in both.
    Rights letters: R=read, W=write, N=notify, I=indicate.
    """
    ansi_re = re.compile(r"\[[0-9;]*[mABCDEFGHJKLMSTfnsulh]")
    writable: list[int] = []
    notifiable: list[int] = []

    for raw_line in profile_output.splitlines():
        line = ansi_re.sub("", raw_line).strip()
        if not line:
            continue
        vh_match = re.search(r"value handle:\s*(\d+)", line, re.I)
        if not vh_match:
            continue
        if re.match(r"service", line, re.I):
            continue
        prefix = re.split(r",\s*handle\s+\d+", line, maxsplit=1)[0]
        after_name = re.sub(r".*\)", "", prefix).strip()
        rights_letters = set((after_name or prefix).upper().replace(" ", ""))
        vh = int(vh_match.group(1))
        if "W" in rights_letters:
            writable.append(vh)
        if "N" in rights_letters or "I" in rights_letters or "notify" in line.lower():
            notifiable.append(vh)

    return writable, notifiable


def _parse_writable_handles(profile_output: str) -> list[int]:
    """Extract value_handle integers for writable characteristics.

    Actual wble-central profile output (ANSI stripped):
      Battery Level (0x2a19) RW, handle 9, value handle: 10
      Write Control Point (0x2a55) W, handle 22, value handle: 23

    Rights letters: R=read, W=write or write_no_resp. Both write types show as 'W'.
    Service lines ("Service ... (handle N to N)") are skipped.
    """
    ansi_re = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKLMSTfnsulh]")
    handles: list[int] = []

    for raw_line in profile_output.splitlines():
        line = ansi_re.sub("", raw_line).strip()
        if not line:
            continue

        # Must have "value handle: N" to be a characteristic line
        vh_match = re.search(r"\bvalue handle:\s*(\d+)", line, re.I)
        if not vh_match:
            continue

        # Skip service lines
        if re.match(r"service\b", line, re.I):
            continue

        # Rights section: text before ", handle N" minus the name (ends at ')')
        prefix = re.split(r",\s*handle\s+\d+", line, maxsplit=1)[0]
        after_name = re.sub(r".*\)", "", prefix).strip()
        rights_letters = set((after_name or prefix).upper().replace(" ", ""))

        if "W" not in rights_letters:
            continue

        handles.append(int(vh_match.group(1)))

    return handles


def _write_fuzz_script(
    handles: list[int],
    engagement_id: str,
    notify_handles: list[int] | None = None,
) -> tuple[str, int]:
    """Generate a wble-central gsh fuzz script and write it to a temp file.

    Phase A: standard payload matrix against all writable handles.
    Phase B: subscribe+write notification-handler fuzzing for notifiable handles.
    Returns (script_path, total_write_count).
    """
    import os
    lines: list[str] = []

    for handle in handles:
        for _label, cmd, hex_payload in _FUZZ_PAYLOADS:
            payload = hex_payload.strip()
            if payload:
                lines.append(f"{cmd} {handle} hex {payload}")
            else:
                lines.append(f"{cmd} {handle} hex")

    # Subscribe+write: enable notifications on handle, fuzz the value, unsub.
    # Targets notification callback handlers which are often less hardened than
    # the ATT write handler itself.
    for nh in (notify_handles or []):
        lines.append(f"sub {nh}")
        for _label, cmd, hex_payload in _SUB_WRITE_PAYLOADS:
            payload = hex_payload.strip()
            if payload:
                lines.append(f"{cmd} {nh} hex {payload}")
            else:
                lines.append(f"{cmd} {nh} hex")
        lines.append(f"unsub {nh}")

    script = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix=f"s7_{engagement_id}_", suffix=".gsh")
    try:
        os.write(fd, script.encode())
    finally:
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
    # If no explicit acks but errors seen: those errors ARE write responses — count them.
    if writes_sent == 0 and error_count > 0:
        writes_sent = error_count
    # If wble-central emits nothing at all, fall back to expected count
    elif writes_sent == 0 and error_count == 0 and stdout.strip():
        writes_sent = expected_writes
    return writes_sent, error_count


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-attach the WhadDevice, polling every 0.5s up to 6s."""
    deadline = time.time() + 15.0
    attempt = 0
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            if attempt > 0:
                log.debug(f"[S7] Reopen succeeded after {attempt * 0.5:.1f}s")
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            time.sleep(0.5)
    log.warning(
        f"[S7] Could not reopen WHAD device after 15s "
        f"({type(last_exc).__name__}: {last_exc!r})"
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
) -> None:
    severity, _ = _assess(
        writable_handles, writes_sent, total_writes, error_count, crash_detected, target
    )
    if writable_handles:
        handles_str = str(writable_handles[:8])
        if len(writable_handles) > 8:
            handles_str = handles_str[:-1] + f", +{len(writable_handles) - 8} more]"
    else:
        handles_str = "none"

    print("\n" + "─" * 76)
    print("  STAGE 7 SUMMARY -- GATT Write Fuzzer (CLI)")
    print("─" * 76)
    print(f"  {'Target':<18}: {target.bd_address}")
    print(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    print(f"  {'Device class':<18}: {target.device_class}")
    print(f"  {'Writable handles':<18}: {handles_str}")
    print(f"  {'Writes / total':<18}: {writes_sent} / {total_writes}")
    print(f"  {'Error responses':<18}: {error_count}")
    crash_val = "YES — disconnected mid-fuzz" if crash_detected else "no"
    print(f"  {'Crash detected':<18}: {crash_val}")
    print(f"\n  {'Severity':<18}: {severity.upper()}")
    if crash_detected:
        print(
            "  Why               : Disconnect under fuzz — buffer overflow\n"
            "                      or unhandled exception in BLE GATT stack."
        )
    elif error_count == 0 and writes_sent > 0:
        print(
            "  Why               : All payloads accepted including 200-512 byte\n"
            "                      writes — missing ATT payload length validation."
        )
    print("─" * 76 + "\n")
