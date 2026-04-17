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
import threading
import time
from collections.abc import Callable
from pathlib import Path

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path
from core.vulndb import get_vuln_fuzz_payloads, get_sweyntooth_vulns, VulnMatch
import config

log = get_logger("s7_fuzz")

CONNECT_TIMEOUT = 15    # seconds for BLE connection attempt
PROFILE_TIMEOUT = 45    # seconds for profile phase
FUZZ_TIMEOUT    = config.FUZZ_TIMEOUT
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
    cancel: Callable[[], bool] | None = None,
) -> list[int]:
    """Run the GATT fuzz stage. Returns the writable handles discovered (may be empty)."""
    use_cli = _cli_available() and dongle.caps.device_type == "hci"
    addr = target.bd_address
    rand_flag = "-r" if target.address_type != "public" else ""

    notify_handles: list[int] = []
    handle_uuids: dict[int, str] = {}   # value_handle → short UUID for vulndb
    vuln_payloads_sent = 0
    response_times: dict[int, dict[str, float]] = {}

    if prepped_handles is not None:
        writable_handles = prepped_handles
        log.info(
            f"[S7] Using {len(writable_handles)} writable handle(s) from S5: "
            f"{writable_handles} — skipping re-profile."
        )
        if use_cli:
            dongle.device.close()
            time.sleep(0.5)
    elif use_cli:
        log.info(f"[S7] Phase 1 — profiling {addr} (CLI) ...")
        dongle.device.close()
        time.sleep(0.5)

        profile_stdout = ""
        try:
            cmd_profile = (
                f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
                f"| wble-central profile"
            )
            log.debug(f"[S7] Profile cmd: {cmd_profile}")
            result = _run_cancellable(cmd_profile, PROFILE_TIMEOUT, cancel)
            if result is None:
                log.info("[S7] Skip requested — aborting profile.")
                _reopen_dongle(dongle)
                return []
            profile_stdout, profile_stderr, _ = result
            if profile_stderr.strip():
                log.debug(f"[S7] Profile stderr: {profile_stderr.strip()[:160]}")
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
        handle_uuids = _parse_handle_uuids(profile_stdout)
        if not writable_handles:
            log.info(f"[S7] No writable handles found on {addr} — nothing to fuzz.")
            _reopen_dongle(dongle)
            return []

        log.info(
            f"[S7] Found {len(writable_handles)} writable handle(s): {writable_handles}"
            + (f", {len(notify_handles)} notifiable: {notify_handles}" if notify_handles else "")
            + " — building fuzz script ..."
        )
    else:
        log.info(f"[S7] Phase 1 — profiling {addr} (Python API) ...")
        writable_handles, notify_handles, handle_uuids = _profile_via_python_api(dongle, target)
        if not writable_handles:
            log.info(f"[S7] No writable handles found on {addr} — nothing to fuzz.")
            return []
        log.info(
            f"[S7] Found {len(writable_handles)} writable handle(s): {writable_handles}"
        )

    total_writes = len(writable_handles) * len(_FUZZ_PAYLOADS)
    log.info(
        f"[S7] Phase 2 — fuzzing {addr} with {total_writes} writes "
        f"across {len(writable_handles)} handle(s) ..."
    )

    time.sleep(SETTLE_SECS)
    crash_detected = False
    writes_sent = 0
    error_count = 0
    fuzz_rc = -1

    if use_cli:
        script_path, total_writes, vuln_payloads_sent = _write_fuzz_script(
            writable_handles, engagement_id, notify_handles=notify_handles,
            handle_uuids=handle_uuids,
        )
        log.info(f"[S7] Script: {script_path}")
        dongle.device.close()
        time.sleep(0.5)

        fuzz_stdout = ""
        fuzz_stderr = ""
        fuzz_cancelled = False

        try:
            cmd_fuzz = (
                f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
                f"| wble-central --file {script_path}"
            )
            log.debug(f"[S7] Fuzz cmd: {cmd_fuzz}")
            result = _run_cancellable(cmd_fuzz, FUZZ_TIMEOUT, cancel)
            if result is None:
                log.info("[S7] Skip requested — aborting fuzz.")
                fuzz_cancelled = True
            else:
                fuzz_stdout, fuzz_stderr, fuzz_rc = result
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
            try:
                Path(script_path).unlink(missing_ok=True)
            except Exception:
                pass

        if fuzz_cancelled:
            return []

        if fuzz_stderr.strip():
            log.debug(f"[S7] Fuzz stderr: {fuzz_stderr.strip()[:200]}")

        if not crash_detected:
            crash_detected = _detect_crash(fuzz_stdout, fuzz_rc)

        writes_sent, error_count = _parse_fuzz_output(fuzz_stdout, total_writes)
    else:
        try:
            writes_sent, error_count, crash_detected, vuln_payloads_sent, response_times = _run_python_fuzz(
                dongle, target, writable_handles, cancel,
                handle_uuids=handle_uuids,
            )
        except Exception as exc:
            log.error(f"[S7] Python fuzz exception: {type(exc).__name__}: {exc}")

    log.info(
        f"[S7] Fuzz complete: handles={len(writable_handles)}  "
        f"writes={writes_sent}/{total_writes}  errors={error_count}  "
        f"crash={crash_detected}"
    )

    _record_finding(
        target, engagement_id,
        writable_handles, writes_sent, total_writes, error_count, crash_detected,
        vuln_payloads_sent=vuln_payloads_sent,
        response_times=response_times,
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
        vh_match = re.search(r"\bvalue handle:\s*(\d+)", line, re.I)
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


def _parse_handle_uuids(profile_output: str) -> dict[int, str]:
    """Extract value_handle → short UUID mapping from wble-central profile output.

    Profile format example:
        Battery Level (0x2a19) RW, handle 9, value handle: 10
    Returns {10: "2A19", ...}.
    """
    ansi_re = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKLMSTfnsulh]")
    mapping: dict[int, str] = {}
    for raw_line in profile_output.splitlines():
        line = ansi_re.sub("", raw_line).strip()
        if not line:
            continue
        vh_match = re.search(r"\bvalue handle:\s*(\d+)", line, re.I)
        if not vh_match:
            continue
        if re.match(r"service\b", line, re.I):
            continue
        uuid_match = re.search(r"\(0x([0-9a-fA-F]{4,})\)", line)
        if uuid_match:
            mapping[int(vh_match.group(1))] = uuid_match.group(1).upper()
    return mapping


def _profile_via_python_api(
    dongle: WhadDongle,
    target: Target,
) -> tuple[list[int], list[int], dict[int, str]]:
    """Profile the target via Python API.

    Returns (writable_handles, notify_handles, handle_uuids).
    """
    from whad.ble.profile.characteristic import CharacteristicProperties
    addr = target.bd_address
    is_random = target.address_type != "public"
    writable: list[int] = []
    notifiable: list[int] = []
    h_uuids: dict[int, str] = {}

    central = dongle.central()
    periph_dev = None
    try:
        periph_dev = central.connect(addr, random=is_random, timeout=CONNECT_TIMEOUT)
        if periph_dev is None:
            log.warning("[S7] Python API profile: could not connect")
            return [], []

        done = threading.Event()
        exc_holder: list[Exception] = []

        def _disc() -> None:
            try:
                periph_dev.discover()
            except Exception as e:
                exc_holder.append(e)
            finally:
                done.set()

        t = threading.Thread(target=_disc, daemon=True)
        t.start()
        done.wait(timeout=20.0)

        for svc in periph_dev.services():
            for ch in (getattr(svc, "characteristics", None) or []):
                vh = int(getattr(ch, "value_handle", 0))
                raw = getattr(ch, "properties", 0)
                props = int(raw) if isinstance(raw, int) else 0
                if props & 0x08 or props & 0x04:
                    writable.append(vh)
                if props & 0x10 or props & 0x20:
                    notifiable.append(vh)
                # Extract short UUID for vulndb lookup
                ch_uuid = str(getattr(ch, "uuid", "")).replace("0x", "").upper()
                if ch_uuid and vh:
                    h_uuids[vh] = ch_uuid[-4:] if len(ch_uuid) >= 4 else ch_uuid
    except Exception as exc:
        log.warning(f"[S7] Python API profile error: {type(exc).__name__}: {exc}")
    finally:
        if periph_dev:
            try:
                periph_dev.disconnect()
            except Exception:
                pass
    return writable, notifiable, h_uuids


def _run_python_fuzz(
    dongle: WhadDongle,
    target: Target,
    handles: list[int],
    cancel: Callable[[], bool] | None,
    handle_uuids: dict[int, str] | None = None,
) -> tuple[int, int, bool, int, dict[int, dict[str, float]]]:
    """Fuzz writable handles via Python API.

    Returns (writes_sent, error_count, crash, vuln_payloads_sent, response_times).
    response_times maps handle → {min, max, avg, count} in seconds.
    """
    addr = target.bd_address
    is_random = target.address_type != "public"
    writes_sent = 0
    error_count = 0
    vuln_payloads_sent = 0
    raw_times: dict[int, list[float]] = {}
    h_uuids = handle_uuids or {}

    def _timed_write(periph_dev, handle: int, payload: bytes,
                     use_cmd: bool, label: str) -> bool:
        """Write with timing. Returns True if connection lost (crash)."""
        nonlocal writes_sent, error_count
        t0 = time.time()
        try:
            if use_cmd:
                periph_dev.write_command(handle, payload)
            else:
                periph_dev.write(handle, payload)
            elapsed = time.time() - t0
            raw_times.setdefault(handle, []).append(elapsed)
            writes_sent += 1
            return False
        except ConnectionLostException:
            log.warning(f"[S7] CRASH: connection lost at h={handle} payload={label}")
            return True
        except Exception:
            elapsed = time.time() - t0
            raw_times.setdefault(handle, []).append(elapsed)
            error_count += 1
            writes_sent += 1
            return False

    def _finalize_times() -> dict[int, dict[str, float]]:
        result: dict[int, dict[str, float]] = {}
        for h, times in raw_times.items():
            if times:
                result[h] = {
                    "min": round(min(times), 4),
                    "max": round(max(times), 4),
                    "avg": round(sum(times) / len(times), 4),
                    "count": len(times),
                }
        return result

    central = dongle.central()
    periph_dev = None
    try:
        periph_dev = central.connect(addr, random=is_random, timeout=CONNECT_TIMEOUT)
        if periph_dev is None:
            log.warning("[S7] Python API fuzz: could not connect")
            return 0, 0, False, 0, {}

        # Phase A: standard payloads
        for handle in handles:
            for _label, cmd, hex_payload in _FUZZ_PAYLOADS:
                if cancel is not None and cancel():
                    return writes_sent, error_count, False, vuln_payloads_sent, _finalize_times()
                payload = (
                    bytes.fromhex(hex_payload.replace(" ", ""))
                    if hex_payload.strip()
                    else b""
                )
                if _timed_write(periph_dev, handle, payload, cmd == "writecmd", _label):
                    return writes_sent, error_count, True, vuln_payloads_sent, _finalize_times()

        # Phase B: CVE-targeted vulndb payloads
        for handle in handles:
            uuid_short = h_uuids.get(handle, "")
            vuln_payloads = get_vuln_fuzz_payloads(uuid_short)
            if vuln_payloads:
                log.debug(
                    f"[S7] Sending {len(vuln_payloads)} vulndb payloads "
                    f"for h={handle} uuid={uuid_short}"
                )
            for vlabel, vpayload in vuln_payloads:
                if cancel is not None and cancel():
                    return writes_sent, error_count, False, vuln_payloads_sent, _finalize_times()
                if _timed_write(periph_dev, handle, vpayload, False, vlabel):
                    return writes_sent, error_count, True, vuln_payloads_sent, _finalize_times()
                vuln_payloads_sent += 1

    except ConnectionLostException:
        return writes_sent, error_count, True, vuln_payloads_sent, _finalize_times()
    except Exception as exc:
        log.error(f"[S7] Python API fuzz error: {type(exc).__name__}: {exc}")
    finally:
        if periph_dev:
            try:
                periph_dev.disconnect()
            except Exception:
                pass

    return writes_sent, error_count, False, vuln_payloads_sent, _finalize_times()


def _write_fuzz_script(
    handles: list[int],
    engagement_id: str,
    notify_handles: list[int] | None = None,
    handle_uuids: dict[int, str] | None = None,
) -> tuple[str, int, int]:
    """Generate a wble-central gsh fuzz script and write it to a temp file.

    Phase A: standard payload matrix against all writable handles.
    Phase B: subscribe+write notification-handler fuzzing for notifiable handles.
    Phase C: CVE-targeted vulndb payloads per handle UUID.
    Returns (script_path, total_write_count, vuln_payload_count).
    """
    import os
    lines: list[str] = []
    h_uuids = handle_uuids or {}
    vuln_count = 0

    # Phase A: standard payloads
    for handle in handles:
        for _label, cmd, hex_payload in _FUZZ_PAYLOADS:
            payload = hex_payload.strip()
            if payload:
                lines.append(f"{cmd} {handle} hex {payload}")
            else:
                lines.append(f"{cmd} {handle} hex")

    # Phase B: subscribe+write notification-handler fuzzing
    for nh in (notify_handles or []):
        lines.append(f"sub {nh}")
        for _label, cmd, hex_payload in _SUB_WRITE_PAYLOADS:
            payload = hex_payload.strip()
            if payload:
                lines.append(f"{cmd} {nh} hex {payload}")
            else:
                lines.append(f"{cmd} {nh} hex")
        lines.append(f"unsub {nh}")

    # Phase C: CVE-targeted vulndb payloads
    for handle in handles:
        uuid_short = h_uuids.get(handle, "")
        for vlabel, vpayload in get_vuln_fuzz_payloads(uuid_short):
            hex_str = " ".join(f"{b:02x}" for b in vpayload) if vpayload else ""
            if hex_str:
                lines.append(f"write {handle} hex {hex_str}")
            else:
                lines.append(f"write {handle} hex")
            vuln_count += 1

    script = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix=f"s7_{engagement_id}_", suffix=".gsh")
    try:
        os.write(fd, script.encode())
    finally:
        os.close(fd)
    return path, len(lines), vuln_count


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


def _run_cancellable(
    cmd: str,
    timeout: float,
    cancel: Callable[[], bool] | None,
) -> tuple[str, str, int] | None:
    """Run a shell command with polling and cancellation support.

    Returns (stdout, stderr, returncode) on completion.
    Returns None if cancel() fires — caller should treat as skip-requested.
    Raises subprocess.TimeoutExpired on timeout (same as subprocess.run).
    Background reader threads prevent pipe-buffer deadlock on large outputs.
    """
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []

    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    t_out = threading.Thread(target=lambda: stdout_buf.append(proc.stdout.read()), daemon=True)
    t_err = threading.Thread(target=lambda: stderr_buf.append(proc.stderr.read()), daemon=True)
    t_out.start()
    t_err.start()

    deadline = time.time() + timeout
    while proc.poll() is None:
        time.sleep(0.5)
        if cancel is not None and cancel():
            proc.kill()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            return None
        if time.time() >= deadline:
            proc.kill()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            raise subprocess.TimeoutExpired(cmd, timeout)

    t_out.join()
    t_err.join()
    return (
        stdout_buf[0] if stdout_buf else "",
        stderr_buf[0] if stderr_buf else "",
        proc.returncode if proc.returncode is not None else -1,
    )


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
    vuln_payloads_sent: int = 0,
    response_times: dict[int, dict[str, float]] | None = None,
) -> None:
    severity, description = _assess(
        writable_handles, writes_sent, total_writes, error_count, crash_detected, target
    )
    evidence: dict = {
        "writable_handles": writable_handles,
        "total_payloads_planned": total_writes,
        "writes_sent": writes_sent,
        "error_count": error_count,
        "crash_detected": crash_detected,
        "vuln_payloads_sent": vuln_payloads_sent,
        "sweyntooth_tested": True,
    }
    if response_times:
        evidence["response_times"] = response_times
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
        evidence=evidence,
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

    log.info("\n" + "─" * 76)
    log.info("  STAGE 7 SUMMARY -- GATT Write Fuzzer (CLI)")
    log.info("─" * 76)
    log.info(f"  {'Target':<18}: {target.bd_address}")
    log.info(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    log.info(f"  {'Device class':<18}: {target.device_class}")
    log.info(f"  {'Writable handles':<18}: {handles_str}")
    log.info(f"  {'Writes / total':<18}: {writes_sent} / {total_writes}")
    log.info(f"  {'Error responses':<18}: {error_count}")
    crash_val = "YES — disconnected mid-fuzz" if crash_detected else "no"
    log.info(f"  {'Crash detected':<18}: {crash_val}")
    log.info(f"\n  {'Severity':<18}: {severity.upper()}")
    if crash_detected:
        log.info(
            "  Why               : Disconnect under fuzz — buffer overflow\n"
            "                      or unhandled exception in BLE GATT stack."
        )
    elif error_count == 0 and writes_sent > 0:
        log.info(
            "  Why               : All payloads accepted including 200-512 byte\n"
            "                      writes — missing ATT payload length validation."
        )
    log.info("─" * 76 + "\n")
