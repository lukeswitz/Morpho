"""
Stage 13 — SMP Pairing Vulnerability Scanner

Connects to each connectable target and walks a pairing matrix from weakest
to strongest. Records which modes the target accepts without user interaction.

Pairing matrix (weakest → strongest):
  1. LESC Just Works       — ECDH, no MITM, no bonding
  2. Legacy Just Works     — no ECDH, no MITM, no bonding
  3. LESC + Bonding        — ECDH, no MITM, stores keys
  4. Legacy + Bonding      — no ECDH, no MITM, stores keys

Any mode accepted without user interaction is a finding. If bonding succeeds,
LTK/IRK/CSRK are captured and stored in finding evidence.
"""

from __future__ import annotations

import json
import threading
import time

from whad.ble.stack.smp.parameters import Pairing
from whad.ble.exceptions import ConnectionLostException, PeripheralNotFound
from whad.exceptions import WhadDeviceTimeout

from core.dongle import WhadDongle
from core.models import Target, Finding
from core.db import insert_finding
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s13_pairing")

# ── Pairing matrix ────────────────────────────────────────────────────────────
# Each entry: (mode_id, human_label, Pairing_instance)
# Ordered weakest → strongest so we stop once we know the target's floor.

_MATRIX: list[tuple[str, str, Pairing]] = [
    (
        "lesc_just_works",
        "LESC Just Works (ECDH, no MITM, no bonding)",
        Pairing(lesc=True,  mitm=False, bonding=False),
    ),
    (
        "legacy_just_works",
        "Legacy Just Works (no ECDH, no MITM, no bonding)",
        Pairing(lesc=False, mitm=False, bonding=False),
    ),
    (
        "lesc_bonding",
        "LESC + Bonding (ECDH, no MITM, stores keys)",
        Pairing(lesc=True,  mitm=False, bonding=True),
    ),
    (
        "legacy_bonding",
        "Legacy + Bonding (no ECDH, no MITM, stores keys)",
        Pairing(lesc=False, mitm=False, bonding=True),
    ),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pairing_with_timeout(periph_dev, pairing_cfg, timeout: float, mode_id: str) -> bool:
    """Run periph_dev.pairing() in a daemon thread with a hard timeout.

    WHAD's pairing() loops forever if the target never responds. This wrapper
    enforces a deadline and returns False if the thread doesn't finish in time.
    """
    result: list[bool] = [False]
    done = threading.Event()

    def _pair():
        try:
            result[0] = periph_dev.pairing(pairing=pairing_cfg)
        except Exception as exc:
            log.debug(f"[S13] {mode_id} pairing exception: {type(exc).__name__}: {exc}")
        finally:
            done.set()

    t = threading.Thread(target=_pair, daemon=True)
    t.start()
    finished = done.wait(timeout=timeout)
    if not finished:
        log.debug(f"[S13] {mode_id} pairing timed out after {timeout}s")
    return result[0]


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
) -> None:
    addr      = target.bd_address
    is_random = target.address_type != "public"

    log.info(f"[S13] Pairing scan: {addr} ({target.name or 'unnamed'})")

    accepted_modes: list[dict] = []
    keys_captured:  list[dict] = []

    for mode_id, mode_label, pairing_cfg in _MATRIX:
        log.info(f"[S13] Trying {mode_label} ...")

        try:
            central = dongle.central()
        except WhadDeviceTimeout:
            log.warning(
                f"[S13] Dongle stopped responding — aborting pairing scan for {addr}"
            )
            break

        _pcap      = pcap_path(engagement_id, 13, addr)
        _monitor   = attach_monitor(central, _pcap)
        periph_dev = None

        try:
            periph_dev = central.connect(
                addr, random=is_random, timeout=config.S13_CONNECT_TIMEOUT
            )
            if periph_dev is None:
                log.warning(f"[S13] Could not connect to {addr} — skipping {mode_id}")
                continue

            success = _pairing_with_timeout(
                periph_dev, pairing_cfg, config.S13_PAIRING_TIMEOUT, mode_id
            )

            if success:
                log.info(f"[S13] {mode_id}: ACCEPTED by target")
                accepted_modes.append({"mode": mode_id, "label": mode_label})

                if pairing_cfg.bonding:
                    keys = _extract_keys(periph_dev)
                    if keys:
                        keys["mode"] = mode_id
                        keys_captured.append(keys)
                        captured = [k for k in keys if k != "mode"]
                        log.info(f"[S13] Keys captured: {', '.join(captured)}")
            else:
                log.info(f"[S13] {mode_id}: rejected or failed")

        except (ConnectionLostException, PeripheralNotFound):
            log.warning(f"[S13] Connection lost during {mode_id}")
        except WhadDeviceTimeout:
            log.warning(f"[S13] Dongle timeout during {mode_id} — stopping scan.")
            break
        except Exception as exc:
            log.warning(f"[S13] {mode_id} error: {type(exc).__name__}: {exc}")
        finally:
            if periph_dev is not None:
                try:
                    periph_dev.disconnect()
                except Exception:
                    pass
            detach_monitor(_monitor)

        time.sleep(1.0)   # settle between attempts

    _record_findings(target, engagement_id, accepted_modes, keys_captured)
    _print_summary(target, accepted_modes, keys_captured)


# ── Key extraction ────────────────────────────────────────────────────────────

def _extract_keys(periph_dev) -> dict:
    """Pull LTK/IRK/CSRK from the SMP security database after bonding."""
    keys: dict = {}
    try:
        smp = periph_dev._PeripheralDevice__smp
        db_json = json.loads(smp.security_database.to_json())
        if db_json:
            entry = db_json[-1]   # most recently added entry
            if "ltk"  in entry:
                keys["ltk"]      = entry["ltk"]
                keys["ltk_rand"] = entry.get("rand", "")
                keys["ltk_ediv"] = entry.get("ediv", 0)
            if "irk"  in entry:
                keys["irk"]  = entry["irk"]
            if "csrk" in entry:
                keys["csrk"] = entry["csrk"]
    except Exception as exc:
        log.debug(f"[S13] Key extraction failed: {exc}")
    return keys


# ── Findings ──────────────────────────────────────────────────────────────────

def _record_findings(
    target: Target,
    engagement_id: str,
    accepted_modes: list[dict],
    keys_captured: list[dict],
) -> None:
    if not accepted_modes:
        return

    has_legacy = any("legacy" in m["mode"] for m in accepted_modes)
    severity   = "critical" if has_legacy else "high"
    mode_names = "; ".join(m["label"] for m in accepted_modes)
    key_note   = (
        f" Bonding keys captured for {len(keys_captured)} mode(s)."
        if keys_captured else ""
    )

    insert_finding(Finding(
        type="pairing_no_mitm",
        severity=severity,
        target_addr=target.bd_address,
        description=(
            f"Target {target.bd_address} ({target.name or 'unnamed'}) accepted "
            f"BLE pairing without MITM protection: {mode_names}.{key_note}"
        ),
        remediation=(
            "Require MITM protection and LE Secure Connections (ECDH) for all "
            "pairing modes. Reject legacy pairing requests. Implement bonding "
            "with mutual authentication to prevent identity spoofing."
        ),
        evidence={
            "accepted_modes": accepted_modes,
            "keys_captured":  keys_captured,
        },
        pcap_path=str(pcap_path(engagement_id, 13, target.bd_address)),
        engagement_id=engagement_id,
    ))
    log.info(
        f"FINDING [{severity}] pairing_no_mitm: {target.bd_address} — "
        f"{len(accepted_modes)} mode(s) accepted"
    )

    if keys_captured:
        insert_finding(Finding(
            type="pairing_keys_captured",
            severity="critical",
            target_addr=target.bd_address,
            description=(
                f"BLE bonding succeeded without authentication on "
                f"{target.bd_address} ({target.name or 'unnamed'}). "
                f"Session keys (LTK/IRK/CSRK) captured."
            ),
            remediation=(
                "Require MITM-protected bonding (Numeric Comparison or Passkey "
                "Entry). Rotate long-term keys after any unauthenticated pairing "
                "attempt. Implement bonding deletion policies for untrusted peers."
            ),
            evidence={"keys": keys_captured},
            pcap_path=str(pcap_path(engagement_id, 13, target.bd_address)),
            engagement_id=engagement_id,
        ))
        log.info(
            f"FINDING [critical] pairing_keys_captured: {target.bd_address} — "
            "LTK/IRK/CSRK captured"
        )

    legacy_modes = [m for m in accepted_modes if "legacy" in m["mode"]]
    if legacy_modes:
        insert_finding(Finding(
            type="pairing_legacy_accepted",
            severity="critical",
            target_addr=target.bd_address,
            description=(
                f"Target {target.bd_address} ({target.name or 'unnamed'}) accepted "
                f"Legacy (non-ECDH) BLE pairing. "
                f"{len(legacy_modes)} legacy mode(s) accepted: "
                f"{'; '.join(m['label'] for m in legacy_modes)}. "
                "Legacy pairing lacks elliptic-curve Diffie-Hellman and is vulnerable "
                "to passive eavesdropping and ECDH downgrade attacks."
            ),
            remediation=(
                "Reject all Legacy pairing requests at the firmware level. "
                "Enforce LE Secure Connections Only mode (SMP security level 4). "
                "Upgrade device firmware to require LESC for all pairings."
            ),
            evidence={
                "legacy_modes_accepted": legacy_modes,
                "ecdh_downgrade_risk": True,
            },
            pcap_path=str(pcap_path(engagement_id, 13, target.bd_address)),
            engagement_id=engagement_id,
        ))
        log.info(
            f"FINDING [critical] pairing_legacy_accepted: {target.bd_address} — "
            f"ECDH downgrade confirmed ({len(legacy_modes)} legacy mode(s))"
        )


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(
    target: Target,
    accepted_modes: list[dict],
    keys_captured: list[dict],
) -> None:
    print("\n" + "─" * 76)
    print("  STAGE 13 SUMMARY -- SMP Pairing Vulnerability Scan")
    print("─" * 76)
    print(f"  {'Target':<18}: {target.bd_address}")
    print(f"  {'Name':<18}: {target.name or '(unnamed)'}")
    print(f"  {'Modes tried':<18}: {len(_MATRIX)}")
    print(f"  {'Modes accepted':<18}: {len(accepted_modes)}")

    if accepted_modes:
        print()
        print("  Accepted pairing modes (no MITM required):")
        for m in accepted_modes:
            print(f"    • {m['label']}")

    if keys_captured:
        print()
        print("  Captured bonding keys:")
        for k in keys_captured:
            mode  = k.get("mode", "?")
            parts = []
            if "ltk"  in k: parts.append(f"LTK={k['ltk'][:16]}...")
            if "irk"  in k: parts.append(f"IRK={k['irk'][:16]}...")
            if "csrk" in k: parts.append(f"CSRK={k['csrk'][:16]}...")
            print(f"    [{mode}] {', '.join(parts)}")

    if not accepted_modes:
        print("  Result: target rejected all unauthenticated pairing modes.")

    print("─" * 76 + "\n")
