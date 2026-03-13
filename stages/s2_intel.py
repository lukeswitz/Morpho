from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import time

from scapy.layers.bluetooth4LE import (
    BTLE,
    BTLE_ADV,
    BTLE_CONNECT_REQ,
    BTLE_DATA,
    BTLE_CTRL,
)

from whad.ble.sniffing import ConnectionConfiguration

from core.dongle import WhadDongle
from core.models import Target, Connection, Finding
from core.db import insert_connection, insert_finding
from core.logger import get_logger
from core.pcap import pcap_path, attach_monitor, detach_monitor
import config

log = get_logger("s2_intel")


def _sync_sniffer_on_target(sniffer, target_addr: str) -> bool:
    """Attempt to synchronize sniffer on a specific target address.

    Calls sniffer.wait_new_connection(address) if available. Returns True on
    success. Falls back silently on AttributeError or any runtime error so the
    caller's manual CONNECT_IND loop can take over.

    Args:
        sniffer: WHAD BLE Sniffer connector instance.
        target_addr: BD address string (upper-case, colon-separated).

    Returns:
        True if wait_new_connection() succeeded, False otherwise.
    """
    try:
        sniffer.wait_new_connection(target_addr)
        log.debug(f"[S2] sniffer.wait_new_connection({target_addr!r}) succeeded")
        return True
    except AttributeError:
        log.debug("[S2] sniffer.wait_new_connection() not available — using manual loop")
        return False
    except Exception as exc:
        log.debug(f"[S2] sniffer.wait_new_connection() failed: {exc} — falling back to manual loop")
        return False


def _apply_sniffer_decrypt_keys(sniffer, keys: dict[str, str]) -> None:
    """Feed extracted BLE keys back into the sniffer for live decryption.

    Calls sniffer.add_key(key_bytes) for each LTK/STK-class key found in
    *keys*. Keys are stored as hex strings; each is converted to bytes before
    being passed to the sniffer. Errors per-key are logged at DEBUG so a bad
    key value never aborts the rest.

    Args:
        sniffer: WHAD BLE Sniffer connector instance.
        keys: Dict mapping field names to hex-string values (output of
              _parse_wanalyze_output or _extract_all_keys internal dict).
    """
    _key_fields = ("stk", "ltk", "irk", "csrk")
    for field, hex_val in keys.items():
        if field not in _key_fields:
            continue
        try:
            key_bytes = bytes.fromhex(hex_val)
            sniffer.add_key(key_bytes)
            log.debug(f"[S2] sniffer.add_key({field}={hex_val[:8]}…) OK")
        except (ValueError, AttributeError) as exc:
            log.debug(f"[S2] sniffer.add_key({field}) skipped: {exc}")
        except Exception as exc:
            log.debug(f"[S2] sniffer.add_key({field}) error: {exc}")


def run(
    dongle: WhadDongle,
    targets: list[Target],
    engagement_id: str,
    print_summary: bool = True,
) -> tuple[list[Connection], dict[str, list[dict]]]:
    target_addrs = {t.bd_address.upper() for t in targets}
    connections: list[Connection] = []

    log.info(
        f"Sniffing connection requests for {config.CONN_SNIFF_DURATION}s "
        f"targeting {len(target_addrs)} device(s)"
    )

    sniffer = dongle.sniffer()
    sniffer.configure(advertisements=True)

    # Enable live decryption on the sniffer before start so it auto-decrypts
    # any key material it captures during the session.
    try:
        sniffer.decrypt = True
        log.debug("[S2] sniffer.decrypt = True")
    except AttributeError:
        log.debug("[S2] sniffer.decrypt property not available on this firmware")
    except Exception as exc:
        log.debug(f"[S2] sniffer.decrypt assignment failed: {exc}")

    # Apply BD address filter so the sniffer focuses on known targets.
    if target_addrs:
        try:
            sniffer.filter = list(target_addrs)
            log.debug(f"[S2] sniffer.filter = {list(target_addrs)}")
        except AttributeError:
            log.debug("[S2] sniffer.filter property not available on this firmware")
        except Exception as exc:
            log.debug(f"[S2] sniffer.filter assignment failed: {exc}")

    _monitor = None
    _s2_pcap: Path | None = None
    if targets:
        _s2_pcap = pcap_path(engagement_id, 2, targets[0].bd_address)
        _monitor = attach_monitor(sniffer, _s2_pcap)
    sniffer.start()

    # Log available firmware actions for diagnostics.
    try:
        actions = sniffer.available_actions(action_filter=None)
        log.debug(f"[S2] sniffer.available_actions(): {actions}")
    except AttributeError:
        log.debug("[S2] sniffer.available_actions() not supported on this firmware")
    except Exception as exc:
        log.debug(f"[S2] sniffer.available_actions() error: {exc}")

    start_ts = time()

    try:
        while time() - start_ts < config.CONN_SNIFF_DURATION:
            remaining = config.CONN_SNIFF_DURATION - (time() - start_ts)
            if remaining <= 0:
                break

            msg = dongle.sniff_next(sniffer, timeout=min(remaining, 2.0))
            if msg is None:
                continue

            pkt = msg if isinstance(msg, BTLE) else None
            if pkt is None:
                try:
                    pkt = BTLE(bytes(msg))
                except Exception:
                    continue

            conn_ind = pkt.getlayer(BTLE_CONNECT_REQ)
            if conn_ind is None:
                continue

            init_a = str(conn_ind.InitA).upper()
            adv_a = str(conn_ind.AdvA).upper()

            if config.TARGET_FILTER and adv_a not in config.TARGET_FILTER:
                continue
            if adv_a not in target_addrs and not config.TARGET_FILTER:
                continue

            aa = conn_ind.AA
            crc_init = conn_ind.crc_init
            win_size = conn_ind.win_size
            win_offset = conn_ind.win_offset
            interval = conn_ind.interval
            latency = conn_ind.latency
            timeout_val = conn_ind.timeout
            chM = conn_ind.chM
            hop = conn_ind.hop

            interval_ms = interval * 1.25
            ch_map_hex = f"{chM:010x}"

            log.info(
                f"CONNECT_IND captured: "
                f"{init_a} -> {adv_a}  "
                f"AA=0x{aa:08X}  "
                f"interval={interval_ms:.1f}ms  "
                f"hop={hop}  "
                f"chMap={ch_map_hex}"
            )

            encrypted = False
            legacy_pairing = False
            plaintext_data = False
            data_pcap = None

            try:
                follow_result = _follow_connection(
                    dongle, sniffer, aa, crc_init, chM, hop, interval
                )
                encrypted = follow_result["encrypted"]
                legacy_pairing = follow_result["legacy_pairing"]
                plaintext_data = follow_result["plaintext_data"]
                data_pcap = follow_result.get("pcap_path")
            except Exception as exc:
                log.debug(f"Connection follow failed: {exc}")

            conn = Connection(
                central_addr=init_a,
                peripheral_addr=adv_a,
                access_address=aa,
                crc_init=crc_init,
                interval_ms=interval_ms,
                channel_map=ch_map_hex,
                hop_increment=hop,
                encrypted=encrypted,
                legacy_pairing_observed=legacy_pairing,
                pairing_pcap_path=str(_s2_pcap) if (legacy_pairing and _s2_pcap) else None,
                plaintext_data_captured=plaintext_data,
                data_pcap_path=data_pcap,
                timestamp=datetime.now(timezone.utc),
                engagement_id=engagement_id,
            )
            connections.append(conn)
            insert_connection(conn)
            _evaluate_findings(conn, engagement_id)

            log.info(
                f"Connection logged: encrypted={encrypted}  "
                f"legacy_pairing={legacy_pairing}  "
                f"plaintext_data={plaintext_data}"
            )

    except KeyboardInterrupt:
        log.info("Connection sniffing interrupted by user.")
    finally:
        try:
            detach_monitor(_monitor)
            sniffer.stop()
        except Exception:
            pass

    if print_summary:
        _print_summary(connections)

    if _s2_pcap is not None and _s2_pcap.exists():
        for conn in connections:
            if conn.legacy_pairing_observed:
                _crack_pairing_keys(conn, str(_s2_pcap), engagement_id)

    # Extract all available BLE key material from every observed connection
    if _s2_pcap is not None and _s2_pcap.exists():
        for conn in connections:
            _extract_all_keys(conn, str(_s2_pcap), engagement_id)

    # Attempt passive GATT profile recovery from captured traffic
    passive_gatt: dict[str, list[dict]] = {}
    if _s2_pcap is not None and _s2_pcap.exists():
        seen_addrs = {c.peripheral_addr for c in connections}
        for addr in seen_addrs:
            profile = _passive_gatt_from_pcap(str(_s2_pcap), addr)
            if profile:
                passive_gatt[addr] = profile
                log.info(
                    f"[S2] Passive GATT profile recovered for {addr}: "
                    f"{len(profile)} characteristic(s)"
                )

    return connections, passive_gatt


def _follow_connection(
    dongle: WhadDongle, sniffer, aa, crc_init, ch_map, hop, interval
):
    result = {
        "encrypted": False,
        "legacy_pairing": False,
        "plaintext_data": False,
        "pcap_path": None,
    }

    try:
        conn_cfg = ConnectionConfiguration(
            access_address=aa,
            crc_init=crc_init,
            channel_map=ch_map,
            hop_increment=hop,
            hop_interval=interval,
        )
        sniffer.configure(active_connection=conn_cfg)
    except Exception as exc:
        log.debug(
            f"Device does not support active connection sniffing: {exc}"
        )
        return result

    deadline = time() + 10.0
    pdu_count = 0

    while time() < deadline:
        remaining = deadline - time()
        if remaining <= 0:
            break

        msg = dongle.sniff_next(sniffer, timeout=min(remaining, 1.0))
        if msg is None:
            continue

        pkt = msg if isinstance(msg, BTLE) else None
        if pkt is None:
            try:
                pkt = BTLE(bytes(msg))
            except Exception:
                continue

        data_layer = pkt.getlayer(BTLE_DATA)
        if data_layer is None:
            continue

        pdu_count += 1
        raw = bytes(data_layer.payload)

        if _is_enc_req(raw):
            result["encrypted"] = True
            log.debug("LL_ENC_REQ detected")
        elif _is_smp_pairing_req(raw) and _is_legacy_pairing(raw):
            result["legacy_pairing"] = True
            log.debug("Legacy SMP pairing request detected")

        if not result["encrypted"] and pdu_count > 5:
            result["plaintext_data"] = True

    if pdu_count > 0 and not result["encrypted"]:
        result["plaintext_data"] = True

    return result


def _is_enc_req(payload: bytes) -> bool:
    if len(payload) < 1:
        return False
    return payload[0] == 0x03


def _is_smp_pairing_req(payload: bytes) -> bool:
    if len(payload) < 6:
        return False
    l2cap_cid = int.from_bytes(payload[2:4], "little") if len(payload) >= 4 else 0
    return l2cap_cid == 0x0006


def _is_legacy_pairing(payload: bytes) -> bool:
    if len(payload) < 8:
        return False
    smp_offset = 4
    if smp_offset < len(payload):
        smp_code = payload[smp_offset]
        if smp_code == 0x01 and len(payload) > smp_offset + 4:
            auth_req = payload[smp_offset + 4]
            sc_flag = (auth_req >> 3) & 1
            return sc_flag == 0
    return False


def _evaluate_findings(conn: Connection, engagement_id: str) -> None:
    if not conn.encrypted and conn.plaintext_data_captured:
        finding = Finding(
            type="plaintext_data",
            severity="high",
            target_addr=conn.peripheral_addr,
            description=(
                f"Connection between {conn.central_addr} and "
                f"{conn.peripheral_addr} transmits data without "
                f"encryption. All GATT traffic is observable."
            ),
            remediation=(
                "Enable LE Secure Connections pairing with "
                "MITM protection. Require encrypted link for "
                "all characteristic access."
            ),
            evidence={
                "central_addr": conn.central_addr,
                "peripheral_addr": conn.peripheral_addr,
                "access_address": conn.access_address,
                "interval_ms": conn.interval_ms,
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [high] plaintext_data: "
            f"{conn.peripheral_addr}"
        )

    if conn.legacy_pairing_observed:
        finding = Finding(
            type="weak_pairing",
            severity="critical",
            target_addr=conn.peripheral_addr,
            description=(
                f"Legacy BLE pairing observed between "
                f"{conn.central_addr} and {conn.peripheral_addr}. "
                f"Vulnerable to passive eavesdropping and offline "
                f"key recovery via CrackLE."
            ),
            remediation=(
                "Upgrade to LE Secure Connections (LESC) pairing. "
                "Legacy JustWorks pairing provides zero protection "
                "against passive attackers."
            ),
            evidence={
                "central_addr": conn.central_addr,
                "peripheral_addr": conn.peripheral_addr,
                "access_address": conn.access_address,
                "crackle_command": (
                    f"crackle -i capture.pcap"
                ),
            },
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(
            f"FINDING [critical] weak_pairing: "
            f"{conn.peripheral_addr}"
        )


def _crack_pairing_keys(
    conn: Connection,
    pcap: str,
    engagement_id: str,
) -> None:
    """Run wplay | wanalyze legacy_pairing_cracking and record extracted keys.

    Args:
        conn: Connection with legacy_pairing_observed=True.
        pcap: Path to the PCAP file captured by the S2 sniffer.
        engagement_id: Engagement ID for Finding storage.
    """
    if not shutil.which("wplay") or not shutil.which("wanalyze"):
        log.warning("[S2] wplay/wanalyze not in PATH — skipping key extraction.")
        return

    cmd = f"wplay --flush {pcap} ble | wanalyze --json legacy_pairing_cracking"
    log.info(f"[S2] Running pairing crack: {cmd}")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        keys = _parse_wanalyze_output(result.stdout)
    except subprocess.TimeoutExpired:
        log.warning("[S2] wanalyze timed out after 60s.")
        return
    except Exception as exc:
        log.error(f"[S2] wanalyze error: {type(exc).__name__}: {exc}")
        return

    if not keys:
        log.info("[S2] wanalyze: no keys extracted (capture may be incomplete).")
        return

    log.info(f"[S2] Pairing keys extracted: {list(keys.keys())}")

    finding = Finding(
        type="pairing_key_extracted",
        severity="critical",
        target_addr=conn.peripheral_addr,
        description=(
            f"Legacy BLE pairing between {conn.central_addr} and "
            f"{conn.peripheral_addr} cracked offline. "
            f"Keys extracted: {list(keys.keys())}. "
            "All session traffic can now be decrypted with wsniff -d -k <KEY>."
        ),
        remediation=(
            "Upgrade to LE Secure Connections (LESC). Legacy JustWorks and "
            "passkey entry are vulnerable to offline STK recovery. "
            "Rotate any credentials or sensitive data exchanged over this link."
        ),
        evidence={
            "keys": keys,
            "pcap_path": pcap,
            "central": conn.central_addr,
            "peripheral": conn.peripheral_addr,
            "crack_command": cmd,
        },
        pcap_path=pcap,
        engagement_id=engagement_id,
    )
    insert_finding(finding)
    log.info(
        f"FINDING [critical] pairing_key_extracted: {conn.peripheral_addr}"
    )


def _parse_wanalyze_output(stdout: str) -> dict[str, str]:
    """Extract BLE key fields from wanalyze --json output.

    Returns empty dict if output is not JSON or contains no recognised keys.

    NOTE: Verify key names against a real capture before relying on this.
    Common wanalyze legacy_pairing_cracking fields: stk, ltk, rand, ediv, irk, csrk.
    """
    if not stdout.strip():
        return {}
    try:
        data = json.loads(stdout.strip())
        if not isinstance(data, dict):
            return {}
        key_fields = ("stk", "ltk", "rand", "ediv", "irk", "csrk")
        return {k: str(v) for k, v in data.items() if k in key_fields and v}
    except json.JSONDecodeError as exc:
        log.debug(f"wanalyze non-JSON output: {exc}. Raw: {stdout[:200]}")
        return {}


def _run_wanalyze(pcap: str, module: str, timeout: int = 60) -> dict | list | None:
    """Run wplay --flush <pcap> ble | wanalyze --json <module> and return parsed JSON.

    Returns None on timeout, JSON parse error, or empty output.
    """
    cmd = f"wplay --flush {pcap} ble | wanalyze --json {module}"
    log.debug(f"[S2] wanalyze {module}: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = result.stdout.strip()
        if not raw:
            return None
        log.debug(f"[S2] wanalyze {module} raw: {raw[:300]}")
        return json.loads(raw)
    except subprocess.TimeoutExpired:
        log.warning(f"[S2] wanalyze {module} timed out after {timeout}s.")
        return None
    except json.JSONDecodeError as exc:
        log.debug(f"[S2] wanalyze {module} non-JSON output: {exc}. Raw: {result.stdout[:200]}")
        return None
    except Exception as exc:
        log.error(f"[S2] wanalyze {module} error: {type(exc).__name__}: {exc}")
        return None


_KEY_MODULES: list[tuple[str, str, str, tuple[str, ...]]] = [
    (
        "encrypted_session_initialization",
        "session_keys_extracted",
        "high",
        ("skd_master", "skd_slave", "iv_master", "iv_slave"),
    ),
    (
        "ltk_distribution",
        "ltk_extracted",
        "critical",
        ("ltk", "rand", "ediv"),
    ),
    (
        "irk_distribution",
        "irk_extracted",
        "high",
        ("irk", "bd_addr"),
    ),
    (
        "csrk_distribution",
        "csrk_extracted",
        "high",
        ("csrk",),
    ),
]


def _extract_all_keys(conn: Connection, pcap: str, engagement_id: str) -> None:
    """Run all wanalyze key-extraction modules against a captured PCAP.

    Creates one Finding per module that yields keys. Gate: wplay/wanalyze in PATH.
    """
    if not shutil.which("wplay") or not shutil.which("wanalyze"):
        return

    for module, finding_type, severity, key_fields in _KEY_MODULES:
        data = _run_wanalyze(pcap, module)
        if not isinstance(data, dict):
            continue

        keys = {k: str(v) for k, v in data.items() if k in key_fields and v}
        if not keys:
            log.debug(f"[S2] {module}: no keys in output.")
            continue

        log.info(f"[S2] {module}: extracted {list(keys.keys())}")

        finding = Finding(
            type=finding_type,
            severity=severity,
            target_addr=conn.peripheral_addr,
            description=(
                f"{module.replace('_', ' ').title()} from connection between "
                f"{conn.central_addr} and {conn.peripheral_addr}. "
                f"Extracted: {list(keys.keys())}."
            ),
            remediation=(
                "Use LE Secure Connections (LESC) with bonding. "
                "Legacy key material is derivable from captured traffic. "
                "Rotate any credentials exchanged over this link."
            ),
            evidence={
                "module": module,
                "keys": keys,
                "pcap_path": pcap,
                "central": conn.central_addr,
                "peripheral": conn.peripheral_addr,
            },
            pcap_path=pcap,
            engagement_id=engagement_id,
        )
        insert_finding(finding)
        log.info(f"FINDING [{severity}] {finding_type}: {conn.peripheral_addr}")


def _passive_gatt_from_pcap(pcap: str, addr: str) -> list[dict]:
    """Attempt passive GATT profile recovery from a PCAP via wanalyze profile_discovery.

    Returns a list of characteristic dicts in the same format as S5's gatt_profiles,
    or an empty list if the module produces no results or the format is unrecognised.

    wanalyze profile_discovery JSON schema is not precisely documented — this function
    handles both a flat list of characteristics and a list of service objects with nested
    characteristics. DEBUG log shows raw output for first-run verification.
    """
    if not shutil.which("wplay") or not shutil.which("wanalyze"):
        return []

    data = _run_wanalyze(pcap, "profile_discovery")
    if data is None:
        return []

    chars: list[dict] = []

    def _make_char(obj: dict) -> dict | None:
        uuid = str(obj.get("uuid") or obj.get("UUID") or "")
        if not uuid:
            return None
        handle = int(obj.get("handle", 0))
        value_handle = int(obj.get("value_handle", obj.get("valueHandle", handle)))
        raw_props = obj.get("properties", obj.get("permissions", obj.get("access", [])))
        if isinstance(raw_props, str):
            raw_props = [raw_props]
        properties = [p.lower().replace("-", "_") for p in raw_props]
        return {
            "uuid": uuid.lower(),
            "uuid_name": "",
            "handle": handle,
            "value_handle": value_handle,
            "properties": properties,
            "requires_auth": bool(obj.get("requires_auth", False)),
            "value_text": obj.get("value_text"),
            "value_hex": obj.get("value_hex") or obj.get("value"),
        }

    # Handle: flat list of characteristics
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            # Service object with nested characteristics
            nested = item.get("characteristics") or item.get("chars") or []
            if nested:
                for char_obj in nested:
                    if isinstance(char_obj, dict):
                        c = _make_char(char_obj)
                        if c:
                            chars.append(c)
            else:
                # Flat characteristic object
                c = _make_char(item)
                if c:
                    chars.append(c)
    elif isinstance(data, dict):
        # Might be {addr: [...services...]} or {services: [...]}
        for key in ("characteristics", "chars", "services", addr, addr.lower()):
            nested = data.get(key)
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict):
                        inner = item.get("characteristics") or item.get("chars") or []
                        if inner:
                            for char_obj in inner:
                                c = _make_char(char_obj)
                                if c:
                                    chars.append(c)
                        else:
                            c = _make_char(item)
                            if c:
                                chars.append(c)
                break

    return chars


def _print_summary(connections: list[Connection]) -> None:
    if not connections:
        log.info("S2 complete: 0 connections captured in sniff window")
        return

    log.info(f"S2 complete: {len(connections)} connection(s) captured")
    log.info(f"  {'CENTRAL':<18} {'PERIPHERAL':<18} {'ACCESS ADDR':<12} E L P")
    for c in connections:
        enc  = "Y" if c.encrypted else "N"
        lgcy = "Y" if c.legacy_pairing_observed else "N"
        pln  = "Y" if c.plaintext_data_captured else "N"
        log.info(
            f"  {c.central_addr:<18} {c.peripheral_addr:<18} "
            f"0x{c.access_address:08X}  {enc} {lgcy} {pln}"
        )