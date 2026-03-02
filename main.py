import argparse
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.dongle import WhadDongle
from core.db import init_db, upsert_engagement
from core.logger import get_logger, stage_banner, active_gate, select_targets
import config

log = get_logger("main")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="BLE Red Team Framework — butterfly-ble-redteam"
    )
    p.add_argument(
        "--engagement",
        "-e",
        default=None,
        help="Engagement ID (auto-generated if omitted)",
    )
    p.add_argument(
        "--name",
        "-n",
        default="unnamed",
        help="Engagement name for reporting",
    )
    p.add_argument(
        "--location",
        "-l",
        default="",
        help="Physical location being assessed",
    )
    p.add_argument(
        "--interface",
        "-i",
        default=config.INTERFACE,
        help=f"WHAD interface (default: {config.INTERFACE})",
    )
    p.add_argument(
        "--scan-duration",
        type=int,
        default=config.SCAN_DURATION,
        help=f"Stage 1 scan duration in seconds (default: {config.SCAN_DURATION})",
    )
    p.add_argument(
        "--stages",
        default="auto",
        help=(
            "Comma-separated list of stages to run, or 'auto' to select based on "
            "dongle capabilities (default: auto). "
            "1=BLE scan, 2=conn intel, 3=clone, 4=jam, 5=GATT enum, 7=fuzz, "
            "8=PoC, 9=inject (opt-in), 10=Unifying, 11=ZigBee, 12=PHY, "
            "13=SMP pairing, 14=ESB, 15=LoRaWAN. "
            "Stages 6 (proxy, needs 2 interfaces) and 9 (injection) always require explicit opt-in."
        ),
    )
    p.add_argument(
        "--no-gate",
        action="store_true",
        help="Disable active-stage confirmation prompts (dangerous)",
    )
    p.add_argument(
        "--target",
        action="append",
        default=[],
        dest="targets",
        metavar="BD_ADDR",
        help="Focus on specific BD address (can repeat)",
    )
    p.add_argument(
        "--proxy-interface",
        default=config.PROXY_INTERFACE,
        help=f"Second interface for Stage 6 wble-proxy (default: {config.PROXY_INTERFACE})",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    return p.parse_args()


def _apply_args(args: argparse.Namespace) -> None:
    import logging as _logging
    config.INTERFACE = args.interface
    config.SCAN_DURATION = args.scan_duration
    if args.no_gate:
        config.ACTIVE_GATE = False
    if args.targets:
        config.TARGET_FILTER = [a.upper() for a in args.targets]
    config.PROXY_INTERFACE = args.proxy_interface
    if args.debug:
        # Lower all already-created named loggers (created at import time)
        for logger in _logging.Logger.manager.loggerDict.values():
            if isinstance(logger, _logging.Logger):
                logger.setLevel(_logging.DEBUG)
                for h in logger.handlers:
                    h.setLevel(_logging.DEBUG)
        _logging.root.setLevel(_logging.DEBUG)


def _banner(eng_id: str, name: str, location: str) -> None:
    line = "=" * 60
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{line}")
    print("  BLE RED TEAM FRAMEWORK")
    print(f"  Engagement : {name} ({eng_id})")
    print(f"  Location   : {location or 'unspecified'}")
    print(f"  Interface  : {config.INTERFACE}")
    print(f"  Proxy iface: {config.PROXY_INTERFACE}")
    print(f"  Started    : {ts}")
    print(f"{line}\n")


def _caps_banner(dongle: WhadDongle) -> None:
    line = "─" * 49
    print(f"\n  DONGLE CAPABILITIES")
    print(f"  {line}")
    for l in dongle.caps.summary_lines():
        print(l)
    print(f"  {line}\n")


def main() -> None:
    args = _parse_args()
    _apply_args(args)

    eng_id = args.engagement or uuid.uuid4().hex[:12]
    config.PCAP_DIR.mkdir(parents=True, exist_ok=True)
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    init_db()
    upsert_engagement(eng_id, args.name, args.location)

    _banner(eng_id, args.name, args.location)

    _stages_arg = args.stages.strip().lower()

    dongle = WhadDongle.create(config.INTERFACE)
    _caps_banner(dongle)

    if _stages_arg == "auto":
        stages_requested = _stages_from_caps(dongle.caps)
        _print_auto_stages(stages_requested)
    else:
        stages_requested = {
            int(s.strip()) for s in args.stages.split(",") if s.strip().isdigit()
        }
        _warn_unsupported_stages(stages_requested, dongle.caps)

    targets = []
    connections = []
    # addr → writable value_handles found by S5 (used by S7 to skip re-profile)
    gatt_writable: dict[str, list[int]] = {}
    # addr → full GATT profile from S5 (used by S8 for semantic PoC)
    gatt_profiles: dict[str, list[dict]] = {}

    try:
        if 1 in stages_requested:
            from stages import s1_map

            stage_banner(1, "Environment Mapping", passive=True)
            targets = s1_map.run(dongle, eng_id)
            log.info(
                f"Stage 1 complete: {len(targets)} targets, "
                f"{sum(1 for t in targets if t.connectable)} connectable"
            )

        if 2 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                from stages import s2_intel

                stage_banner(2, "Connection Intelligence", passive=True)
                connections, s2_gatt = s2_intel.run(dongle, connectable, eng_id)
                for addr, profile in s2_gatt.items():
                    if addr not in gatt_profiles:
                        gatt_profiles[addr] = profile
                        log.info(
                            f"[S2] Passive GATT profile available for {addr}: "
                            f"{len(profile)} char(s)"
                        )
                log.info(
                    f"Stage 2 complete: {len(connections)} connections observed"
                )
            else:
                log.info("Stage 2 skipped: no connectable targets found.")

        if 3 in stages_requested and targets:
            high_value = [
                t
                for t in targets
                if t.connectable and t.risk_score >= 6
            ]
            if high_value:
                stage_banner(3, "Identity Cloning / Rogue Peripheral", passive=False)
                if not config.ACTIVE_GATE or active_gate(
                    3,
                    f"Clone {high_value[0].bd_address} "
                    f"({high_value[0].device_class}, "
                    f"risk={high_value[0].risk_score})",
                ):
                    from stages import s3_clone

                    s3_clone.run(
                        dongle, high_value[0], eng_id,
                        gatt_profiles.get(high_value[0].bd_address),
                    )
            else:
                log.info(
                    "Stage 3 skipped: no high-value connectable targets."
                )

        if 4 in stages_requested and (targets or connections):
            stage_banner(4, "Reactive Jamming PoC", passive=False)
            if connections:
                jam_target = connections[0]
                if not config.ACTIVE_GATE or active_gate(
                    4,
                    "Reactive jamming will disrupt BLE communications. "
                    "Authorized targets only.",
                ):
                    from stages import s4_jam
                    s4_jam.run(dongle, jam_target, eng_id)
            else:
                connectable = [t for t in targets if t.connectable]
                if connectable:
                    jam_picks = select_targets(
                        connectable,
                        prompt="Stage 4 — Pick ONE target to jam",
                        smart_skip_classes={"it_gear"},
                        max_count=1,
                    )
                    if jam_picks:
                        jam_target = jam_picks[0]
                        if not config.ACTIVE_GATE or active_gate(
                            4,
                            f"Reactive jamming will disrupt BLE communications "
                            f"for {jam_target.bd_address} "
                            f"({jam_target.name or jam_target.device_class}). "
                            "Authorized targets only.",
                        ):
                            from stages import s4_jam
                            s4_jam.run(dongle, jam_target, eng_id)
                    else:
                        log.info("Stage 4 skipped by operator.")
                else:
                    log.info("Stage 4 skipped: no connectable targets.")

        if 5 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                stage_banner(
                    5, "Direct Interaction / GATT Enumeration", passive=False
                )
                gatt_picks = select_targets(
                    connectable,
                    prompt="Stage 5 — Select targets for GATT enumeration",
                    default_all=False,
                    smart_skip_classes={"it_gear"},
                )
                if gatt_picks:
                    if not config.ACTIVE_GATE or active_gate(
                        5,
                        f"Will connect to {len(gatt_picks)} device(s) "
                        "and enumerate GATT profiles.",
                    ):
                        from stages import s5_interact
                        for t in gatt_picks:
                            handles, profile = s5_interact.run(dongle, t, eng_id)
                            if handles:
                                gatt_writable[t.bd_address] = handles
                            if profile:
                                gatt_profiles[t.bd_address] = profile
                else:
                    log.info("Stage 5 skipped by operator.")
            else:
                log.info("Stage 5 skipped: no connectable targets.")

        if 6 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                from stages import s6_proxy

                stage_banner(6, "MITM Proxy", passive=False)
                proxy_picks = select_targets(
                    connectable,
                    prompt="Stage 6 — Select target for MITM proxy",
                    default_all=False,
                    smart_skip_classes={"it_gear"},
                    max_count=1,
                )
                if proxy_picks:
                    if len(proxy_picks) > 1:
                        log.warning(
                            "[S6] wble-proxy runs one target at a time; "
                            f"using {proxy_picks[0].bd_address}. "
                            "Rerun with --stages 6 for remaining targets."
                        )
                    if not config.ACTIVE_GATE or active_gate(
                        6,
                        f"MITM proxy against {proxy_picks[0].bd_address} "
                        f"({proxy_picks[0].name or proxy_picks[0].device_class}). "
                        "Requires two RF interfaces. Authorized targets only.",
                    ):
                        s6_proxy.run(dongle, proxy_picks[0], eng_id)
                else:
                    log.info("Stage 6 skipped by operator.")
            else:
                log.info("Stage 6 skipped: no connectable targets.")

        if 7 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                stage_banner(7, "GATT Write Fuzzer", passive=False)

                # If S5 ran and found writable handles, pre-select those targets
                if gatt_writable:
                    s5_fuzz_targets = [
                        t for t in connectable if t.bd_address in gatt_writable
                    ]
                    if s5_fuzz_targets:
                        print(
                            f"\n  Stage 7 — S5 found writable characteristics on "
                            f"{len(s5_fuzz_targets)} device(s):\n"
                        )
                        for t in s5_fuzz_targets:
                            h = gatt_writable[t.bd_address]
                            name = (t.name or "—")[:20]
                            print(
                                f"    {t.bd_address:<20}  "
                                f"{name:<20}  "
                                f"handles={h}"
                            )
                        fuzz_picks = s5_fuzz_targets
                    else:
                        fuzz_picks = select_targets(
                            connectable,
                            prompt="Stage 7 — Select targets for GATT write fuzzing",
                            default_all=False,
                            smart_skip_classes={"it_gear"},
                        )
                else:
                    fuzz_picks = select_targets(
                        connectable,
                        prompt="Stage 7 — Select targets for GATT write fuzzing",
                        default_all=False,
                        smart_skip_classes={"it_gear"},
                    )

                if fuzz_picks:
                    if not config.ACTIVE_GATE or active_gate(
                        7,
                        f"Will write fuzz payloads to {len(fuzz_picks)} device(s). "
                        "Authorized targets only.",
                    ):
                        from stages import s7_fuzz
                        for t in fuzz_picks:
                            found = s7_fuzz.run(
                                dongle, t, eng_id,
                                prepped_handles=gatt_writable.get(t.bd_address),
                            )
                            if found and t.bd_address not in gatt_writable:
                                gatt_writable[t.bd_address] = found
                else:
                    log.info("Stage 7 skipped by operator.")
            else:
                log.info("Stage 7 skipped: no connectable targets.")

        if 8 in stages_requested and targets:
            # S5 full profiles take priority; S7-only targets get self-profiled in S8.
            poc_targets = [
                t for t in targets
                if t.connectable and (
                    t.bd_address in gatt_profiles
                    or t.bd_address in gatt_writable
                )
            ]
            if poc_targets:
                stage_banner(8, "GATT Semantic PoC / Targeted Interaction", passive=False)
                if not config.ACTIVE_GATE or active_gate(
                    8,
                    f"Will perform targeted GATT writes on {len(poc_targets)} device(s): "
                    "device rename, alert trigger, proprietary channel probe. "
                    "Authorized targets only.",
                ):
                    from stages import s8_poc
                    _name_input = input(
                        "  Custom name for 0x2A00 rename [BLE-PoC]: "
                    ).strip()
                    poc_name = _name_input if _name_input else "BLE-PoC"
                    for t in poc_targets:
                        s8_poc.run(
                            dongle, t, eng_id,
                            gatt_profiles.get(t.bd_address, []),
                            poc_name=poc_name,
                        )
            else:
                log.info("Stage 8 skipped: no writable targets identified by S5 or S7.")

        if 9 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                from stages import s9_inject

                stage_banner(9, "Packet Injection / Replay", passive=False)
                inject_picks = select_targets(
                    connectable,
                    prompt="Stage 9 — Select target for injection",
                    default_all=False,
                    max_count=1,
                )
                if inject_picks:
                    mode = _ask_inject_mode()
                    if not config.ACTIVE_GATE or active_gate(
                        9,
                        f"Will inject BLE packets targeting "
                        f"{inject_picks[0].bd_address} "
                        f"({inject_picks[0].name or inject_picks[0].device_class}). "
                        f"Mode: {mode}. Authorized targets only.",
                    ):
                        s9_inject.run(
                            dongle, inject_picks[0], eng_id, connections, mode
                        )
                else:
                    log.info("Stage 9 skipped by operator.")
            else:
                log.info("Stage 9 skipped: no connectable targets.")

        if 10 in stages_requested:
            from stages import s10_unifying

            stage_banner(10, "Logitech Unifying / MouseJack", passive=False)
            uni_mode = _ask_unifying_mode()
            if not config.ACTIVE_GATE or active_gate(
                10,
                f"Will transmit on 2.4 GHz Unifying channels. "
                f"Mode: {uni_mode}. Authorized environments only.",
            ):
                s10_unifying.run(dongle, eng_id, uni_mode)
            else:
                log.info("Stage 10 skipped by operator.")

        if 11 in stages_requested:
            from stages import s11_zigbee

            stage_banner(11, "IEEE 802.15.4 / ZigBee Recon", passive=True)
            s11_zigbee.run(dongle, eng_id)

        if 12 in stages_requested:
            from stages import s12_phy

            stage_banner(12, "PHY / ISM Band Survey", passive=True)
            s12_phy.run(dongle, eng_id)

        if 14 in stages_requested:
            from stages import s14_esb

            stage_banner(14, "ESB Raw Channel Scan", passive=True)
            s14_esb.run(dongle, eng_id)

        if 15 in stages_requested:
            from stages import s15_lorawan

            stage_banner(15, "LoRaWAN Recon", passive=True)
            s15_lorawan.run(dongle, eng_id)

        if 16 in stages_requested:
            from stages import s16_l2cap

            stage_banner(16, "L2CAP CoC (capability gap)", passive=True)
            s16_l2cap.run(dongle, eng_id)

        if 13 in stages_requested and targets:
            pairing_targets = [t for t in targets if t.connectable]
            if pairing_targets:
                stage_banner(13, "SMP Pairing Vulnerability Scan", passive=False)
                if not config.ACTIVE_GATE or active_gate(
                    13,
                    f"Will attempt BLE pairing against {len(pairing_targets)} device(s) "
                    "using 4 pairing modes (LESC/Legacy × Just Works/Bonding). "
                    "Authorized targets only.",
                ):
                    from stages import s13_pairing
                    for idx, t in enumerate(pairing_targets):
                        s13_pairing.run(dongle, t, eng_id)
                        if idx < len(pairing_targets) - 1:
                            time.sleep(3.0)  # dongle recovery between targets
            else:
                log.info("Stage 13 skipped: no connectable targets.")

    except KeyboardInterrupt:
        log.info("Run aborted by user.")
    finally:
        dongle.close()

    from output.markdown_report import generate as gen_md
    from output.json_report import generate as gen_json
    gen_md(eng_id, args.name, args.location)
    gen_json(eng_id, args.name, args.location)

    _emit_summary(eng_id)


def _stages_from_caps(caps) -> set[int]:
    """Return the set of stage numbers supportable by this dongle's capabilities."""
    stages: set[int] = set()
    if caps.can_scan:           stages.add(1)               # passive BLE scan
    if caps.can_sniff:          stages.add(2)               # connection intelligence
    if caps.can_peripheral:     stages.add(3)               # identity clone
    if caps.can_reactive_jam:   stages.add(4)               # reactive jamming
    if caps.can_central:        stages.update({5, 7, 8, 13})  # GATT enum/fuzz/PoC, SMP
    # S6 (MITM proxy) requires a second RF interface — always opt-in
    # S9 (packet injection) is destructive — always opt-in
    if caps.can_unifying:       stages.add(10)              # Logitech Unifying/MouseJack
    if caps.can_zigbee:         stages.add(11)              # ZigBee/802.15.4 recon
    if caps.can_phy:            stages.add(12)              # PHY ISM band survey
    if caps.can_esb:            stages.add(14)              # ESB raw channel scan
    if caps.can_lorawan:        stages.add(15)              # LoRaWAN recon
    return stages


def _print_auto_stages(stages: set[int]) -> None:
    nums = ", ".join(str(s) for s in sorted(stages))
    print(f"  Auto-selected stages : {nums}\n")


def _warn_unsupported_stages(stages: set[int], caps) -> None:
    """Log a warning for each explicitly requested stage the dongle cannot support."""
    _STAGE_CAP: dict[int, tuple[str, str]] = {
        1:  ("can_scan",        "BLE Scanner"),
        2:  ("can_sniff",       "BLE Sniffer"),
        3:  ("can_peripheral",  "BLE Peripheral"),
        4:  ("can_reactive_jam","ReactiveJam"),
        5:  ("can_central",     "BLE Central"),
        6:  ("can_central",     "BLE Central"),
        7:  ("can_central",     "BLE Central"),
        8:  ("can_central",     "BLE Central"),
        9:  ("can_central",     "BLE Central"),
        10: ("can_unifying",    "Unifying CLI tools"),
        11: ("can_zigbee",      "ZigBee module"),
        12: ("can_phy",         "PHY module"),
        13: ("can_central",     "BLE Central"),
        14: ("can_esb",         "ESB module"),
        15: ("can_lorawan",     "LoRaWAN module"),
    }
    for s in sorted(stages):
        if s not in _STAGE_CAP:
            continue
        cap_name, cap_label = _STAGE_CAP[s]
        if not getattr(caps, cap_name, True):
            log.warning(
                f"Stage {s} requires {cap_label} ({cap_name}=False) — "
                "stage will skip itself at runtime."
            )


def _ask_inject_mode() -> str:
    """Prompt operator to select ADV injection or InjectaBLE connection mode."""
    print("\n  Stage 9 — Select injection mode:")
    print("    [A]  ADV injection  — flood/replay target advertisements")
    print("                         (scan DoS / device discovery cache poisoning)")
    print("    [I]  InjectaBLE     — inject PDUs into active BLE connection")
    print("                         (needs S2 connection parameters: AA, CRC, hop)")
    print("                         If no S2 data exists, you will be offered a")
    print("                         live capture before injection proceeds.")
    while True:
        try:
            choice = input("  Select mode [A/I]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "adv"
        if choice in ("A", ""):
            return "adv"
        if choice == "I":
            return "injectable"
        print("  Please enter A or I.")


def _ask_unifying_mode() -> str:
    """Prompt operator to select passive sniff or MouseJack inject mode."""
    print("\n  Stage 10 — Select Unifying mode:")
    print("    [S]  Sniff  — passive scan for Unifying devices,")
    print("                  capture mouse/keyboard events")
    print("    [I]  Inject — MouseJack: synchronise and inject keystrokes")
    print("                  into a vulnerable Unifying receiver")
    while True:
        try:
            choice = input("  Select mode [S/I]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "sniff"
        if choice in ("S", ""):
            return "sniff"
        if choice == "I":
            return "inject"
        print("  Please enter S or I.")


def _emit_summary(eng_id: str) -> None:
    from core.db import get_targets, get_findings, _connect

    targets = get_targets(eng_id)
    findings = get_findings(eng_id)

    with _connect() as conn:
        unique_devices = conn.execute(
            "SELECT COUNT(DISTINCT bd_address) FROM targets"
        ).fetchone()[0]
        total_sightings = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        total_engagements = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]

    print("\n" + "=" * 60)
    print(f"  RUN COMPLETE — engagement {eng_id}")
    print(f"  Targets this run : {len(targets)}")
    print(
        f"  Unique devices   : {unique_devices} "
        f"({total_sightings} sightings across {total_engagements} run(s))"
    )
    print(f"  Findings         : {len(findings)}")

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count:
            print(f"    {sev:<12} {count}")

    if findings:
        print("\n  Finding details:")
        for f in sorted(
            findings,
            key=lambda x: ("critical", "high", "medium", "low", "info").index(
                x["severity"]
            ),
        ):
            desc = f.get("description", "")
            ftype = f["type"][:16]
            prefix = f"    [{f['severity'].upper():<8}]  {f['target_addr']:<20}  {ftype:<16}  "
            term_width = shutil.get_terminal_size(fallback=(120, 24)).columns
            desc_width = max(40, term_width - len(prefix))
            if len(desc) > desc_width:
                lines = [desc[i:i + desc_width] for i in range(0, len(desc), desc_width)]
                print(prefix + ("\n" + " " * len(prefix)).join(lines))
            else:
                print(prefix + desc)

    print(f"\n  Database: {config.DB_PATH}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()