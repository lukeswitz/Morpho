import argparse
import shutil
import time
import uuid
from datetime import datetime, timezone

from core.dongle import WhadDongle, HardwareMap, DongleCaps, detect_hardware
from core.db import init_db, upsert_engagement
from core.logger import get_logger, stage_banner, active_gate, select_targets
import config

log = get_logger("main")


_INNER = 62  # inner content width between │/║ border chars


def _lj(s: str, n: int) -> str:
    return s[:n].ljust(n)


_STAGE_GROUPS: list[tuple[str, list[tuple[str, str, str, str]]]] = [
    ("BLE  ·  uart0 / nRF52840", [
        ("01", "environment mapping",      "passive",  ""),
        ("02", "connection intelligence",  "passive",  ""),
        ("03", "identity cloning",         "active",   ""),
        ("04", "reactive jamming",         "active*",  ""),
        ("05", "gatt enum + shell",        "active",   ""),
        ("06", "mitm proxy",               "active*",  ""),
        ("07", "gatt write fuzzer",        "active",   ""),
        ("08", "semantic poc",             "active",   ""),
        ("09", "packet injection",         "active*",  ""),
        ("13", "smp pairing scan",         "active",   ""),
        ("16", "l2cap coc",                "active*",  ""),
        ("20", "ble connection hijacker",  "active*",  ""),
    ]),
    ("802.15.4  ·  uart0 / nRF52840", [
        ("11", "zigbee recon",             "passive",  ""),
        ("12", "phy ism survey (2.4GHz)",  "passive",  ""),
        ("23", "raw 802.15.4 survey",      "passive",  "[+s11]"),
    ]),
    ("ESB / UNIFYING  ·  rfstorm0  →  uart0 fallback", [
        ("10", "unifying / mousejack",     "active",   ""),
        ("14", "esb raw scan",             "passive",  ""),
        ("18", "esb prx/ptx",              "active*",  ""),
        ("19", "unifying python api",      "active*",  ""),
        ("22", "rf4ce recon",              "passive*", ""),
    ]),
    ("LORAWAN  ·  external LoRa radio", [
        ("15", "lorawan recon",            "passive",  ""),
    ]),
    ("SUB-GHz  ·  yardstickone0", [
        ("17", "sub-ghz phy survey",       "passive*", ""),
    ]),
    ("BLUETOOTH CLASSIC  ·  hci / ubertooth0", [
        ("21", "br/edr scout",             "passive",  ""),
    ]),
]


def _render_stage_box(title: str, rows: list[tuple[str, str, str, str]]) -> list[str]:
    title_pad = _INNER - 3 - len(title)
    lines = [f"  ┌─ {title} {'─' * title_pad}┐"]
    for num, name, mode, note in rows:
        # 2+2+2+24+2+8+2+6+14 = 62 = _INNER
        content = f"  {num}  {_lj(name, 24)}  {_lj(mode, 8)}  {_lj(note, 6)}{'':14}"
        lines.append(f"  │{content}│▒")
    lines += [
        f"  └{'─' * _INNER}┘▒",
        f"   {'▒' * (_INNER + 2)}",
        "",
    ]
    return lines


def _help_text() -> str:
    eq = "═" * _INNER
    wave = "~" * 62
    lines: list[str] = [
        "",
        f"  ╔{eq}╗",
        f"  ║{wave}║",
        f"  ║{'':62}║",
        f"  ║{'':17}R  U  B  Y     W  A  V  E  S{'':17}║",
        f"  ║{'':62}║",
        f"  ║{wave}║",
        f"  ║{'':62}║",
        f"  ║   wireless multi-protocol assessment  ·  23 stages{'':11}║",
        f"  ║{'':62}║",
        f"  ╚{eq}╝",
        "",
        "  usage: python main.py -n <name> -l <location> [options]",
        "",
    ]
    for group_title, stages in _STAGE_GROUPS:
        lines += _render_stage_box(group_title, stages)
    lines += [
        "  * opt-in stage  ·  requires --opt-in or explicit --stages N",
        "  [+s11] auto-selected alongside stage 11 (zigbee)",
        "",
        f"  OPTIONS {'─' * 56}",
        "",
        "    -n, --name NAME               engagement name (for reporting)",
        "    -l, --location LOC            physical location",
        "    -e, --engagement ID           engagement id  [auto-generated]",
        "    -i, --interface IFACE         ble interface  [uart0]",
        "        --esb-interface IFACE     esb/unifying  [auto: rfstorm0]",
        "        --phy-interface IFACE     sub-ghz phy  [auto: yardstickone0]",
        "        --ubertooth-interface     passive ble sniffer  [auto]",
        "        --proxy-interface IFACE   second iface for s6 mitm  [auto]",
        "        --stages N,N,...          stage list or 'auto'  [auto]",
        "        --opt-in                  enable all opt-in stages",
        "        --no-gate                 skip active-stage prompts",
        "        --target BD_ADDR          focus address (repeat ×n)",
        "        --scan-duration SECS      s1 ble scan duration  [120]",
        "        --debug                   debug logging",
        "",
        f"  EXAMPLES {'─' * 55}",
        "",
        '    python main.py -n "Lobby" -l "Floor 1"',
        '    python main.py -n "Lobby" -l "Floor 1" --opt-in',
        '    python main.py -n "Lab" --stages 1,5,7,8',
        '    python main.py -n "Lab" --stages 1,2 --no-gate',
        '    python main.py -n "Survey" --stages 14,17 --esb-interface rfstorm0',
        "",
    ]
    return "\n".join(lines) + "\n"


class _StyledParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return _help_text()


def _parse_args() -> argparse.Namespace:
    p = _StyledParser(
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
            "1=BLE scan, 2=conn intel, 3=clone, 5=GATT enum, 7=fuzz, "
            "8=PoC, 10=Unifying (sniff/inject/ducky/mouse), "
            "11=ZigBee, 12=PHY, 13=SMP pairing, 14=ESB passive, 15=LoRaWAN, "
            "21=BR/EDR scout, 23=raw 802.15.4 recon (all protocols). "
            "Opt-in (require --opt-in or explicit --stages N): "
            "4=jam, 6=proxy (needs 2 interfaces), 9=BLE injection, 16=L2CAP CoC, "
            "17=sub-GHz PHY (YardStickOne), 18=ESB PRX/PTX (rfstorm), "
            "19=Unifying Python API (rfstorm), 20=BLE hijacker, "
            "22=RF4CE recon (802.15.4 ch 15/20/25)."
        ),
    )
    p.add_argument(
        "--opt-in",
        action="store_true",
        help=(
            "Enable all opt-in stages (4=jam, 6=MITM proxy, 9=inject, 16=L2CAP, "
            "17=sub-GHz, 18=ESB active, 19=Unifying API, 20=BLE hijack, "
            "22=RF4CE recon). "
            "Each still requires operator confirmation at runtime via active-gate. "
            "Combine with --stages to add opt-in stages to an explicit list."
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
        "--esb-interface",
        default=None,
        metavar="IFACE",
        help="WHAD interface for ESB/Unifying stages 10+14 (default: auto-detect rfstorm0)",
    )
    p.add_argument(
        "--phy-interface",
        default=None,
        metavar="IFACE",
        help="WHAD interface for sub-GHz PHY stage 17 (default: auto-detect yardstickone0)",
    )
    p.add_argument(
        "--ubertooth-interface",
        default=None,
        metavar="IFACE",
        help="WHAD interface for Ubertooth One passive sniffer (default: auto-detect ubertooth0)",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    return p.parse_args()


# Stages that require explicit operator opt-in (never auto-selected).
# Each still prompts via active-gate when it runs.
_OPT_IN_STAGES: frozenset[int] = frozenset({4, 6, 9, 16, 17, 18, 19, 20, 22})


def _apply_args(args: argparse.Namespace) -> None:
    import logging as _logging
    config.INTERFACE = args.interface
    config.SCAN_DURATION = args.scan_duration
    if args.no_gate:
        config.ACTIVE_GATE = False
    if args.targets:
        config.TARGET_FILTER = [a.upper() for a in args.targets]
    config.PROXY_INTERFACE = args.proxy_interface
    if args.esb_interface:
        config.ESB_INTERFACE = args.esb_interface
    if args.phy_interface:
        config.PHY_SUBGHZ_INTERFACE = args.phy_interface
    if args.ubertooth_interface:
        config.UBERTOOTH_INTERFACE = args.ubertooth_interface
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
    print("  ▄▄▄▄  ▄▄ ▄▄ ▄▄▄▄  ▄▄ ▄▄ ██     ██  ▄▄▄  ▄▄ ▄▄ ▄▄▄▄▄  ▄▄▄▄ ")
    print("  ██▄█▄ ██ ██ ██▄██ ▀███▀ ██ ▄█▄ ██ ██▀██ ██▄██ ██▄▄  ███▄▄ ")
    print("  ██ ██ ▀███▀ ██▄█▀   █    ▀██▀██▀  ██▀██  ▀█▀  ██▄▄▄ ▄▄██▀ ")
    print(f"  Engagement : {name} ({eng_id})")
    print(f"  Location   : {location or 'unspecified'}")
    print(f"  Interface  : {config.INTERFACE}")
    print(f"  Proxy iface: {config.PROXY_INTERFACE}")
    print(f"  Started    : {ts}")
    print(f"{line}\n")


def _caps_banner(hw: HardwareMap) -> None:
    line = "─" * 49
    print(f"\n  DONGLE CAPABILITIES")
    for dongle in [hw.ble_dongle, hw.esb_dongle, hw.phy_dongle, hw.ubertooth_dongle]:
        if dongle is None:
            continue
        print(f"  {line}")
        print(f"  [{dongle.interface}]")
        for ln in dongle.caps.summary_lines():
            print(ln)
    print(f"  {line}\n")


def _hardware_banner(hw: HardwareMap) -> None:
    line = "─" * 62
    print(f"\n  HARDWARE DETECTED")
    print(f"  {line}")
    if hw.ble_dongle:
        ble_stages = "BLE stages 1-3, 5, 7-8, 11-13, 15, 21 (opt-in: 4, 6, 9, 16, 20)"
        print(f"  [{hw.ble_dongle.interface}]")
        print(f"    Type     : {hw.ble_dongle.caps.device_type}")
        print(f"    Handles  : {ble_stages}")
    else:
        print(f"  [no BLE device] stages 1-9, 11-13, 15-16 unavailable")
        print(f"    (interface {config.INTERFACE} not found — use --interface to override)")
    if hw.esb_dongle:
        print(f"  [{hw.esb_dongle.interface}]")
        print(f"    Type     : {hw.esb_dongle.caps.device_type}")
        print(f"    Handles  : ESB/Unifying stages 10, 14, 18, 19")
    else:
        fallback = hw.ble_dongle.interface if hw.ble_dongle else "unavailable"
        print(f"  [no ESB device] stages 10, 14 fall back to {fallback}")
    if hw.phy_dongle:
        print(f"  [{hw.phy_dongle.interface}]")
        print(f"    Type     : {hw.phy_dongle.caps.device_type}")
        print(f"    Handles  : sub-GHz PHY stage 17")
    else:
        print(f"  [no sub-GHz PHY device] stage 17 will be skipped if requested")
    if hw.ubertooth_dongle:
        print(f"  [{hw.ubertooth_dongle.interface}]")
        print(f"    Type     : {hw.ubertooth_dongle.caps.device_type}")
        print(f"    Handles  : supplementary passive BLE sniffer (S1/S2 extended range)")
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

    hw = detect_hardware(
        config.INTERFACE,
        config.ESB_INTERFACE,
        config.PHY_SUBGHZ_INTERFACE,
        config.UBERTOOTH_INTERFACE,
    )
    _caps_banner(hw)
    _hardware_banner(hw)

    if _stages_arg == "auto":
        stages_requested = _stages_from_hardware(hw)
        if args.opt_in:
            stages_requested |= _OPT_IN_STAGES
            log.info(f"[--opt-in] Added opt-in stages: {sorted(_OPT_IN_STAGES)}")
        _print_auto_stages(stages_requested)
    else:
        stages_requested = {
            int(s.strip()) for s in args.stages.split(",") if s.strip().isdigit()
        }
        if args.opt_in:
            stages_requested |= _OPT_IN_STAGES
            log.info(f"[--opt-in] Added opt-in stages: {sorted(_OPT_IN_STAGES)}")
        _warn_unsupported_stages(stages_requested, hw)

    targets = []
    connections = []
    # addr → writable value_handles found by S5 (used by S7 to skip re-profile)
    gatt_writable: dict[str, list[int]] = {}
    # addr → full GATT profile from S5 (used by S8 for semantic PoC)
    gatt_profiles: dict[str, list[dict]] = {}

    try:
        if 1 in stages_requested:
            if hw.ble_dongle is None and hw.ubertooth_dongle is None:
                log.warning("[S1] No BLE or Ubertooth device available — scan skipped.")
            else:
                from stages import s1_map

                stage_banner(1, "Environment Mapping", passive=True)
                targets = s1_map.run(hw.ble_dongle, eng_id, ubertooth_dongle=hw.ubertooth_dongle)
                log.info(
                    f"Stage 1 complete: {len(targets)} targets, "
                    f"{sum(1 for t in targets if t.connectable)} connectable"
                )

        if 2 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                from stages import s2_intel

                stage_banner(2, "Connection Intelligence", passive=True)
                connections, s2_gatt = s2_intel.run(hw.ble_dongle, connectable, eng_id)
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
                        hw.ble_dongle, high_value[0], eng_id,
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
                    s4_jam.run(hw.ble_dongle, jam_target, eng_id)
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
                            s4_jam.run(hw.ble_dongle, jam_target, eng_id)
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
                            handles, profile = s5_interact.run(hw.ble_dongle, t, eng_id)
                            if handles:
                                gatt_writable[t.bd_address] = handles
                            if profile:
                                gatt_profiles[t.bd_address] = profile
                            if profile:
                                ans = input(
                                    f"\n  Enter GATT shell for {t.bd_address}? [y/N] "
                                ).strip().lower()
                                if ans == "y":
                                    s5_interact.shell(hw.ble_dongle, t, profile, eng_id)
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
                        s6_proxy.run(hw.ble_dongle, proxy_picks[0], eng_id)
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
                                hw.ble_dongle, t, eng_id,
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
                            hw.ble_dongle, t, eng_id,
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
                            hw.ble_dongle, inject_picks[0], eng_id, connections, mode
                        )
                else:
                    log.info("Stage 9 skipped by operator.")
            else:
                log.info("Stage 9 skipped: no connectable targets.")

        if 10 in stages_requested:
            from stages import s10_unifying

            _esb_dev = hw.esb_dongle or hw.ble_dongle
            if _esb_dev is None:
                log.warning("[S10] No ESB or BLE device available — stage skipped.")
            else:
                _esb_iface = hw.esb_dongle.interface if hw.esb_dongle else config.INTERFACE
                stage_banner(10, "Logitech Unifying / MouseJack", passive=False)
                uni_mode = _ask_unifying_mode()
                if not config.ACTIVE_GATE or active_gate(
                    10,
                    f"Will transmit on 2.4 GHz Unifying channels via {_esb_iface}. "
                    f"Mode: {uni_mode}. Authorized environments only.",
                ):
                    s10_unifying.run(_esb_dev, eng_id, uni_mode, interface=_esb_iface)
                else:
                    log.info("Stage 10 skipped by operator.")

        if 11 in stages_requested:
            if hw.ble_dongle is None:
                log.warning("[S11] No BLE device available — ZigBee stage skipped.")
            else:
                from stages import s11_zigbee

                zigbee_mode = _ask_zigbee_mode()
                if zigbee_mode == "coordinator":
                    stage_banner(11, "IEEE 802.15.4 / ZigBee — Rogue Coordinator", passive=False)
                    if not config.ACTIVE_GATE or active_gate(
                        11,
                        "Will create a rogue ZigBee PAN and open a join window. "
                        "End devices that join without install-code enforcement will "
                        "reveal key material. Authorized environments only.",
                    ):
                        s11_zigbee.run(hw.ble_dongle, eng_id, mode="coordinator")
                    else:
                        log.info("Stage 11 coordinator mode skipped by operator.")
                elif zigbee_mode == "enddevice":
                    stage_banner(11, "IEEE 802.15.4 / ZigBee — EndDevice Join", passive=False)
                    if not config.ACTIVE_GATE or active_gate(
                        11,
                        "Will scan ZigBee networks (passive) then attempt to JOIN the "
                        "most active PAN as an EndDevice. This associates our adapter "
                        "with the real network and may capture group traffic. "
                        "Authorized environments only.",
                    ):
                        s11_zigbee.run(hw.ble_dongle, eng_id, mode="enddevice")
                    else:
                        log.info("Stage 11 enddevice mode skipped by operator.")
                else:
                    stage_banner(11, "IEEE 802.15.4 / ZigBee Recon", passive=True)
                    s11_zigbee.run(hw.ble_dongle, eng_id, mode="passive")

        if 12 in stages_requested:
            if hw.ble_dongle is None:
                log.warning("[S12] No BLE device available — PHY survey skipped.")
            else:
                from stages import s12_phy

                stage_banner(12, "PHY / ISM Band Survey (2.4 GHz)", passive=True)
                s12_phy.run(hw.ble_dongle, eng_id)

        if 14 in stages_requested:
            from stages import s14_esb

            _esb_dev = hw.esb_dongle or hw.ble_dongle
            if _esb_dev is None:
                log.warning("[S14] No ESB or BLE device available — stage skipped.")
            else:
                stage_banner(14, "ESB Raw Channel Scan", passive=True)
                s14_esb.run(_esb_dev, eng_id)

        if 15 in stages_requested:
            if hw.ble_dongle is None:
                log.warning("[S15] No BLE device available — LoRaWAN stage skipped.")
            else:
                from stages import s15_lorawan

                stage_banner(15, "LoRaWAN Recon", passive=True)
                s15_lorawan.run(hw.ble_dongle, eng_id)

        if 16 in stages_requested:
            if hw.ble_dongle is None:
                log.warning("[S16] No BLE device available — L2CAP stage skipped.")
            else:
                from stages import s16_l2cap

                stage_banner(16, "L2CAP CoC (capability gap)", passive=True)
                s16_l2cap.run(hw.ble_dongle, eng_id)

        if 17 in stages_requested:
            from stages import s17_subghz

            stage_banner(17, "sub-GHz PHY Survey (YardStickOne)", passive=True)
            if hw.phy_dongle is None:
                log.warning(
                    "[S17] No YardStickOne detected — sub-GHz PHY sweep skipped. "
                    "Connect a YardStickOne and retry with --phy-interface yardstickone0."
                )
            else:
                s17_subghz.run(hw.phy_dongle, eng_id)

        if 18 in stages_requested:
            from stages import s18_esb_active

            _esb_dev = hw.esb_dongle or hw.ble_dongle
            if _esb_dev is None:
                log.warning("[S18] No ESB or BLE device available — stage skipped.")
            else:
                _esb_iface = hw.esb_dongle.interface if hw.esb_dongle else config.INTERFACE
                stage_banner(18, "ESB PRX/PTX Active Attack (RfStorm)", passive=False)
                if not config.ACTIVE_GATE or active_gate(
                    18,
                    f"Will transmit ESB frames on 2.4 GHz via {_esb_iface}. "
                    "PRX mode intercepts frames addressed to a device. "
                    "PTX mode injects unauthenticated commands. "
                    "Authorized environments only.",
                ):
                    s18_esb_active.run(_esb_dev, eng_id)
                else:
                    log.info("Stage 18 skipped by operator.")

        if 19 in stages_requested:
            from stages import s19_unifying_api

            _esb_dev = hw.esb_dongle or hw.ble_dongle
            if _esb_dev is None:
                log.warning("[S19] No ESB or BLE device available — stage skipped.")
            else:
                _esb_iface = hw.esb_dongle.interface if hw.esb_dongle else config.INTERFACE
                stage_banner(19, "Logitech Unifying Python API (RfStorm)", passive=False)
                if not config.ACTIVE_GATE or active_gate(
                    19,
                    f"Will inject cursor/keystroke events to a Unifying receiver via {_esb_iface}. "
                    "Mouse/Keyboard/DuckyScript modes available. "
                    "Authorized devices only.",
                ):
                    s19_unifying_api.run(_esb_dev, eng_id)
                else:
                    log.info("Stage 19 skipped by operator.")

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
                        s13_pairing.run(hw.ble_dongle, t, eng_id)
                        if idx < len(pairing_targets) - 1:
                            time.sleep(3.0)  # dongle recovery between targets
            else:
                log.info("Stage 13 skipped: no connectable targets.")

        if 20 in stages_requested and connections:
            from stages import s20_hijack

            stage_banner(20, "BLE Connection Hijacker (InjectaBLE)", passive=False)
            # Pick highest-value connection (prefer plaintext/unencrypted link)
            hijack_conns = sorted(
                connections,
                key=lambda c: (not c.plaintext_data_captured, not c.encrypted),
            )
            if not config.ACTIVE_GATE or active_gate(
                20,
                f"Will synchronise to a live BLE connection and attempt to evict "
                f"the legitimate Central, taking over as {hijack_conns[0].peripheral_addr}. "
                "Requires can_reactive_jam (ButteRFly nRF52840). Authorized only.",
            ):
                for conn in hijack_conns[:2]:   # try up to 2 connections
                    target_obj = next(
                        (t for t in targets if t.bd_address == conn.peripheral_addr), None
                    )
                    profile = gatt_profiles.get(conn.peripheral_addr)
                    success = s20_hijack.run(
                        hw.ble_dongle, conn, target_obj, eng_id, profile
                    )
                    if success:
                        break
            else:
                log.info("Stage 20 skipped by operator.")
        elif 20 in stages_requested:
            log.info("Stage 20 skipped: no connections captured (run Stage 2 first).")

        if 21 in stages_requested:
            from stages import s21_btclassic

            stage_banner(21, "Bluetooth Classic (BR/EDR) Scout", passive=True)
            s21_btclassic.run(hw, eng_id)

        if 22 in stages_requested:
            from stages import s22_rf4ce

            _rf4ce_dev = hw.esb_dongle or hw.ble_dongle
            if _rf4ce_dev is None:
                log.warning(
                    "[S22] No ESB or BLE device available — RF4CE stage skipped."
                )
            else:
                stage_banner(22, "RF4CE Remote Control Recon", passive=True)
                s22_rf4ce.run(hw, eng_id)

        if 23 in stages_requested:
            if hw.ble_dongle is None:
                log.warning("[S23] No BLE device available — raw 802.15.4 stage skipped.")
            else:
                from stages import s23_dot15d4

                stage_banner(23, "Raw IEEE 802.15.4 Reconnaissance", passive=True)
                s23_dot15d4.run(hw.ble_dongle, eng_id)

    except KeyboardInterrupt:
        log.info("Run aborted by user.")
    finally:
        if hw.ble_dongle:
            hw.ble_dongle.close()
        if hw.esb_dongle:
            hw.esb_dongle.close()
        if hw.phy_dongle:
            hw.phy_dongle.close()
        if hw.ubertooth_dongle:
            hw.ubertooth_dongle.close()

    from output.markdown_report import generate as gen_md
    from output.json_report import generate as gen_json
    gen_md(eng_id, args.name, args.location)
    gen_json(eng_id, args.name, args.location)

    _emit_summary(eng_id)


def _stages_from_hardware(hw: HardwareMap) -> set[int]:
    """Return the set of stage numbers supportable by detected hardware."""
    caps = hw.ble_dongle.caps if hw.ble_dongle else DongleCaps()
    stages: set[int] = set()
    if caps.can_scan:           stages.add(1)               # passive BLE scan
    if caps.can_sniff:          stages.add(2)               # connection intelligence
    if caps.can_peripheral:     stages.add(3)               # identity clone
    # S4 (reactive jam) and S20 (hijack) are destructive — always opt-in
    if caps.can_central:        stages.update({5, 7, 8, 13})  # GATT enum/fuzz/PoC, SMP
    # S6 (MITM proxy) requires a second RF interface — always opt-in
    # S9 (packet injection) is destructive — always opt-in
    # S17 (sub-GHz) requires YardStickOne — auto-selected below
    # ESB/Unifying: available from ESB dongle, primary dongle, or either
    _esb_caps = hw.esb_dongle.caps if hw.esb_dongle else caps
    if _esb_caps.can_unifying or caps.can_unifying:
        stages.add(10)                                       # Logitech Unifying/MouseJack
    if caps.can_zigbee:         stages.update({11, 23})     # ZigBee recon + raw 802.15.4 recon
    if caps.can_phy:            stages.add(12)              # PHY 2.4 GHz ISM band survey
    if _esb_caps.can_esb or caps.can_esb:
        stages.add(14)                                       # ESB raw channel scan
    if caps.can_lorawan:        stages.add(15)              # LoRaWAN recon
    if hw.phy_dongle is not None:
        stages.add(17)                                       # sub-GHz PHY (YardStickOne)
    # S18 (ESB PRX/PTX) + S19 (Unifying API) are always opt-in — not auto-selected
    # S22 (RF4CE recon) is opt-in — requires explicit --stages 22 or --opt-in
    # S21 (BR/EDR) auto-selected when HCI or Ubertooth present
    if hw.ubertooth_dongle is not None or _hci_available():
        stages.add(21)
    return stages


def _hci_available() -> bool:
    """Return True if any hci* interface is visible on this system."""
    if not shutil.which("hciconfig"):
        return False
    try:
        import subprocess as _sp
        import re as _re
        out = _sp.run(["hciconfig"], capture_output=True, text=True, timeout=3).stdout
        return bool(_re.search(r"\bhci\d+\b", out))
    except Exception:
        return False


def _print_auto_stages(stages: set[int]) -> None:
    nums = ", ".join(str(s) for s in sorted(stages))
    print(f"  Auto-selected stages : {nums}\n")


def _warn_unsupported_stages(stages: set[int], hw: HardwareMap) -> None:
    """Log a warning for each explicitly requested stage the hardware cannot support."""
    caps = hw.ble_dongle.caps if hw.ble_dongle else DongleCaps()
    _esb_caps = hw.esb_dongle.caps if hw.esb_dongle else caps

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
        18: ("can_esb",         "ESB module (PRX/PTX)"),
        19: ("can_unifying",    "Unifying module"),
        20: ("can_reactive_jam", "ReactiveJam (BLE Hijacker)"),
        22: ("can_zigbee",      "ZigBee/dot15d4 module (RF4CE)"),
        23: ("can_zigbee",      "dot15d4 module (raw 802.15.4)"),
    }
    for s in sorted(stages):
        if s == 17:
            if hw.phy_dongle is None:
                log.warning(
                    "Stage 17 requires a YardStickOne (phy_dongle=None) — "
                    "stage will be skipped. Connect YardStickOne or use --phy-interface."
                )
            continue
        if s in (18, 19):
            if hw.esb_dongle is None:
                log.warning(
                    f"Stage {s} works best with an RfStorm dongle (esb_dongle=None) — "
                    "will fall back to BLE dongle but synchronize() may fail."
                )
            continue
        if s not in _STAGE_CAP:
            continue
        cap_name, cap_label = _STAGE_CAP[s]
        # ESB/Unifying stages can use either primary or ESB dongle
        check_caps = _esb_caps if s in (10, 14) else caps
        if not getattr(check_caps, cap_name, True):
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


def _ask_zigbee_mode() -> str:
    """Prompt operator to select ZigBee mode."""
    print("\n  Stage 11 — Select ZigBee mode:")
    print("    [P]  Passive     — sniff channels 11-26, recover keys, decrypt traffic")
    print("    [C]  Coordinator — create rogue PAN, open join window, capture joins")
    print("    [E]  EndDevice   — join a real PAN as device, capture group traffic/inject")
    while True:
        try:
            choice = input("  Select mode [P/C/E]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "passive"
        if choice in ("P", ""):
            return "passive"
        if choice == "C":
            return "coordinator"
        if choice == "E":
            return "enddevice"
        print("  Please enter P, C, or E.")


def _ask_unifying_mode() -> str:
    """Prompt operator to select Unifying attack mode."""
    print("\n  Stage 10 — Select Unifying mode:")
    print("    [S]  Sniff   — passive scan, keylog, wanalyze PCAP pipeline")
    print("    [I]  Inject  — MouseJack: inject text keystrokes into receiver")
    print("    [D]  Ducky   — MouseJack: replay DuckyScript file (-d) with locale")
    print("    [M]  Mouse   — inject cursor movement and click (scripted or relay)")
    while True:
        try:
            choice = input("  Select mode [S/I/D/M]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            return "sniff"
        if choice in ("S", ""):
            return "sniff"
        if choice == "I":
            return "inject"
        if choice == "D":
            return "ducky"
        if choice == "M":
            return "mouse"
        print("  Please enter S, I, D, or M.")


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