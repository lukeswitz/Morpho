import argparse
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
        default="1,2,3,4,5,7,8",
        help="Comma-separated list of stages to run (default: 1,2,3,4,5,7,8)",
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
    return p.parse_args()


def _apply_args(args: argparse.Namespace) -> None:
    config.INTERFACE = args.interface
    config.SCAN_DURATION = args.scan_duration
    if args.no_gate:
        config.ACTIVE_GATE = False
    if args.targets:
        config.TARGET_FILTER = [a.upper() for a in args.targets]
    config.PROXY_INTERFACE = args.proxy_interface


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

    stages_requested = {
        int(s.strip()) for s in args.stages.split(",") if s.strip().isdigit()
    }

    dongle = WhadDongle.create(config.INTERFACE)
    _caps_banner(dongle)

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
                connections = s2_intel.run(dongle, connectable, eng_id)
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

                    s3_clone.run(dongle, high_value[0], eng_id)
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
                            print(
                                f"    {t.bd_address:<20}  "
                                f"{t.name or '—':<20}  "
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
                            s7_fuzz.run(
                                dongle, t, eng_id,
                                prepped_handles=gatt_writable.get(t.bd_address),
                            )
                else:
                    log.info("Stage 7 skipped by operator.")
            else:
                log.info("Stage 7 skipped: no connectable targets.")

        if 8 in stages_requested and targets:
            poc_targets = [
                t for t in targets
                if t.connectable and t.bd_address in gatt_profiles
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
                    for t in poc_targets:
                        s8_poc.run(dongle, t, eng_id, gatt_profiles[t.bd_address])
            else:
                log.info("Stage 8 skipped: no GATT profiles from S5.")

    except KeyboardInterrupt:
        log.info("Run aborted by user.")
    finally:
        dongle.close()

    from output.markdown_report import generate as gen_md
    from output.json_report import generate as gen_json
    gen_md(eng_id, args.name, args.location)
    gen_json(eng_id, args.name, args.location)

    _emit_summary(eng_id)


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
        for f in sorted(findings, key=lambda x: ("critical","high","medium","low","info").index(x["severity"])):
            desc = f.get("description", "")
            short = desc[:80] + "…" if len(desc) > 80 else desc
            print(
                f"    [{f['severity'].upper():<8}]  "
                f"{f['target_addr']:<20}  "
                f"{f['type']:<16}  "
                f"{short}"
            )

    print(f"\n  Database: {config.DB_PATH}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()