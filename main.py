import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.dongle import WhadDongle
from core.db import init_db, upsert_engagement
from core.logger import get_logger, stage_banner, active_gate
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
        default="1,2,3,4,5",
        help="Comma-separated list of stages to run (default: 1,2,3,4,5)",
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
    return p.parse_args()


def _apply_args(args: argparse.Namespace) -> None:
    config.INTERFACE = args.interface
    config.SCAN_DURATION = args.scan_duration
    if args.no_gate:
        config.ACTIVE_GATE = False
    if args.targets:
        config.TARGET_FILTER = [a.upper() for a in args.targets]


def _banner(eng_id: str, name: str, location: str) -> None:
    line = "=" * 60
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{line}")
    print("  BLE RED TEAM FRAMEWORK")
    print(f"  Engagement : {name} ({eng_id})")
    print(f"  Location   : {location or 'unspecified'}")
    print(f"  Interface  : {config.INTERFACE}")
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
            jam_target = (
                connections[0]
                if connections
                else next(
                    (t for t in targets if t.connectable), None
                )
            )
            if jam_target:
                if not config.ACTIVE_GATE or active_gate(
                    4,
                    "Reactive jamming will disrupt BLE communications. "
                    "Authorized targets only.",
                ):
                    from stages import s4_jam

                    s4_jam.run(dongle, jam_target, eng_id)
            else:
                log.info("Stage 4 skipped: no suitable target.")

        if 5 in stages_requested and targets:
            connectable = [t for t in targets if t.connectable]
            if connectable:
                stage_banner(
                    5, "Direct Interaction / GATT Enumeration", passive=False
                )
                if not config.ACTIVE_GATE or active_gate(
                    5,
                    f"Will connect to {len(connectable)} device(s) "
                    "and enumerate GATT profiles.",
                ):
                    from stages import s5_interact

                    for t in connectable:
                        s5_interact.run(dongle, t, eng_id)
            else:
                log.info("Stage 5 skipped: no connectable targets.")

    except KeyboardInterrupt:
        log.info("Run aborted by user.")
    finally:
        dongle.close()

    from output.markdown_report import generate as gen_md
    from output.json_report import generate as gen_json
    md_path = gen_md(eng_id, args.name, args.location)
    if md_path:
        log.info(f"Markdown report: {md_path}")
    json_path = gen_json(eng_id, args.name, args.location)
    if json_path:
        log.info(f"JSON report:     {json_path}")

    _emit_summary(eng_id)


def _emit_summary(eng_id: str) -> None:
    from core.db import get_targets, get_findings, _connect

    targets = get_targets(eng_id)
    findings = get_findings(eng_id)

    with _connect() as conn:
        total_targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        total_engagements = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]

    print("\n" + "=" * 60)
    print(f"  RUN COMPLETE — engagement {eng_id}")
    print(f"  Targets this run : {len(targets)}")
    print(f"  Total in DB      : {total_targets} targets across {total_engagements} engagement(s)")
    print(f"  Findings         : {len(findings)}")

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count:
            print(f"    {sev:<12} {count}")

    print(f"\n  Database: {config.DB_PATH}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()