from datetime import datetime, timezone
from pathlib import Path

from core.db import get_targets, get_findings
from core.logger import get_logger
import config

log = get_logger("markdown_report")


def generate(engagement_id: str, name: str, location: str) -> Path:
    targets = get_targets(engagement_id)
    findings = get_findings(engagement_id)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# BLE Red Team Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Engagement | {name} ({engagement_id}) |",
        f"| Location | {location or 'unspecified'} |",
        f"| Generated | {ts} |",
        f"| Targets | {len(targets)} |",
        f"| Findings | {len(findings)} |",
        f"",
    ]

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_counts = {}
    for f in findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines.append("## Finding Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for s in sev_order:
        c = sev_counts.get(s, 0)
        if c:
            lines.append(f"| {s.upper()} | {c} |")
    lines.append("")

    if findings:
        lines.append("## Findings Detail")
        lines.append("")
        sorted_findings = sorted(
            findings,
            key=lambda x: sev_order.index(x["severity"])
            if x["severity"] in sev_order
            else 99,
        )
        for i, f in enumerate(sorted_findings, 1):
            lines.append(
                f"### {i}. [{f['severity'].upper()}] "
                f"{f['type']} -- {f['target_addr']}"
            )
            lines.append("")
            lines.append(f"**Description:** {f['description']}")
            lines.append("")
            lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")
            if f.get("pcap_path"):
                lines.append(f"**PCAP:** `{f['pcap_path']}`")
                lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("## Target Inventory")
    lines.append("")
    lines.append(
        "| BD Address | Type | Class | Conn | "
        "Risk | RSSI | Name |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for t in targets:
        lines.append(
            f"| {t['bd_address']} | {t['address_type']} | "
            f"{t['device_class']} | "
            f"{'Y' if t['connectable'] else 'N'} | "
            f"{t['risk_score']} | "
            f"{t['rssi_avg']:.0f} | "
            f"{t['name'] or '--'} |"
        )
    lines.append("")

    report_path = (
        config.REPORT_DIR / f"report_{engagement_id}.md"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Markdown report written to {report_path}")
    return report_path