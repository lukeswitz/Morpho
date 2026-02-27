"""
output/json_report.py — machine-readable engagement report.

Generates reports/report_<engagement_id>.json for cross-engagement querying
and integration with external tooling (dashboards, defect trackers, etc.).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.db import get_targets, get_findings, get_connections
from core.logger import get_logger
import config

log = get_logger("json_report")

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def generate(engagement_id: str, name: str, location: str) -> Path | None:
    targets = get_targets(engagement_id)
    findings = get_findings(engagement_id)
    connections = get_connections(engagement_id)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    sev_counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1

    report: dict = {
        "engagement": {
            "id": engagement_id,
            "name": name,
            "location": location or "",
            "generated": ts,
        },
        "summary": {
            "targets": len(targets),
            "findings": len(findings),
            "connections": len(connections),
            **sev_counts,
        },
        "findings": [
            {
                "type": f.get("type"),
                "severity": f.get("severity"),
                "target_addr": f.get("target_addr"),
                "description": f.get("description"),
                "remediation": f.get("remediation"),
                "pcap_path": f.get("pcap_path"),
                "timestamp": f.get("timestamp"),
                "evidence": _parse_json_field(f.get("evidence")),
            }
            for f in sorted(
                findings,
                key=lambda x: _SEV_ORDER.index(x["severity"])
                if x.get("severity") in _SEV_ORDER
                else 99,
            )
        ],
        "connections": [
            {
                "central_addr": c.get("central_addr"),
                "peripheral_addr": c.get("peripheral_addr"),
                "access_address": c.get("access_address"),
                "interval_ms": c.get("interval_ms"),
                "encrypted": bool(c.get("encrypted")),
                "legacy_pairing_observed": bool(c.get("legacy_pairing_observed")),
                "plaintext_data_captured": bool(c.get("plaintext_data_captured")),
                "timestamp": c.get("timestamp"),
            }
            for c in connections
        ],
        "targets": [
            {
                "bd_address": t.get("bd_address"),
                "address_type": t.get("address_type"),
                "adv_type": t.get("adv_type"),
                "name": t.get("name"),
                "manufacturer": t.get("manufacturer"),
                "device_class": t.get("device_class"),
                "connectable": bool(t.get("connectable")),
                "risk_score": t.get("risk_score"),
                "rssi_avg": t.get("rssi_avg"),
                "services": _parse_json_field(t.get("services")) or [],
                "first_seen": t.get("first_seen"),
                "last_seen": t.get("last_seen"),
            }
            for t in targets
        ],
    }

    report_path = config.REPORT_DIR / f"report_{engagement_id}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    log.info(f"JSON report written to {report_path}")
    return report_path


def _parse_json_field(value) -> object:
    """Parse a field that may already be a dict/list or a JSON string."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value
