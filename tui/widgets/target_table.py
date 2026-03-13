from __future__ import annotations

import unicodedata
from typing import TypedDict

from rich.text import Text as RichText
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable

_RISK_ORDER: dict[str, int] = {"CRIT": 4, "HIGH": 3, "MED": 2, "LOW": 1, "INFO": 0}
_COL_LABELS = ("RISK", "ADDRESS", "ADV", "ADDR", "CLASS", "MANUFACTURER", "RSSI", "NAME")


def _ascii_safe(s: str) -> str:
    return "".join(
        c for c in s
        if unicodedata.category(c)[0] not in ("S", "C") or c in ("\t",)
    ).strip()


def _risk_label(score: int) -> str:
    if score >= 8:
        return "CRIT"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MED "
    if score >= 2:
        return "LOW "
    return "INFO"


class _RowData(TypedDict):
    """Raw (un-redacted) field values stored per row for toggle support."""
    risk:   str
    addr:   str   # real BD address
    adv:    str
    atype:  str
    cls:    str
    mfr:    str
    rssi:   str
    name:   str


class TargetTableWidget(Widget):
    """
    Right panel: live-updating target table.

    Row keys are always the *real* BD address so update_cell() works
    correctly regardless of redact state.  The _rows dict stores raw
    (un-redacted) values so redact_all_rows() / restore_all_rows() can
    re-render every row without needing the original Target objects.
    """

    def __init__(self) -> None:
        super().__init__()
        self._col_risk:    object = None
        self._col_addr:    object = None
        self._col_adv:     object = None
        self._col_atype:   object = None
        self._col_cls:     object = None
        self._col_mfr:     object = None
        self._col_rssi:    object = None
        self._col_name:    object = None
        self._col_results: object = None
        # real_addr → raw field dict (for redact toggle / restore)
        self._rows: dict[str, _RowData] = {}
        # tracks which real_addrs have a row in the DataTable
        # (can't use table.rows directly — it's keyed by RowKey, not str)
        self._known: set[str] = set()
        self._sort_col: object = None
        self._sort_reverse: bool = False
        self._col_base_labels: dict[object, str] = {}
        # per-device scan feedback
        self._scan_status: dict[str, str] = {}  # addr → active stage label e.g. "S05"
        self._findings:    dict[str, int] = {}  # addr → cumulative findings count

    def compose(self) -> ComposeResult:
        table: DataTable = DataTable(id="target-dt", zebra_stripes=True)
        k_risk    = table.add_column("RISK")
        k_addr    = table.add_column("ADDRESS")
        k_adv     = table.add_column("ADV")
        k_atype   = table.add_column("ADDR")
        k_cls     = table.add_column("CLASS")
        k_mfr     = table.add_column("MANUFACTURER")
        k_rssi    = table.add_column("RSSI")
        k_name    = table.add_column("NAME")
        k_results = table.add_column("RESULTS")
        (
            self._col_risk, self._col_addr, self._col_adv, self._col_atype,
            self._col_cls, self._col_mfr, self._col_rssi, self._col_name,
            self._col_results,
        ) = (k_risk, k_addr, k_adv, k_atype, k_cls, k_mfr, k_rssi, k_name, k_results)
        self._col_base_labels = {
            k_risk:    "RISK",
            k_addr:    "ADDRESS",
            k_adv:     "ADV",
            k_atype:   "ADDR",
            k_cls:     "CLASS",
            k_mfr:     "MANUFACTURER",
            k_rssi:    "RSSI",
            k_name:    "NAME",
            k_results: "RESULTS",
        }
        yield table

    # ── Sorting ───────────────────────────────────────────────────────────────

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        table = self.query_one("#target-dt", DataTable)
        col_key = event.column_key
        if self._sort_col == col_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col_key
            self._sort_reverse = False

        if col_key == self._col_rssi:
            def sort_key(cell: RichText) -> int:
                try:
                    return int(cell.plain)
                except ValueError:
                    return 0
        elif col_key == self._col_risk:
            def sort_key(cell: RichText) -> int:  # type: ignore[misc]
                return _RISK_ORDER.get(cell.plain.strip(), -1)
        else:
            def sort_key(cell: RichText) -> str:  # type: ignore[misc]
                return cell.plain.lower()

        table.sort(col_key, key=sort_key, reverse=self._sort_reverse)
        indicator = " ▼" if self._sort_reverse else " ▲"
        for ck, base in self._col_base_labels.items():
            table.columns[ck].label = RichText(
                base + (indicator if ck == col_key else "")
            )
        table.refresh()

    # ── Public API ────────────────────────────────────────────────────────────

    def add_target(self, target: object) -> None:
        """
        Upsert a row.  Called from the Textual event loop (via call_from_thread).
        'target' is a core.models.Target instance typed as object to avoid import.
        """
        from core.logger import register_redact_name

        real_addr = getattr(target, "bd_address", "??:??:??:??:??:??")

        raw_adv   = (getattr(target, "adv_type", "") or "").replace("ADV_", "").replace("_IND", "")[:10]
        raw_atype_full = getattr(target, "address_type", "") or ""
        raw_atype = (
            "rnd" if raw_atype_full.startswith("random") else
            "pub" if raw_atype_full == "public" else
            raw_atype_full[:6]
        )
        raw_cls  = _ascii_safe(getattr(target, "device_class", "") or "")[:14]
        raw_mfr  = _ascii_safe((getattr(target, "manufacturer", None) or "—"))[:20]
        raw_name = _ascii_safe((getattr(target, "name", None) or "—"))[:20]

        # Register names for future log redaction regardless of current state
        if raw_name not in ("—", ""):
            register_redact_name(raw_name)
        if raw_mfr not in ("—", ""):
            register_redact_name(raw_mfr)

        row: _RowData = {
            "risk":  _risk_label(getattr(target, "risk_score", 0)),
            "addr":  real_addr,
            "adv":   raw_adv,
            "atype": raw_atype,
            "cls":   raw_cls,
            "mfr":   raw_mfr,
            "rssi":  f"{getattr(target, 'rssi_avg', 0):.0f}",
            "name":  raw_name,
        }
        self._rows[real_addr] = row
        self._render_row(real_addr)

    def redact_all_rows(self) -> None:
        """Apply redaction to every row currently in the table."""
        for real_addr in self._rows:
            self._render_row(real_addr)

    def restore_all_rows(self) -> None:
        """Re-render every row with raw values (after disabling redact)."""
        for real_addr in self._rows:
            self._render_row(real_addr)

    def set_scan_status(self, addr: str, stage_label: str) -> None:
        """Mark addr as currently being scanned by stage_label (e.g. 'S05')."""
        self._scan_status[addr] = stage_label
        if addr in self._rows:
            self._render_row(addr)

    def add_finding(self, addr: str, n: int = 1) -> None:
        """Increment findings count for addr and clear the active scan indicator."""
        self._findings[addr] = self._findings.get(addr, 0) + n
        self._scan_status.pop(addr, None)
        if addr in self._rows:
            self._render_row(addr)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _render_row(self, real_addr: str) -> None:
        """Render one row applying the current redact state."""
        from core.logger import redact_str

        row = self._rows[real_addr]
        table = self.query_one("#target-dt", DataTable)

        t_risk  = RichText(row["risk"])
        t_addr  = RichText(redact_str(real_addr))
        t_adv   = RichText(row["adv"])
        t_atype = RichText(row["atype"])
        t_cls   = RichText(row["cls"])
        t_mfr   = RichText(redact_str(row["mfr"]))
        t_rssi  = RichText(row["rssi"])
        t_name  = RichText(redact_str(row["name"]))

        active_stage = self._scan_status.get(real_addr)
        findings     = self._findings.get(real_addr, 0)
        if active_stage:
            t_results = RichText(f"\u27f3 {active_stage}", style="bold #ffff00")
        elif findings:
            t_results = RichText(f"\u2713 {findings} fnds", style="#00cc66")
        else:
            t_results = RichText("\u2014", style="dim")

        if real_addr in self._known:
            table.update_cell(real_addr, self._col_risk,    t_risk)
            table.update_cell(real_addr, self._col_addr,    t_addr)
            table.update_cell(real_addr, self._col_adv,     t_adv)
            table.update_cell(real_addr, self._col_atype,   t_atype)
            table.update_cell(real_addr, self._col_cls,     t_cls)
            table.update_cell(real_addr, self._col_mfr,     t_mfr)
            table.update_cell(real_addr, self._col_rssi,    t_rssi)
            table.update_cell(real_addr, self._col_name,    t_name)
            table.update_cell(real_addr, self._col_results, t_results)
        else:
            self._known.add(real_addr)
            table.add_row(
                t_risk, t_addr, t_adv, t_atype, t_cls, t_mfr, t_rssi, t_name, t_results,
                key=real_addr,
            )
