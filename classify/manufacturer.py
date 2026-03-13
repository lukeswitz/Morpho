import csv
import re as _re
from pathlib import Path

from core.logger import get_logger
import config

log = get_logger("manufacturer")

# ---------------------------------------------------------------------------
# OUI table — loaded once from oui.csv at import time
# ---------------------------------------------------------------------------

_OUI_MAP: dict[str, str] = {}


def _load_oui() -> None:
    """
    Build OUI → Organization Name lookup from oui.csv.

    CSV format (IEEE MA-L/MA-M/MA-S registry export):
        Registry,Assignment,Organization Name,Organization Address
        MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","..."

    Assignment is 6 uppercase hex chars (e.g. A4C138 → A4:C1:38).
    Only MA-L entries (24-bit OUI) are used; MA-M/MA-S are 28/36-bit
    and don't match the 3-byte OUI prefix of a BD address.
    """
    csv_path = Path(__file__).parent.parent / "oui.csv"
    if not csv_path.exists():
        log.warning(f"oui.csv not found at {csv_path} — OUI lookup disabled")
        return

    loaded = 0
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            registry = row.get("Registry", "").strip()
            if registry != "MA-L":
                continue
            assignment = row.get("Assignment", "").strip().upper()
            if len(assignment) != 6:
                continue
            org = row.get("Organization Name", "").strip().strip('"').strip()
            if not org:
                continue
            oui_key = ":".join(assignment[i : i + 2] for i in (0, 2, 4))
            _OUI_MAP[oui_key] = org
            loaded += 1

    log.debug(f"OUI table loaded: {loaded} entries from {csv_path.name}")


_load_oui()


# ---------------------------------------------------------------------------
# Bluetooth SIG company_identifiers.yaml  (optional, ships alongside oui.csv)
# ---------------------------------------------------------------------------
#
# Download from: https://www.bluetooth.com/specifications/assigned-numbers/
# (public YAML repo) — place as company_identifiers.yaml next to oui.csv.
#
# Expected format:
#   company_identifiers:
#     - value: 0
#       name: "Ericsson AB"
#     - value: 4
#       name: "Agere Systems"
#
# Values may be decimal integers or 0x-prefixed hex strings.
# No pyyaml dependency — the format is regular enough for regex parsing.

_SIG_MAP: dict[int, str] = {}

# The YAML list format is:  "  - value: 0"  so the "- " prefix must be optional.
_VALUE_RE = _re.compile(r"^\s*(?:-\s+)?value:\s*(0[xX][0-9A-Fa-f]+|\d+)")
_NAME_RE  = _re.compile(r'^\s*name:\s*"?([^"#\n]+?)"?\s*$')


def _load_sig_company_ids() -> None:
    yaml_path = Path(__file__).parent.parent / "company_identifiers.yaml"
    if not yaml_path.exists():
        log.debug("company_identifiers.yaml not found — SIG company lookup uses config.COMPANY_IDS only")
        return

    loaded = 0
    pending_value: int | None = None

    with yaml_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            vm = _VALUE_RE.match(line)
            if vm:
                raw = vm.group(1)
                pending_value = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw)
                continue
            nm = _NAME_RE.match(line)
            if nm and pending_value is not None:
                _SIG_MAP[pending_value] = nm.group(1).strip()
                loaded += 1
                pending_value = None

    if loaded:
        log.info(f"SIG company IDs loaded: {loaded} entries from {yaml_path.name}")
    else:
        log.warning(f"SIG YAML found at {yaml_path} but 0 entries parsed — check format")


_load_sig_company_ids()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def oui_lookup(bd_address: str) -> str | None:
    """
    Return the registered organisation name for the OUI of a public BD address.

    The first three bytes of a public address are the OUI.
    Returns None for random addresses or unknown OUIs.
    """
    prefix = bd_address.upper()[:8]  # e.g. "BE:28:5D"
    return _OUI_MAP.get(prefix)


def decode_manufacturer(data: bytes) -> tuple[int | None, str | None]:
    """
    Parse a manufacturer-specific AD record (type 0xFF).

    The first two bytes are the Bluetooth SIG company ID (little-endian).
    Returns (company_id, company_name).

    Lookup order:
      1. Full SIG company_identifiers.yaml table (7,200+ entries, if present)
      2. COMPANY_IDS dict in config.py (hardcoded additions / overrides)
      3. None — caller should fall back to OUI or leave manufacturer unset

    Returning None (not "Unknown (0x...)") lets callers keep a good OUI name
    when the company ID isn't in either table.
    """
    if len(data) < 2:
        return None, None

    company_id = int.from_bytes(data[:2], "little")

    # 1. Full SIG YAML table
    name: str | None = _SIG_MAP.get(company_id)

    # 2. Config overrides (fills gaps when YAML isn't present, custom entries)
    if name is None:
        name = config.COMPANY_IDS.get(company_id)

    if name:
        log.debug(f"Company ID {company_id:#06x} → {name}")
    else:
        log.debug(f"Company ID {company_id:#06x} not resolved")

    return company_id, name
