import csv
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
    Returns (company_id, company_name).  Falls back to the COMPANY_IDS map
    in config.py for well-known IDs, then shows the raw hex value.
    """
    if len(data) < 2:
        return None, None

    company_id = int.from_bytes(data[:2], "little")
    name = config.COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")
    log.debug(f"Company ID {company_id:#06x} → {name}")
    return company_id, name
