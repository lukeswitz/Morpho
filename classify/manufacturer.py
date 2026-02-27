from core.logger import get_logger
import config

log = get_logger("manufacturer")


def decode_manufacturer(data: bytes) -> tuple[int | None, str | None]:
    """
    Parse manufacturer specific AD record (type 0xFF).
    First two bytes are company ID (little-endian).
    Returns (company_id, company_name).
    """
    if len(data) < 2:
        return None, None

    company_id = int.from_bytes(data[:2], "little")
    name = config.COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")
    log.debug(f"Company ID {company_id:#06x} → {name}")
    return company_id, name


def oui_lookup(bd_address: str) -> str | None:
    """
    Rough OUI lookup for public addresses.
    First 3 bytes of a public address are the OUI.
    Extend with a real OUI database file if precision is needed.
    """
    oui_map = {
        "AC:23:3F": "Nordic Semiconductor",
        "00:1A:7D": "Intel",
        "F8:1A:67": "Texas Instruments",
        "04:A3:16": "Silicon Laboratories",
        "C4:BE:84": "Texas Instruments",
        "38:8B:59": "Apple",
        "A4:C1:38": "Espressif",
    }
    prefix = bd_address.upper()[:8]
    return oui_map.get(prefix)
