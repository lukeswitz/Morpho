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
        "38:8B:59": "Apple",
        "A4:C1:38": "Espressif",
        "AC:23:3F": "Nordic Semiconductor",
        "00:1A:7D": "Intel",
        "F8:1A:67": "Texas Instruments",
        "04:A3:16": "Silicon Laboratories",
        "C4:BE:84": "Texas Instruments",
        "E8:E0:E6": "Realtek",
        "8C:2B:AA": "Broadcom",
        "F0:9F:C2": "Qualcomm",
        "00:0D:B5": "Philips",
        "BC:85:56": "Fitbit",
        "48:65:EE": "Garmin",
        "30:AE:A4": "Xiaomi",
        "4C:65:A8": "OnePlus",
        "AC:BC:32": "Lenovo",
        "B0:B9:8A": "Parrot",
        "5A:31:3E": "Amazon",
        "D8:A0:30": "Sonos",
        "00:13:10": "Plantronics",
    }
    prefix = bd_address.upper()[:8]
    return oui_map.get(prefix)
