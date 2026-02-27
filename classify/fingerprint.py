import re
from core.models import Target
from core.logger import get_logger
import config

log = get_logger("fingerprint")


def classify_device(t: Target) -> str:
    name_lower = (t.name or "").lower()

    for device_class, rules in config.DEVICE_CLASS_RULES.items():
        for pattern in rules["name_patterns"]:
            if re.search(pattern, name_lower):
                log.debug(f"{t.bd_address} classified as {device_class} via name pattern '{pattern}'")
                return device_class

        for uuid in rules["service_uuids"]:
            if uuid.upper() in [s.upper() for s in t.services]:
                log.debug(f"{t.bd_address} classified as {device_class} via service UUID {uuid}")
                return device_class

        if t.company_id and t.company_id in rules["company_ids"]:
            log.debug(f"{t.bd_address} classified as {device_class} via company ID {t.company_id:#06x}")
            return device_class

    return "unknown"


def compute_risk_score(t: Target) -> int:
    score = 0

    if t.device_class == "access_control":
        score += 5
    elif t.device_class == "medical":
        score += 4
    elif t.device_class == "industrial":
        score += 3
    else:
        score = 1

    if t.connectable:
        score += 1
    else:
        return score

    if not t.address_type.startswith("random"):
        score += 1

    if t.rssi_avg > -50:
        score += 1

    for pattern in config.HIGH_VALUE_PATTERNS:
        if re.search(pattern, (t.name or "").lower()):
            score += 3
            break

    return min(score, 10)
