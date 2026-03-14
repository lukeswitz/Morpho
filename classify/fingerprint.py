import re
from core.models import Target
from core.logger import get_logger
import config

log = get_logger("fingerprint")


def classify_device(t: Target) -> str:
    name_lower = (t.name or "").lower()
    mfr_lower = (t.manufacturer or "").lower()

    for device_class, rules in config.DEVICE_CLASS_RULES.items():
        for pattern in rules["name_patterns"]:
            if re.search(pattern, name_lower):
                log.debug(f"{t.bd_address} classified as {device_class} via name pattern '{pattern}'")
                return device_class
            if mfr_lower and re.search(pattern, mfr_lower):
                log.debug(f"{t.bd_address} classified as {device_class} via manufacturer pattern '{pattern}'")
                return device_class

        for uuid in rules["service_uuids"]:
            if uuid.upper() in [s.upper() for s in t.services]:
                log.debug(f"{t.bd_address} classified as {device_class} via service UUID {uuid}")
                return device_class

        if t.company_id and t.company_id in rules["company_ids"]:
            log.debug(f"{t.bd_address} classified as {device_class} via company ID {t.company_id:#06x}")
            return device_class

    return "unknown"


_HIGH_RISK_CLASSES = {"access_control", "medical", "industrial"}
_IOT_CLASSES = {"access_control", "medical", "industrial", "sensor", "smart_home", "peripheral"}


def compute_risk_score(t: Target) -> int:
    if t.device_class == "access_control":
        score = 5
    elif t.device_class == "medical":
        score = 4
    elif t.device_class == "industrial":
        score = 3
    elif t.device_class == "sensor":
        score = 2
    elif t.device_class == "smart_home":
        score = 2
    elif t.device_class == "peripheral":
        score = 2
    else:
        score = 1

    if not t.connectable:
        return score
    score += 1

    if not t.address_type.startswith("random"):
        score += 1

    if t.rssi_avg > -50:
        score += 1

    name_lower = (t.name or "").lower()
    high_value_hit = any(re.search(p, name_lower) for p in config.HIGH_VALUE_PATTERNS)
    if high_value_hit:
        score += 3

    # Unclassified devices and known IT gear without a high-value name hit are noise
    if t.device_class not in _IOT_CLASSES and not high_value_hit:
        return min(score, 3)

    return min(score, 10)
