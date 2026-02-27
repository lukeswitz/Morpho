import os
from pathlib import Path

INTERFACE = "uart0"
SCAN_DURATION = 120
CONN_SNIFF_DURATION = 300
ACTIVE_GATE = True
VERBOSE_MODE = False        # True = print [WHAD] narration lines (training/classroom mode)
DONGLE_TIMEOUT = 5          # seconds allowed for each capability probe at startup
PCAP_DIR = Path("./pcaps")
REPORT_DIR = Path("./reports")
DB_PATH = Path("./findings.db")
TARGET_FILTER = []

HIGH_VALUE_PATTERNS = [
    r"lock",
    r"door",
    r"access",
    r"badge",
    r"entry",
    r"hvac",
    r"temp",
    r"humid",
    r"sensor",
    r"therm",
    r"alarm",
    r"gate",
    r"motion",
    r"smoke",
    r"fire",
    r"patient",
    r"monitor",
    r"infus",
    r"pump",
    r"vital",
    r"plc",
    r"hmi",
    r"scada",
    r"relay",
    r"controll",
]

COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0059: "Nordic Semiconductor",
    0x0499: "Ruuvi Innovations",
    0x0157: "Polar Electro",
    0x0171: "Amazon",
    0x02E5: "Espressif",
    0x08D0: "Cisco",
}

SERVICE_UUID_MAP = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180A": "Device Information",
    "180D": "Heart Rate",
    "180F": "Battery Service",
    "1810": "Blood Pressure",
    "1812": "Human Interface Device",
    "181A": "Environmental Sensing",
    "181C": "User Data",
    "1820": "Internet Protocol Support",
    "FFF0": "Nordic UART (common IoT)",
    "FFE0": "HM-10 Serial (common IoT)",
}

DEVICE_CLASS_RULES = {
    "access_control": {
        "name_patterns": [
            r"lock",
            r"door",
            r"access",
            r"badge",
            r"entry",
            r"gate",
        ],
        "service_uuids": [],
        "company_ids": [],
    },
    "sensor": {
        "name_patterns": [
            r"hvac",
            r"temp",
            r"humid",
            r"therm",
            r"sensor",
            r"ruuvi",
            r"motion",
            r"smoke",
            r"fire",
            r"alarm",
        ],
        "service_uuids": ["181A"],
        "company_ids": [0x0499],
    },
    "medical": {
        "name_patterns": [
            r"patient",
            r"monitor",
            r"infus",
            r"pump",
            r"vital",
            r"heart",
            r"bp",
            r"spo2",
            r"glucose",
        ],
        "service_uuids": ["180D", "1810"],
        "company_ids": [0x0157],
    },
    "industrial": {
        "name_patterns": [
            r"plc",
            r"hmi",
            r"scada",
            r"relay",
            r"controll",
            r"actuator",
        ],
        "service_uuids": [],
        "company_ids": [],
    },
    "it_gear": {
        "name_patterns": [],
        "service_uuids": ["1812"],
        "company_ids": [0x004C, 0x0006, 0x0075, 0x00E0, 0x0171],
    },
}