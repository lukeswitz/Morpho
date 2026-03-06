import os
from pathlib import Path

INTERFACE = "uart0"
PROXY_INTERFACE = "hci0"   # second interface for Stage 6 wble-proxy
SCAN_DURATION = 120
CONN_SNIFF_DURATION = 60
ACTIVE_GATE = True
VERBOSE_MODE = False        # True = print [WHAD] narration lines (training/classroom mode)
DONGLE_TIMEOUT = 5          # seconds allowed for each capability probe at startup
PCAP_DIR = Path("./pcaps")
REPORT_DIR = Path("./reports")
DB_PATH = Path("./findings.db")
TARGET_FILTER = []
RSSI_MIN_FILTER = 0     # dBm — 0 = no filter; e.g. -70 ignores devices weaker than -70 dBm
S3_SPAWN_MODE   = False  # True = use wble-spawn transparent relay instead of static clone

# Stage 13 — SMP Pairing Vulnerability Scanner
S13_CONNECT_TIMEOUT = 15   # seconds to establish each test connection
S13_PAIRING_TIMEOUT = 15   # seconds per pairing attempt (WHAD blocks internally)

# Stage 10 — Logitech Unifying / MouseJack
UNIFYING_SNIFF_SECS   = 30               # passive channel-scan window
UNIFYING_INJECT_SECS  = 10               # quick scan before inject to find devices
MOUSEJACK_TEXT        = "MouseJack-PoC"  # text injected in keyboard PoC
UNIFYING_LOCALE       = "us"             # keyboard locale for wuni-keyboard -l
UNIFYING_DUCKY_SCRIPT: str | None = None # path to DuckyScript file for inject -d mode

# Stage 18 — ESB PRX/PTX Active Attack
ESB_PRX_TIMEOUT    = 30             # seconds to listen in PRX (passive ACK) mode
ESB_PTX_PAYLOAD    = "050000000000" # hex payload bytes for PTX inject test
ESB_REPLAY_FRAMES  = 5              # frames to capture in PRX before PTX replay

# Stage 19 — Logitech Unifying Python API
UNIFYING_MOUSE_MOVES  = 5                # mouse move demo steps
UNIFYING_KBD_TEXT     = "Hello from WHAD" # text for Keyboard.send_text()
UNIFYING_SYNC_TIMEOUT = 15               # seconds to wait for synchronize()

# Stage 11 — IEEE 802.15.4 / ZigBee
ZIGBEE_SCAN_SECS    = 60   # informational total across all channels
ZIGBEE_PER_CH_SECS  = 3    # dwell per channel (16 channels × 3s = 48s)
ZIGBEE_COORD_SECS   = 60   # join window for rogue coordinator mode

# Stage 12 — PHY / ISM Band Survey
PHY_SWEEP_SECS       = 120  # informational total sweep budget
PHY_PER_FREQ_SECS    = 2    # dwell per frequency step (2 MHz spacing)
PHY_CAPTURE_TOP_N    = 3    # focused PCAP capture for N most-active frequencies
PHY_CAPTURE_SECS     = 5    # focused capture duration per hot frequency

# Stage 14 — ESB Raw Scanner
ESB_SCAN_SECS    = 60    # total scan budget across all channels
ESB_PER_CH_SECS  = 1     # packet wait timeout per channel

# Stage 15 — LoRaWAN Recon
LORAWAN_REGION    = "EU868"   # "EU868" or "US915"
LORAWAN_SNIFF_SECS = 120      # total passive listen window

# Stage 17 — YardStickOne sub-GHz PHY Survey
SUBGHZ_SWEEP_SECS    = 120   # total sweep budget
SUBGHZ_PER_FREQ_SECS = 2     # dwell per frequency step
SUBGHZ_RECORD_SECS   = 5     # focused PCAP capture per active OOK frequency

# Secondary device interfaces (auto-detected from whadup if not set)
ESB_INTERFACE: str | None = None         # rfstorm0 if available
PHY_SUBGHZ_INTERFACE: str | None = None  # yardstickone0 if available
UBERTOOTH_INTERFACE: str | None = None   # ubertooth0 if available

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