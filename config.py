import os
from pathlib import Path

INTERFACE = "uart0"
PROXY_INTERFACE = "hci0"   # second interface for Stage 6 wble-proxy
SCAN_DURATION = 60
CONN_SNIFF_DURATION = 45
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
ESB_PRX_ACK_PAYLOAD: str | None = None  # hex bytes to send as custom ACK per received frame

# Stage 19 — Logitech Unifying Python API
UNIFYING_MOUSE_MOVES       = 5                # mouse move demo steps
UNIFYING_MOUSE_RIGHT_CLICK = False            # also inject right_click() after left_click()
UNIFYING_MOUSE_SCROLL_LINES = 0               # >0 = scroll up N lines; <0 = scroll down N lines
UNIFYING_KBD_TEXT     = "Hello from WHAD" # text for Keyboard.send_text()
UNIFYING_SYNC_TIMEOUT = 15               # seconds to wait for synchronize()

# Stage 22 — RF4CE Remote Control Reconnaissance
RF4CE_SNIFF_SECS = 30  # dwell per channel (channels 15, 20, 25)

# Stage 11 — IEEE 802.15.4 / ZigBee
ZIGBEE_SCAN_SECS    = 60   # informational total across all channels
ZIGBEE_PER_CH_SECS  = 3    # dwell per channel (16 channels × 3s = 48s)
ZIGBEE_COORD_SECS   = 60   # join window for rogue coordinator mode

# Stage 23 — Raw IEEE 802.15.4 Reconnaissance
DOT15D4_PER_CH_SECS = 5    # dwell per channel (16 channels × 5s = 80s)

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

# Output redaction — replace MACs and device names in all log/TUI output
REDACT_OUTPUT: bool = False

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
    # Chipset / silicon vendors
    0x0002: "Intel",
    0x000A: "Qualcomm",
    0x000F: "Broadcom",
    0x0025: "Cambridge Silicon Radio",
    0x005A: "Dialog Semiconductor",
    0x0101: "MediaTek",
    0x025F: "NXP Semiconductors",
    0x0059: "Nordic Semiconductor",
    0x02E5: "Espressif",
    # Consumer electronics
    0x0006: "Microsoft",
    0x0008: "Motorola",
    0x004C: "Apple",
    0x0057: "Harman International",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x00CD: "Logitech",
    0x00E0: "Google",
    0x0131: "Parrot",
    0x0145: "Plantronics",
    0x015F: "Sony",
    0x0171: "Amazon",
    0x01A4: "Bose",
    0x0310: "Fitbit",
    0x0636: "Xiaomi",
    0x0822: "Anker",
    0x05A7: "Sonos",
    # Networking / enterprise
    0x08D0: "Cisco",
    # Health / fitness
    0x0157: "Polar Electro",
    0x0217: "Withings",
    0x0231: "Tile",
    0x0499: "Ruuvi Innovations",
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
            r"schlage",
            r"august",
            r"yale",
            r"kwikset",
            r"nuki",
            r"igloohome",
        ],
        "service_uuids": [],
        "company_ids": [],
    },
    "sensor": {
        # Pure environmental / condition monitoring devices only
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
            r"inkbird",
            r"sensorpush",
            r"ibs-th",
            r"thermoplus",
            r"blue maestro",
            r"mopeka",
            r"telaire",
            r"bthome",
        ],
        "service_uuids": ["181A", "181C", "181D", "181E"],
        "company_ids": [0x0499],   # Ruuvi Innovations
    },
    "smart_home": {
        # Lighting, plugs, switches, and home automation brands
        # (many also make sensors but their primary identity is smart home)
        "name_patterns": [
            r"govee",
            r"philips hue",
            r"\bhue\b",
            r"lifx",
            r"nanoleaf",
            r"\bwiz\b",
            r"\bwyze\b",
            r"tradfri",
            r"\bikea\b",
            r"wemo",
            r"\bkasa\b",
            r"meross",
            r"shelly",
            r"sonoff",
            r"tasmota",
            r"tuya",
            r"switchbot",
            r"\beve\b",
            r"ledvance",
            r"sengled",
            r"aqara",
            r"xiaomi",
            r"mijia",
            r"smart plug",
            r"smart bulb",
            r"smart light",
            r"smart switch",
        ],
        "service_uuids": [],
        "company_ids": [
            0x02AA,   # Govee Health
            0x038F,   # Xiaomi
        ],
    },
    "medical": {
        "name_patterns": [
            r"patient",
            r"monitor",
            r"infus",
            r"pump",
            r"vital",
            r"heart",
            r"\bbp\b",
            r"spo2",
            r"glucose",
            r"oximeter",
            r"contec",
            r"nonin",
            r"omron",
            r"withings",
        ],
        "service_uuids": ["180D", "1810", "1808", "1809"],
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
            r"modbus",
            r"profibus",
            r"fieldbus",
            r"gateway",
        ],
        "service_uuids": [],
        "company_ids": [],
    },
    "peripheral": {
        # BLE-connected peripherals — HID devices, headphones, speakers.
        # These ARE valid GATT targets (audio controls, battery, EQ, etc.)
        # and should NOT be skipped by smart selection.
        "name_patterns": [
            r"razer",
            r"logitech",
            r"corsair",
            r"steelseries",
            r"hyperx",
            r"roccat",
            r"keyboard",
            r"trackpad",
            r"earbud",
            r"headphone",
            r"headset",
            r"jabra",
            r"plantronics",
            r"bose",
            r"sony wh",
            r"sony wf",
            r"sony xm",
            r"jbl",
            r"sennheiser",
            r"meta ray",
            r"rayban",
        ],
        "service_uuids": ["1812"],   # HID over GATT
        "company_ids": [
            0x1532,   # Razer
            0x00D2,   # Logitech
        ],
    },
    "mobile_device": {
        # Phones, tablets, laptops, smartwatches — personal devices that
        # typically lock down GATT and aren't useful enumeration targets.
        # smart selection skips this class.
        "name_patterns": [
            r"\bapple\b",
            r"iphone",
            r"ipad",
            r"macbook",
            r"galaxy\b",
            r"\bpixel\b",
            r"oneplus",
            r"nothing phone",
            r"surface",
            r"apple watch",
            r"galaxy watch",
            r"fitbit",
            r"garmin",
            r"fenix",
            r"forerunner",
            r"vivoactive",
            r"oculus",
            r"quest",
            r"airpod",
            r"beats",
            r"magic mouse",
            r"magic keyboard",
        ],
        "service_uuids": [],
        "company_ids": [
            0x004C,   # Apple
            0x0006,   # Microsoft
            0x0075,   # Samsung
            0x00E0,   # Google
            0x0046,   # Meta/Facebook
        ],
    },
}