"""
core/vulndb.py — Wireless CVE & vulnerability knowledge base.

Maps discovered services, characteristics, link-layer parameters, and protocol
fingerprints to known CVEs and attack vectors.  This is what makes Butterfly
more powerful than raw WHAD — automated vulnerability intelligence that a
professional pentest requires.

Usage from any stage:
    from core.vulndb import match_ble_service, match_ble_char, match_pairing, ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class VulnMatch:
    """One vulnerability matched against a discovered artifact."""
    cve:         str           # "CVE-2019-9506" or "" if no CVE assigned
    name:        str           # human-friendly attack name
    severity:    str           # critical / high / medium / low / info
    summary:     str           # one-line description
    remediation: str           # actionable fix
    references:  tuple[str, ...] = ()  # URLs / paper titles
    tags:        tuple[str, ...] = ()  # e.g. ("ble", "link-layer", "crypto")


# ── BLE service-level vulnerabilities ─────────────────────────────────────────

_BLE_SERVICE_VULNS: dict[str, list[VulnMatch]] = {
    # HID over GATT — keystroke injection / eavesdropping
    "1812": [
        VulnMatch(
            cve="",
            name="BLE HID Keystroke Injection",
            severity="critical",
            summary="HID-over-GATT service allows keystroke injection if pairing is weak or absent",
            remediation="Require LESC with MITM protection; disable Just Works pairing",
            references=("https://bluetooth.com/specifications/specs/hid-over-gatt-profile-1-0/",),
            tags=("ble", "hid", "injection"),
        ),
    ],
    # Writable Generic Access — device name spoofing
    "1800": [
        VulnMatch(
            cve="",
            name="GAP Device Name Write",
            severity="medium",
            summary="Writable Device Name characteristic (0x2A00) allows impersonation",
            remediation="Set Device Name characteristic to read-only; require authentication for writes",
            references=(),
            tags=("ble", "spoofing"),
        ),
    ],
    # Internet Protocol Support — potential network pivot
    "1820": [
        VulnMatch(
            cve="",
            name="IPSP Network Pivot",
            severity="high",
            summary="IP Support Profile enables IPv6 over BLE — potential lateral movement into IP network",
            remediation="Restrict IPSP to authenticated connections; firewall BLE-to-IP bridge",
            references=("https://bluetooth.com/specifications/specs/internet-protocol-support-profile-1-0/",),
            tags=("ble", "network", "pivot"),
        ),
    ],
    # User Data Service — PII exposure
    "181C": [
        VulnMatch(
            cve="",
            name="User Data PII Exposure",
            severity="high",
            summary="User Data Service exposes personal information (name, age, weight) without authentication",
            remediation="Require encrypted and authenticated connection for User Data Service access",
            references=(),
            tags=("ble", "privacy", "pii"),
        ),
    ],
    # Blood Pressure — medical data exposure
    "1810": [
        VulnMatch(
            cve="",
            name="Blood Pressure Data Exposure",
            severity="high",
            summary="Blood Pressure Service leaks PHI over unauthenticated BLE connection",
            remediation="Require LESC pairing with MITM for all medical data services",
            references=(),
            tags=("ble", "medical", "phi"),
        ),
    ],
    # Heart Rate — medical data exposure
    "180D": [
        VulnMatch(
            cve="",
            name="Heart Rate Data Exposure",
            severity="medium",
            summary="Heart Rate Service readable without authentication — health data leakage",
            remediation="Require authenticated connection for health data services",
            references=(),
            tags=("ble", "medical", "phi"),
        ),
    ],
    # Nordic UART — common IoT debug shell
    "FFF0": [
        VulnMatch(
            cve="",
            name="Nordic UART Debug Shell",
            severity="high",
            summary="Nordic UART Service (0xFFF0) often provides unauthenticated serial console — command injection risk",
            remediation="Remove UART service from production firmware; require authentication if needed for OTA",
            references=(),
            tags=("ble", "iot", "debug", "shell"),
        ),
    ],
    # Alternate Nordic UART UUID
    "6E400001-B5A3-F393-E0A9-E50E24DCCA9E": [
        VulnMatch(
            cve="",
            name="Nordic UART Service (NUS)",
            severity="high",
            summary="Nordic UART Service provides unauthenticated bidirectional serial — command injection risk",
            remediation="Remove NUS from production firmware; require LESC pairing for debug interfaces",
            references=("https://infocenter.nordicsemi.com/topic/sdk_nrf5_v17.1.0/ble_sdk_app_nus_eval.html",),
            tags=("ble", "iot", "debug", "shell"),
        ),
    ],
    # HM-10 Serial — cheap IoT debug
    "FFE0": [
        VulnMatch(
            cve="",
            name="HM-10 Serial Service",
            severity="high",
            summary="HM-10 transparent UART service exposes serial console without authentication",
            remediation="Remove debug serial service from production builds",
            references=(),
            tags=("ble", "iot", "debug", "shell"),
        ),
    ],
}

# ── BLE characteristic-level vulnerabilities ──────────────────────────────────

@dataclass(frozen=True)
class CharVuln:
    """Vulnerability tied to a specific characteristic UUID + property combo."""
    uuid:        str           # 4-char short UUID or full 128-bit
    risky_props: frozenset[str]  # properties that trigger this match (e.g. {"write", "write_no_resp"})
    match:       VulnMatch


_BLE_CHAR_VULNS: list[CharVuln] = [
    # Device Name writable
    CharVuln(
        uuid="2A00",
        risky_props=frozenset({"write", "write_no_resp"}),
        match=VulnMatch(
            cve="",
            name="Writable Device Name",
            severity="medium",
            summary="Device Name (0x2A00) is writable — enables impersonation and social engineering",
            remediation="Make Device Name read-only in GATT server configuration",
            tags=("ble", "spoofing"),
        ),
    ),
    # Alert Level writable — can trigger physical alert
    CharVuln(
        uuid="2A06",
        risky_props=frozenset({"write", "write_no_resp"}),
        match=VulnMatch(
            cve="",
            name="Alert Level Write (Find Me)",
            severity="medium",
            summary="Alert Level (0x2A06) writable without auth — can trigger physical alarm on device",
            remediation="Require authentication for Alert Level writes",
            tags=("ble", "physical"),
        ),
    ),
    # Heart Rate Control Point — energy expended reset
    CharVuln(
        uuid="2A39",
        risky_props=frozenset({"write"}),
        match=VulnMatch(
            cve="",
            name="Heart Rate Control Tampering",
            severity="medium",
            summary="Heart Rate Control Point (0x2A39) writable — can reset energy data on medical device",
            remediation="Require authenticated pairing for control point characteristics",
            tags=("ble", "medical", "tampering"),
        ),
    ),
    # SC Control Point (Cycling) — calibration reset
    CharVuln(
        uuid="2A55",
        risky_props=frozenset({"write", "indicate"}),
        match=VulnMatch(
            cve="",
            name="Sensor Calibration Reset",
            severity="medium",
            summary="SC Control Point (0x2A55) writable — sensor calibration data can be reset",
            remediation="Require authentication for control point access",
            tags=("ble", "tampering"),
        ),
    ),
    # OTA DFU Control Point (Nordic / vendor common)
    CharVuln(
        uuid="2A06",
        risky_props=frozenset({"write"}),
        match=VulnMatch(
            cve="",
            name="OTA DFU without Authentication",
            severity="critical",
            summary="OTA firmware update control point accessible without authentication — RCE via malicious firmware",
            remediation="Require signed firmware images and authenticated DFU connections",
            tags=("ble", "ota", "rce"),
        ),
    ),
]

# Known OTA/DFU characteristic UUIDs (vendor-specific)
_OTA_DFU_UUIDS: frozenset[str] = frozenset({
    "00001530-1212-EFDE-1523-785FEABCD123",  # Nordic Legacy DFU
    "FE59",                                    # Nordic Secure DFU (buttonless)
    "8EC90001-F315-4F60-9FB8-838830DAEA50",  # Nordic Secure DFU Control
    "8EC90002-F315-4F60-9FB8-838830DAEA50",  # Nordic Secure DFU Data
    "F000FFC0-0451-4000-B000-000000000000",  # TI OAD
    "F000FFC1-0451-4000-B000-000000000000",  # TI OAD Image Identify
    "F000FFC2-0451-4000-B000-000000000000",  # TI OAD Image Block
    "1D14D6EE-FD63-4FA1-BFA4-8F47B42119F0",  # Silicon Labs OTA Control
    "984227F3-34FC-4045-A5D0-2C581F81A153",  # Silicon Labs OTA Data
    "00060000-F8CE-11E4-ABF4-0002A5D5C51B",  # Cypress WICED OTA FW Upgrade
    "99564A02-DC01-4D3C-B04E-3BB1EF0571B2",  # Microchip OTAU
})


# ── BLE link-layer / crypto vulnerabilities ───────────────────────────────────

def match_key_size(key_size: int) -> list[VulnMatch]:
    """Flag KNOB attack if negotiated key entropy < 16 bytes."""
    if key_size < 16:
        return [VulnMatch(
            cve="CVE-2019-9506",
            name="KNOB Attack (Key Negotiation of Bluetooth)",
            severity="critical",
            summary=f"Negotiated encryption key size is {key_size} bytes (< 16) — "
                    "attacker can brute-force session key in real time",
            remediation="Enforce minimum 16-byte key size in controller firmware; "
                        "apply vendor patch for CVE-2019-9506",
            references=(
                "https://knobattack.com/",
                "https://nvd.nist.gov/vuln/detail/CVE-2019-9506",
            ),
            tags=("ble", "btclassic", "crypto", "knob"),
        )]
    return []


def match_pairing(*, legacy: bool, just_works: bool, mitm: bool,
                  sc: bool, oob: bool = False) -> list[VulnMatch]:
    """Flag pairing-related CVEs based on observed SMP exchange."""
    vulns: list[VulnMatch] = []

    if legacy and not sc:
        vulns.append(VulnMatch(
            cve="CVE-2020-26558",
            name="Legacy Pairing Passkey Brute-Force",
            severity="high",
            summary="Legacy BLE pairing (no Secure Connections) — passkey can be "
                    "brute-forced via bit-by-bit confirmation attack",
            remediation="Enable LE Secure Connections (LESC) on both devices",
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
                "https://bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
            ),
            tags=("ble", "pairing", "crypto"),
        ))

    if just_works and not mitm:
        vulns.append(VulnMatch(
            cve="CVE-2019-19194",
            name="Just Works MITM (SweynTooth family)",
            severity="high",
            summary="Just Works pairing without MITM protection — attacker can "
                    "intercept and modify pairing exchange",
            remediation="Use Numeric Comparison or Passkey Entry with MITM flag set",
            references=(
                "https://asset-group.github.io/disclosures/sweyntooth/",
                "https://nvd.nist.gov/vuln/detail/CVE-2019-19194",
            ),
            tags=("ble", "pairing", "mitm", "sweyntooth"),
        ))

    if legacy and just_works:
        vulns.append(VulnMatch(
            cve="",
            name="Legacy Just Works — Passive Eavesdropping",
            severity="critical",
            summary="Legacy pairing with Just Works — STK derived from zeros; "
                    "entire session can be decrypted passively",
            remediation="Upgrade to LESC with Numeric Comparison or OOB pairing",
            references=(),
            tags=("ble", "pairing", "crypto", "passive"),
        ))

    if sc and just_works and not mitm:
        vulns.append(VulnMatch(
            cve="CVE-2022-25836",
            name="BLE Passkey/NumComp Method Confusion",
            severity="high",
            summary="LESC Just Works without MITM — vulnerable to method confusion "
                    "attack downgrading Numeric Comparison to Just Works",
            remediation="Set MITM flag in IO capabilities; reject Just Works if "
                        "device supports display+keyboard",
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2022-25836",
            ),
            tags=("ble", "pairing", "method-confusion"),
        ))

    return vulns


def match_reconnection(*, bonded: bool, encrypted: bool) -> list[VulnMatch]:
    """Flag BLESA if reconnection is unencrypted."""
    if bonded and not encrypted:
        return [VulnMatch(
            cve="CVE-2020-9770",
            name="BLESA (BLE Spoofing Attack)",
            severity="high",
            summary="Reconnection to bonded device occurs without re-authentication — "
                    "attacker can spoof the peripheral",
            remediation="Require encryption on reconnection; validate LTK before "
                        "accepting GATT operations",
            references=(
                "https://www.usenix.org/conference/woot20/presentation/wu",
                "https://nvd.nist.gov/vuln/detail/CVE-2020-9770",
            ),
            tags=("ble", "spoofing", "blesa"),
        )]
    return []


# ── SweynTooth link-layer vulns ───────────────────────────────────────────────

SWEYNTOOTH_VULNS: list[VulnMatch] = [
    VulnMatch(
        cve="CVE-2019-19195",
        name="SweynTooth: Truncated L2CAP",
        severity="high",
        summary="Truncated L2CAP fragment causes heap overflow on vulnerable SoCs "
                "(Dialog DA14680, NXP KW41Z, Telink TLSR8258)",
        remediation="Update SoC firmware to patched version; filter malformed L2CAP at gateway",
        references=("https://asset-group.github.io/disclosures/sweyntooth/",),
        tags=("ble", "link-layer", "sweyntooth", "crash"),
    ),
    VulnMatch(
        cve="CVE-2019-19196",
        name="SweynTooth: Zero-Length L2CAP",
        severity="high",
        summary="Zero-length L2CAP PDU crashes BLE stack on vulnerable chipsets",
        remediation="Update SoC firmware; validate L2CAP length > 0 in stack",
        references=("https://asset-group.github.io/disclosures/sweyntooth/",),
        tags=("ble", "link-layer", "sweyntooth", "crash"),
    ),
    VulnMatch(
        cve="CVE-2019-19197",
        name="SweynTooth: Unexpected Public Key",
        severity="critical",
        summary="Sending Public Key during Legacy pairing crashes SoC "
                "(Cypress PSoC 4/6, Dialog DA14585)",
        remediation="Update SoC firmware; reject SMP Public Key in non-LESC mode",
        references=("https://asset-group.github.io/disclosures/sweyntooth/",),
        tags=("ble", "link-layer", "sweyntooth", "crash"),
    ),
    VulnMatch(
        cve="CVE-2019-19199",
        name="SweynTooth: Sequential ATT Deadlock",
        severity="high",
        summary="Rapid sequential ATT requests without waiting for response causes "
                "deadlock / infinite loop (Texas Instruments CC2640R2)",
        remediation="Update SoC firmware; implement ATT request queuing",
        references=("https://asset-group.github.io/disclosures/sweyntooth/",),
        tags=("ble", "link-layer", "sweyntooth", "dos"),
    ),
]


# ── BrakTooth (Bluetooth Classic) ─────────────────────────────────────────────

BRAKTOOTH_VULNS: list[VulnMatch] = [
    VulnMatch(
        cve="CVE-2021-28139",
        name="BrakTooth: Feature Page Execution",
        severity="critical",
        summary="Malformed LMP feature response causes arbitrary code execution "
                "on ESP32 Bluetooth Classic stack",
        remediation="Update ESP-IDF to >= 4.4.1; apply vendor LMP patches",
        references=(
            "https://asset-group.github.io/disclosures/braktooth/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-28139",
        ),
        tags=("btclassic", "lmp", "braktooth", "rce"),
    ),
    VulnMatch(
        cve="CVE-2021-34147",
        name="BrakTooth: LMP Auto Rate Overflow",
        severity="high",
        summary="Oversized LMP_auto_rate PDU causes heap overflow on Intel AX200/201",
        remediation="Apply Intel Bluetooth firmware update",
        references=("https://asset-group.github.io/disclosures/braktooth/",),
        tags=("btclassic", "lmp", "braktooth", "crash"),
    ),
]


# ── BR/EDR service-level vulnerabilities ──────────────────────────────────────

_BTCLASSIC_SERVICE_VULNS: dict[str, list[VulnMatch]] = {
    "0x1101": [  # Serial Port Profile
        VulnMatch(
            cve="",
            name="Unauthenticated SPP Channel",
            severity="high",
            summary="Serial Port Profile (SPP) accessible without authentication — "
                    "arbitrary data exchange with device firmware",
            remediation="Require SSP with MITM; disable SPP in production",
            references=(),
            tags=("btclassic", "spp", "unauth"),
        ),
    ],
    "0x1105": [  # OBEX Object Push
        VulnMatch(
            cve="",
            name="OBEX Push File Transfer",
            severity="high",
            summary="OBEX Object Push allows unauthenticated file transfer to device",
            remediation="Disable OBEX Push; require pairing for file transfers",
            references=(),
            tags=("btclassic", "obex", "file-transfer"),
        ),
    ],
    "0x1115": [  # PAN User (BNEP)
        VulnMatch(
            cve="CVE-2017-0785",
            name="BlueBorne BNEP Information Disclosure",
            severity="high",
            summary="PAN/BNEP service vulnerable to BlueBorne info leak (Android < 8.0, Linux < 4.14)",
            remediation="Update OS/firmware to patch BlueBorne; disable PAN if unused",
            references=(
                "https://www.armis.com/blueborne/",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
            ),
            tags=("btclassic", "blueborne", "bnep"),
        ),
    ],
    "0x1116": [  # PAN NAP
        VulnMatch(
            cve="CVE-2017-0781",
            name="BlueBorne BNEP RCE",
            severity="critical",
            summary="PAN NAP service vulnerable to BlueBorne heap overflow RCE "
                    "(Android < 8.0)",
            remediation="Update Android to >= 8.0; disable Bluetooth PAN service",
            references=(
                "https://www.armis.com/blueborne/",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0781",
            ),
            tags=("btclassic", "blueborne", "rce"),
        ),
    ],
    "0x111F": [  # Handsfree Audio Gateway
        VulnMatch(
            cve="CVE-2017-0782",
            name="BlueBorne L2CAP OOB (Handsfree)",
            severity="high",
            summary="Handsfree AG profile exposes BlueBorne L2CAP out-of-bounds "
                    "write (Android < 8.0)",
            remediation="Update Android; restrict Bluetooth service visibility",
            references=(
                "https://www.armis.com/blueborne/",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
            ),
            tags=("btclassic", "blueborne"),
        ),
    ],
}

_BTCLASSIC_GENERIC_VULNS: list[VulnMatch] = [
    VulnMatch(
        cve="CVE-2020-10135",
        name="BIAS (Bluetooth Impersonation Attack)",
        severity="critical",
        summary="Attacker can impersonate a previously bonded device during secure "
                "connection establishment by role-switching and downgrading auth",
        remediation="Apply vendor firmware patches for BIAS; enforce mutual "
                    "authentication on reconnection",
        references=(
            "https://francozappa.github.io/about-bias/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
        ),
        tags=("btclassic", "bias", "impersonation"),
    ),
    VulnMatch(
        cve="CVE-2020-15802",
        name="BLURtooth (CTKD Downgrade)",
        severity="high",
        summary="Cross-Transport Key Derivation allows BLE attacker to overwrite "
                "BR/EDR keys (or vice versa) — impersonation across transports",
        remediation="Disable CTKD or apply Bluetooth 5.1+ restriction patches",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15802",
            "https://kb.cert.org/vuls/id/589825",
        ),
        tags=("btclassic", "ble", "ctkd", "blurtooth"),
    ),
]


# ── ESB / Unifying / MouseJack vulnerabilities ────────────────────────────────

def match_esb(*, vendor: str = "", encrypted: bool = False,
              hid_keyboard: bool = False) -> list[VulnMatch]:
    """Flag MouseJack / KeySniffer for ESB HID devices."""
    vulns: list[VulnMatch] = []

    if hid_keyboard and not encrypted:
        vulns.append(VulnMatch(
            cve="CVE-2016-10761",
            name="MouseJack Keystroke Injection",
            severity="critical",
            summary="Wireless keyboard transmits HID reports in plaintext over "
                    "2.4 GHz ESB — attacker can inject arbitrary keystrokes",
            remediation="Replace with Bluetooth LE keyboard with LESC; if Unifying, "
                        "update firmware to enforce AES encryption",
            references=(
                "https://www.mousejack.com/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-10761",
            ),
            tags=("esb", "unifying", "mousejack", "injection"),
        ))

    if hid_keyboard and not encrypted:
        vulns.append(VulnMatch(
            cve="CVE-2016-10762",
            name="KeySniffer Passive Eavesdropping",
            severity="critical",
            summary="Unencrypted keyboard HID over 2.4 GHz — all keystrokes "
                    "readable within 100m by passive attacker",
            remediation="Replace keyboard with encrypted model; apply firmware update",
            references=(
                "https://www.keysniffer.net/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-10762",
            ),
            tags=("esb", "keysniffer", "eavesdropping"),
        ))

    if vendor.lower() in ("logitech", "unifying") and not encrypted:
        vulns.append(VulnMatch(
            cve="CVE-2019-13052",
            name="Logitech Unifying Key Extraction",
            severity="high",
            summary="Logitech Unifying receiver firmware allows AES key extraction "
                    "via USB — enables passive decryption of all paired devices",
            remediation="Update Unifying receiver firmware to latest version; "
                        "apply Logitech Bolt migration",
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2019-13052",
                "https://github.com/mame82/munifying",
            ),
            tags=("esb", "unifying", "key-extraction"),
        ))

    return vulns


# ── ZigBee vulnerabilities ────────────────────────────────────────────────────

def match_zigbee(*, default_tc_key: bool = False,
                 unencrypted_transport: bool = False,
                 key_in_plaintext: bool = False) -> list[VulnMatch]:
    """Flag ZigBee-specific weaknesses."""
    vulns: list[VulnMatch] = []

    if default_tc_key:
        vulns.append(VulnMatch(
            cve="",
            name="ZigBee Default Trust Center Key",
            severity="critical",
            summary="Network uses well-known Trust Center key "
                    "(5A6967426565416C6C69616E63653039) — all traffic decryptable",
            remediation="Configure unique Trust Center link key; use Install Code "
                        "based key exchange (ZigBee 3.0)",
            references=(),
            tags=("zigbee", "crypto", "default-key"),
        ))

    if key_in_plaintext:
        vulns.append(VulnMatch(
            cve="CVE-2020-27890",
            name="ZigBee Key Transport Plaintext",
            severity="critical",
            summary="Network key transported in plaintext during device join — "
                    "passive attacker captures network-wide encryption key",
            remediation="Use ZigBee 3.0 Install Code key exchange; disable "
                        "plaintext key transport in coordinator config",
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2020-27890",
            ),
            tags=("zigbee", "crypto", "key-transport"),
        ))

    if unencrypted_transport:
        vulns.append(VulnMatch(
            cve="",
            name="ZigBee Unencrypted Network Traffic",
            severity="high",
            summary="ZigBee network layer frames transmitted without encryption — "
                    "all application data readable",
            remediation="Enable NWK-level encryption on coordinator; rotate network key",
            references=(),
            tags=("zigbee", "crypto", "unencrypted"),
        ))

    return vulns


# ── LoRaWAN vulnerabilities ───────────────────────────────────────────────────

def match_lorawan(*, replay_accepted: bool = False,
                  fcnt_reset: bool = False,
                  abp_device: bool = False) -> list[VulnMatch]:
    """Flag LoRaWAN protocol weaknesses."""
    vulns: list[VulnMatch] = []

    if replay_accepted:
        vulns.append(VulnMatch(
            cve="",
            name="LoRaWAN Join Replay Accepted",
            severity="critical",
            summary="Network server accepted replayed Join Request — DevNonce "
                    "uniqueness not enforced (LoRaWAN 1.0.x vulnerability)",
            remediation="Upgrade to LoRaWAN 1.1; enable DevNonce tracking on "
                        "network server; reject duplicate DevNonces",
            references=(
                "https://doi.org/10.1145/3395351.3399423",
            ),
            tags=("lorawan", "replay", "join"),
        ))

    if fcnt_reset:
        vulns.append(VulnMatch(
            cve="",
            name="LoRaWAN Frame Counter Reset",
            severity="high",
            summary="Device frame counter restarted from low value — indicates "
                    "either device reboot without NVM or ABP provisioning; "
                    "enables replay of older frames",
            remediation="Use OTAA instead of ABP; persist frame counters in NVM; "
                        "enforce monotonic FCnt on server",
            references=(),
            tags=("lorawan", "fcnt", "replay"),
        ))

    if abp_device:
        vulns.append(VulnMatch(
            cve="",
            name="LoRaWAN ABP Provisioning",
            severity="medium",
            summary="Device uses ABP (Activation by Personalization) — static "
                    "session keys never rotate; replay and eavesdropping risk",
            remediation="Migrate to OTAA provisioning for automatic key rotation",
            references=(),
            tags=("lorawan", "abp", "static-keys"),
        ))

    return vulns


# ── Sub-GHz vulnerabilities ───────────────────────────────────────────────────

def match_subghz(*, fixed_code: bool = False,
                 protocol: str = "") -> list[VulnMatch]:
    """Flag sub-GHz replay and brute-force vulnerabilities."""
    vulns: list[VulnMatch] = []

    if fixed_code:
        vulns.append(VulnMatch(
            cve="",
            name="Fixed-Code Replay Attack",
            severity="critical",
            summary=f"Device uses fixed OOK code ({protocol or 'unknown'} protocol) — "
                    "captured transmission can be replayed indefinitely",
            remediation="Replace with rolling-code or challenge-response system; "
                        "consider KeeLoq or AES-based fob replacement",
            references=(),
            tags=("subghz", "replay", "fixed-code"),
        ))

    proto_lower = protocol.lower()
    if proto_lower in ("pt2262", "pt2264", "ev1527", "ht6p20b"):
        vulns.append(VulnMatch(
            cve="",
            name=f"{protocol} Brute-Force Vulnerability",
            severity="high",
            summary=f"{protocol} encoder uses {12 if 'pt2262' in proto_lower else 20}-bit "
                    "address space — De Bruijn sequence covers all codes in one burst",
            remediation="Replace with rolling-code system; PT2262 has no cryptographic protection",
            references=(),
            tags=("subghz", "brute-force", protocol.lower()),
        ))

    return vulns


# ── Lookup helpers for stage integration ──────────────────────────────────────

def match_ble_service(uuid_short: str) -> list[VulnMatch]:
    """Match a BLE service UUID (4-char hex or full 128-bit) to known vulns."""
    key = uuid_short.upper().replace("0X", "")
    return list(_BLE_SERVICE_VULNS.get(key, []))


def match_ble_char(uuid_short: str, properties: Sequence[str]) -> list[VulnMatch]:
    """Match a characteristic UUID + properties to known vulns."""
    key = uuid_short.upper().replace("0X", "")
    props_set = frozenset(p.lower().replace(" ", "_") for p in properties)
    matches: list[VulnMatch] = []

    for cv in _BLE_CHAR_VULNS:
        if cv.uuid.upper() == key and cv.risky_props & props_set:
            matches.append(cv.match)

    # Check for OTA/DFU characteristics
    full_uuid = uuid_short.upper()
    if full_uuid in _OTA_DFU_UUIDS or key in _OTA_DFU_UUIDS:
        if props_set & {"write", "write_no_resp"}:
            matches.append(VulnMatch(
                cve="",
                name="OTA/DFU Without Authentication",
                severity="critical",
                summary=f"OTA firmware update characteristic ({key}) writable — "
                        "arbitrary firmware upload possible",
                remediation="Require signed firmware; authenticate DFU connections",
                references=(),
                tags=("ble", "ota", "dfu", "rce"),
            ))

    return matches


def match_btclassic_service(uuid_hex: str) -> list[VulnMatch]:
    """Match a BR/EDR SDP service UUID to known vulns."""
    key = uuid_hex if uuid_hex.startswith("0x") else f"0x{uuid_hex}"
    return list(_BTCLASSIC_SERVICE_VULNS.get(key, []))


def get_btclassic_generic_vulns() -> list[VulnMatch]:
    """Return generic BR/EDR CVEs that apply to all discoverable devices."""
    return list(_BTCLASSIC_GENERIC_VULNS)


def get_sweyntooth_vulns() -> list[VulnMatch]:
    """Return SweynTooth family for link-layer fuzz testing."""
    return list(SWEYNTOOTH_VULNS)


def get_braktooth_vulns() -> list[VulnMatch]:
    """Return BrakTooth family for Bluetooth Classic testing."""
    return list(BRAKTOOTH_VULNS)


# ── Smart fuzz payloads per vulnerability class ───────────────────────────────

def get_vuln_fuzz_payloads(uuid_short: str) -> list[tuple[str, bytes]]:
    """Return targeted fuzz payloads for a characteristic UUID.

    Returns list of (label, payload) tuples designed to trigger known
    vulnerability classes rather than generic fuzzing.
    """
    key = uuid_short.upper().replace("0X", "")
    payloads: list[tuple[str, bytes]] = []

    # SweynTooth: truncated / zero-length L2CAP
    payloads.append(("sweyntooth_zero_l2cap", b""))
    payloads.append(("sweyntooth_truncated_l2cap", b"\x01"))
    payloads.append(("sweyntooth_short_att", b"\x02\x00"))

    # Oversized ATT (CVE-2019-19195)
    payloads.append(("sweyntooth_oversize_att", b"\x00" * 255))

    # ATT protocol confusion — wrong opcode for context
    payloads.append(("att_invalid_opcode", bytes([0x7F])))
    payloads.append(("att_reserved_opcode", bytes([0x40, 0x00, 0x00])))

    # Type confusion based on UUID
    if key == "2A00":  # Device Name
        payloads.append(("name_overflow_64", b"A" * 64))
        payloads.append(("name_overflow_248", b"A" * 248))  # BT spec max
        payloads.append(("name_null_interior", b"Test\x00Hidden"))
        payloads.append(("name_utf8_overlong", b"\xc0\xaf"))
    elif key == "2A06":  # Alert Level
        payloads.append(("alert_invalid_high", bytes([0x03])))  # > max valid
        payloads.append(("alert_negative", bytes([0xFF])))
        payloads.append(("alert_oversized", bytes([0x02, 0x02, 0x02])))
    elif key in ("2A39", "2A55"):  # Control Points
        payloads.append(("ctrl_reserved_opcode", bytes([0xFF])))
        payloads.append(("ctrl_oversized_param", bytes([0x01]) + b"\x00" * 50))
    elif key.startswith("FFF") or key.startswith("FFE"):  # UART/custom
        payloads.append(("uart_at_probe", b"AT\r\n"))
        payloads.append(("uart_shell_probe", b"\r\nhelp\r\n"))
        payloads.append(("uart_root_probe", b"root\r\n"))
        payloads.append(("uart_fmt_string", b"%s%s%s%n%n%n"))
        payloads.append(("uart_newline_injection", b"cmd\r\n; id\r\n"))
        payloads.append(("uart_null_term", b"\x00" * 20))

    # DFU-specific payloads
    full_uuid = uuid_short.upper()
    if full_uuid in _OTA_DFU_UUIDS or key in {"FE59"}:
        payloads.append(("dfu_start_cmd", bytes([0x01])))
        payloads.append(("dfu_init_pkt", bytes([0x02, 0x00])))
        payloads.append(("dfu_fake_image_header", bytes([0x03]) + b"\x00" * 12))
        payloads.append(("dfu_oversized_init", bytes([0x02]) + b"\xFF" * 100))

    return payloads
