from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Target:
    bd_address:             str
    address_type:           str
    adv_type:               str
    name:                   Optional[str]       = None
    manufacturer:           Optional[str]       = None
    company_id:             Optional[int]       = None
    services:               list[str]           = field(default_factory=list)
    tx_power:               Optional[int]       = None
    rssi_samples:           list[int]           = field(default_factory=list)
    rssi_avg:               float               = 0.0
    device_class:           str                 = "unknown"
    connectable:            bool                = False
    first_seen:             datetime            = field(default_factory=datetime.utcnow)
    last_seen:              datetime            = field(default_factory=datetime.utcnow)
    raw_adv_records:        list[bytes]         = field(default_factory=list)
    risk_score:             int                 = 0
    engagement_id:          Optional[str]       = None


@dataclass
class Connection:
    central_addr:               str
    peripheral_addr:            str
    access_address:             int
    crc_init:                   int
    interval_ms:                float
    channel_map:                str
    hop_increment:              int
    encrypted:                  bool                = False
    legacy_pairing_observed:    bool                = False
    pairing_pcap_path:          Optional[str]       = None
    plaintext_data_captured:    bool                = False
    data_pcap_path:             Optional[str]       = None
    timestamp:                  datetime            = field(default_factory=datetime.utcnow)
    engagement_id:              Optional[str]       = None


@dataclass
class GattCharacteristic:
    uuid:               str
    handle:             int
    value_handle:       int
    properties:         list[str]
    requires_auth:      bool        = False
    requires_enc:       bool        = False
    value_hex:          Optional[str] = None
    value_text:         Optional[str] = None


@dataclass
class Finding:
    type:           str
    severity:       str
    target_addr:    str
    description:    str
    remediation:    str
    evidence:       dict            = field(default_factory=dict)
    pcap_path:      Optional[str]  = None
    timestamp:      datetime        = field(default_factory=datetime.utcnow)
    engagement_id:  Optional[str]  = None

    SEVERITIES = ("critical", "high", "medium", "low", "info")

    def __post_init__(self):
        if self.severity not in self.SEVERITIES:
            raise ValueError(f"severity must be one of {self.SEVERITIES}")
