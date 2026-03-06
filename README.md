# Butterfly-RedTeam

Multi-protocol wireless red team framework built on [WHAD](https://github.com/whad-team/whad-client). Runs a structured 19-stage assessment pipeline — BLE, ESB, Logitech Unifying, ZigBee, LoRaWAN, and sub-GHz PHY — with per-stage authorization gates, automatic hardware detection, SQLite findings storage, and Markdown/JSON reporting.

> **Authorization required.** This tool transmits RF packets and connects to wireless devices. Only operate against equipment you own or have written authorization to test.

---

## Hardware Support

| Device | Interface | Protocols |
|--------|-----------|-----------|
| Makerdiary nRF52840 MDK (ButteRFly firmware) | `uart0` | BLE (all modes), ZigBee/802.15.4, ESB (Scanner) |
| RfStorm (nRF24L01+) | `rfstorm0` | ESB Sniffer (all-channel), Logitech Unifying API |
| YARD Stick One | `yardstickone0` | Sub-GHz PHY (300–928 MHz) |

All three devices are auto-detected from `whadup` at startup. Stages are automatically routed to the correct hardware.

---

## Requirements

| Item | Detail |
|------|--------|
| Python | 3.13 (managed with `uv`) |
| WHAD | `pip install whad` — provides all CLI tools and Python connectors |
| Optional | `scapy` for raw PDU probe in Stage 8 |

**WHAD CLI tools used:**
`wble-connect`, `wble-central`, `wble-proxy`, `wble-spawn`, `wplay`, `wanalyze`,
`wsniff`, `winject`, `wuni-scan`, `wuni-keyboard`, `wuni-mouse`, `whadup`

---

## Install

```bash
uv venv && source .venv/bin/activate
uv pip install whad scapy
```

**Linux — USB permissions:**
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**Verify connected hardware:**
```bash
whadup
# Expected output example:
# - uart0
#   Type: ButteRFly
# - rfstorm0
#   Type: RfStorm
# - yardstickone0
#   Type: YardStickOne
```

---

## Usage

```bash
# Auto mode — detects hardware, selects stages by capability
python main.py -n "Engagement1" -l "Building A"

# Explicit stage list
python main.py -n "Engagement1" -l "Building A" --stages 1,2,5,7,8,10,14

# Opt-in stages: 9 (BLE inject), 17 (sub-GHz), 18 (ESB active), 19 (Unifying API)
python main.py -n "Engagement1" -l "Building A" --stages 1,2,5,9,17,18,19

# Specific BLE target only
python main.py -n "Engagement1" -l "Building A" --target AA:BB:CC:DD:EE:FF

# Override hardware interfaces manually
python main.py --interface uart0 --esb-interface rfstorm0 --phy-interface yardstickone0

# Extended BLE scan, skip prompts
python main.py -n "Engagement1" --scan-duration 300 --no-gate

# Debug logging
python main.py -n "Engagement1" --debug
```

---

## Stage Reference

### BLE Stages (uart0 / ButteRFly)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 1 | Environment Mapping | Passive | BLE advertisement scan — discovers targets, classifies devices (access control, medical, industrial, it_gear, sensor), scores risk 0–10. RSSI filter configurable. |
| 2 | Connection Intelligence | Passive | Sniffs CONNECT_IND PDUs; extracts pairing/LTK/IRK/CSRK key material via `wanalyze`; recovers passive GATT profiles from PCAP. |
| 3 | Identity Cloning | Active | Rogue peripheral cloning target BD address and full GATT profile. Write-capture hooks record anything a connecting central writes. Transparent relay via `wble-spawn` (opt-in via `S3_SPAWN_MODE`). |
| 4 | Reactive Jamming | Active | Disrupts BLE advertising/connections via `reactive_jam`. Operator selects target at runtime. |
| 5 | GATT Enumeration | Active | Connects and enumerates full GATT profile; reads Battery, DIS, HeartRate services; exports writable handles and JSON profile to `reports/`. MTU negotiated to 247. |
| 6 | MITM Proxy | Active | Transparent BLE MITM via `wble-proxy`. Requires two RF interfaces (`--proxy-interface`). Always opt-in. |
| 7 | GATT Write Fuzzer | Active | Feeds oversized/malformed payloads to all writable handles; identifies handles that accept arbitrary writes vs those that enforce length/type validation. |
| 8 | Semantic PoC | Active | Targeted GATT writes — device rename (0x2A00, confirmed by read-back), alert trigger (0x2A06), HR control reset (0x2A39), proprietary channel probe (up to 5 unknown chars × 12 probe bytes), raw ATT PDU probe, inline LESC pairing escalation for auth-gated handles. |
| 9 | Packet Injection | Active | ADV flood/replay via `wsniff`+`winject`; InjectaBLE PDU injection into live connections using S2 channel parameters (AA, CRC, hop). Always opt-in. |
| 11 | ZigBee / 802.15.4 | Passive | Scans IEEE 802.15.4 channels 11–26; auto-decrypts traffic; recovers network keys; records PAN IDs. |
| 12 | PHY ISM Survey | Passive | Sweeps 2402–2480 MHz in 2 MHz steps with GFSK; aggregates activity into 5 MHz bands; reports packet count and peak RSSI. |
| 13 | SMP Pairing Scan | Active | Tests 4 pairing modes (LESC/Legacy × Just Works/Bonding); extracts distributed keys from security database; thread-guarded against pairing() hanging indefinitely. Always opt-in. |
| 15 | LoRaWAN Recon | Passive | Listens for JoinRequest (captures DevEUI, AppEUI, DevNonce), DataUp frames. Requires external LoRa radio hardware (not nRF52840). |
| 16 | L2CAP CoC | Info | Documents the L2CAP Connection-Oriented Channel capability gap; records for reporting. |

### ESB / Unifying Stages (rfstorm0 / RfStorm preferred; falls back to uart0)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 10 | Logitech Unifying / MouseJack | Active | Four operator-selected modes: **sniff** (passive scan + keylog + `wanalyze keystroke pairing_cracking` pipeline on PCAP), **inject** (MouseJack text injection with locale), **ducky** (DuckyScript file playback via `wuni-keyboard -d`), **mouse** (scripted move+click or hardware relay via `wuni-mouse -d`). |
| 14 | ESB Raw Scan | Passive | RfStorm: uses `whad.esb.Sniffer(channel=None)` — stable all-channel loop. nRF52840: uses `whad.esb.Scanner` with monkey-patch for kwargs bug. Flags low-entropy (plaintext) payloads. |
| 18 | ESB PRX/PTX Active | Active | **PRX** — listen as Primary Receiver for frames addressed to a device, capture and entropy-check content. **PTX** — `synchronize()` to device channel then `send_data(waiting_ack=True)` to inject unauthenticated frames; ACK confirmation reported. Always opt-in. |
| 19 | Unifying Python API | Active | `whad.unifying.Mouse` and `whad.unifying.Keyboard` connectors. **Mouse** mode: `synchronize()` + move spiral + left click. **Keyboard** mode: `synchronize()` + `send_text()`. **Ducky** mode: full DuckyScript parser (STRING, ENTER, DELAY, modifier keys) via `Keyboard.send_key()`. Always opt-in. |

### Sub-GHz PHY Stage (yardstickone0 / YardStickOne)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 17 | Sub-GHz PHY Survey | Passive | Sweeps 136 frequencies across 300–348 MHz, 391–464 MHz, 782–928 MHz in 2 MHz steps. Aggregates activity into 5 MHz bands; provides protocol context hints (Z-Wave, 433 MHz remotes, LoRa, TPMS). Always opt-in. |

---

## Auto Stage Selection

When `--stages auto` (default), the framework probes hardware capabilities after startup and selects stages automatically:

- **BLE stages** selected by `can_scan`, `can_sniff`, `can_peripheral`, `can_central`, `can_reactive_jam` flags
- **S10 / S14** selected when any connected dongle has `can_unifying` / `can_esb`
- **S17** selected when a YardStickOne is detected
- **S18 / S19** always require explicit opt-in (never auto-selected)
- **S6, S9** always require explicit opt-in

```
Auto-selected stages : 1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 14, 17
```

---

## Key Configuration (`config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `uart0` | Primary BLE dongle |
| `ESB_INTERFACE` | auto | ESB/Unifying dongle (auto-detected rfstorm0) |
| `PHY_SUBGHZ_INTERFACE` | auto | Sub-GHz PHY dongle (auto-detected yardstickone0) |
| `SCAN_DURATION` | 120 | Stage 1 BLE scan seconds |
| `RSSI_MIN_FILTER` | 0 | Ignore devices weaker than N dBm (0 = off) |
| `ACTIVE_GATE` | True | Require `yes` confirmation before active stages |
| `MOUSEJACK_TEXT` | `MouseJack-PoC` | Text injected in S10 keyboard PoC |
| `UNIFYING_LOCALE` | `us` | Keyboard locale for `wuni-keyboard -l` |
| `UNIFYING_DUCKY_SCRIPT` | None | Path to DuckyScript file for S10 ducky / S19 ducky mode |
| `ESB_PRX_TIMEOUT` | 30 | S18 PRX listen window (seconds) |
| `ESB_PTX_PAYLOAD` | `050000000000` | S18 PTX injection payload (hex) |
| `UNIFYING_KBD_TEXT` | `Hello from WHAD` | S19 keyboard injection text |
| `SUBGHZ_SWEEP_SECS` | 120 | S17 total sweep budget |
| `S3_SPAWN_MODE` | False | Use transparent `wble-spawn` relay in S3 instead of static clone |

---

## Output

| Artifact | Location |
|----------|----------|
| SQLite findings DB | `./findings.db` |
| Markdown report | `./reports/report_<eng_id>.md` |
| JSON report | `./reports/report_<eng_id>.json` |
| Per-stage PCAPs | `./pcaps/<eng_id>/s<N>_<addr>.pcap` |
| S5 GATT profiles | `./reports/s5_profile_<addr>_<eng_id>.json` |
| S10 Unifying PCAP | `./pcaps/s10_unifying_<eng_id>_<addr>.pcap` |

---

## Finding Types

| Finding | Severity | Stage |
|---------|----------|-------|
| `gatt_poc` | high/medium/low | 8 |
| `mousejack_keystroke_injection` | critical | 10 |
| `mousejack_ducky_injection` | critical | 10 |
| `mousejack_mouse_injection` | medium | 10 |
| `unifying_device_discovered` | medium | 10 |
| `unifying_keystrokes_captured` | high | 10 |
| `unifying_pairing_key_recovered` | critical | 10 |
| `esb_device_discovered` | info | 14 |
| `esb_unencrypted_traffic` | medium | 14 |
| `esb_prx_frames_captured` | high/medium | 18 |
| `esb_ptx_injection` | critical/high | 18 |
| `unifying_api_mouse_injection` | critical | 19 |
| `unifying_api_keyboard_injection` | critical | 19 |
| `unifying_api_ducky_injection` | critical | 19 |
| `zigbee_network_discovered` | medium | 11 |
| `zigbee_keys_recovered` | high | 11 |
| `phy_rf_activity` | info | 12 |
| `phy_subghz_rf_activity` | info | 17 |
| `smp_pairing_vulnerable` | high/medium | 13 |

---

## Troubleshooting

**`WhadDeviceTimeout` at startup**
The ButteRFly firmware does not re-emit DeviceReady after initial boot, so `reset()` times out. The framework patches `reset()` to a no-op during connector init — this is expected and handled automatically.

**`whadup: command not found`**
Activate the virtual environment: `source .venv/bin/activate`

**`Permission denied: /dev/ttyACM0`** (Linux)
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**Stage 5/7 returns "No characteristics parsed"**
Target may not support the `wble-central profile` command format. Stage 8 self-profiles via the Python WHAD API and will still attempt semantic PoC writes.

**Stage 10 — no Unifying devices found**
`wuni-scan` may exit quickly if no devices are present. The scanner restarts in a loop for the full `UNIFYING_SNIFF_SECS` window. Verify the dongle is rfstorm0 (`whadup`) and devices are actively transmitting.

**Stage 14 — ESB Scanner TypeError on nRF52840**
Known WHAD v1.2.x bug (`whad.esb.Scanner` kwargs mismatch). The framework monkey-patches `Connector.sniff()` to absorb the extra kwargs. For reliable ESB scanning, use an RfStorm dongle (rfstorm0) — it uses `whad.esb.Sniffer` which does not have this bug.

**Stage 18/19 `synchronize()` fails**
Target device must be actively transmitting. Ensure the RfStorm dongle is within range (typically <10 m) and the device is in use (mouse moving, keyboard typing). If using nRF52840 as fallback, synchronize() success is not guaranteed.
