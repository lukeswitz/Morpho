<div align="center">
<img width="500" alt="rubywaves" src="https://github.com/user-attachments/assets/2560fdc5-341a-4fdb-8160-73fb4ed4f6ac" />

Multi-protocol wireless red team framework built on [WHAD](https://github.com/whad-team/whad-client). Runs a structured 23-stage assessment pipeline — BLE, ESB, Logitech Unifying, ZigBee, LoRaWAN, sub-GHz PHY, Bluetooth Classic, RF4CE, and raw 802.15.4 — with per-stage authorization gates, automatic hardware detection, SQLite findings storage, and Markdown/JSON reporting.
</div>

> [!IMPORTANT]
> **Authorization required.** This tool transmits RF packets and connects to wireless devices. Only operate against equipment you own or have written authorization to test.

---

## Terminal UI

Butterfly ships a full Textual-based TUI. The classic CLI mode remains available for headless/SSH use; the TUI is the default when launched interactively.

### Launch Screen

A BBS-style configuration form fills every parameter before execution starts — engagement name, location, hardware interfaces, scan duration, and per-stage selection with opt-in stages clearly marked.

```
┌─────────────────────────────────────────────────────────────────────┐
│  ████  ██ ██ ████  ██ ██ ██     ██  ███  ██ ██ █████  ████          │
│  ██▄█▄ ██ ██ ██▄██ ▀███▀ ██ ▄█▄ ██ ██▀██ ██▄██ ██▄██ ██▄▄           │
│  ██ ██ ▀███▀ ██▄█▀   █    ▀██▀██▀  ██▀██  ▀█▀  ██▄▄▄ ▄▄██▀          │
│                                                                     │
│  Engagement Name: ____________   Location: ____________             │
│  BLE Interface:   uart0          Scan Duration (s): 120             │
│  ESB Interface:   rfstorm0       PHY Interface: yardstickone0       │
│  Ubertooth:       ubertooth0                                        │
│                                                                     │
│  [ ] *S04 reactive jam    [ ] *S06 mitm proxy    [x] S01 env map    │
│  [x]  S02 conn intel      [x]  S05 gatt shell    [x] S07 fuzzer     │
│  ... (all 23 stages, opt-in marked with *)                          │
│                                                                     │
│               [ LAUNCH ENGAGEMENT ]                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Dashboard Screen

Three-panel live view active during stage execution:

```
┌──────────────────┬──────────────────────────────────┬──────────────────────┐
│  STAGE LIST      │  LOG PANE                        │  TARGET TABLE        │
│                  │                                  │                      │
│  S01  COMPLETE   │  S01 PASSIVE Environment Map     │  ADDRESS  CLASS RSSI │
│  S02  COMPLETE   │  12:34:01 [INFO] 14 targets...   │  AA:BB..  med   -62  │
│  S03  RUNNING    │  12:34:12 [INFO] cloning...      │  CC:DD..  acc   -48  │
│  S04  SKIPPED    │  12:34:15 [WARN] no response     │  EE:FF..  unk   -71  │
│  S05  PENDING    │                                  │                      │
│  ...             │                                  │  findings: 3         │
├──────────────────┴──────────────────────────────────┴──────────────────────┤
│  prompt> _                                                                 │
└────────────────────────────────────────────────────────────────────────────┘
```

**Dashboard keyboard bindings:**

| Key | Action |
|-----|--------|
| `Ctrl+C` | Abort run — unblocks any pending prompt and exits |
| `Ctrl+X` | Skip current stage — unblocks any pending prompt with a graceful skip value and advances to the next stage |
| `Ctrl+L` | Toggle log pane visibility |
| `Ctrl+R` | Toggle redaction — replaces all MACs and device names with placeholders in both log and target table (for screen-sharing / demos) |

### Active Gate Modal

Every opt-in stage raises a full-screen confirmation modal before any RF transmission. The operator must explicitly choose one of three actions — there is no default.

```
  ╔════════════════════════════════════════╗
  ║   ACTIVE STAGE 06 GATE                 ║
  ║                                        ║
  ║   MITM BLE Proxy (Stage 6)             ║
  ║                                        ║
  ║   This stage will transmit RF packets. ║
  ║   Only proceed on authorized targets.  ║
  ║                                        ║
  ║  [ YES — proceed ] [SKIP] [ABORT run]  ║
  ╚════════════════════════════════════════╝
```

### Target Selection Modal

Stages that require target selection present a DataTable sorted by risk score with the same selection grammar as the CLI: numbers (`1,3`), `all`, `smart`, or `skip`. `smart` automatically excludes low-value device classes.

### GATT Shell Screen

After Stage 5 enumeration or a Stage 20 hijack, the TUI switches to a dedicated GATT shell screen with a persistent prompt, timestamped colored output, and immediate re-focus after each command.

```
  // GATT SHELL  //  AA:BB:CC:DD:EE:FF  //  type 'help'  //  Ctrl+C to exit
  ──────────────────────────────────────────────────────────────────────────
  [12:45:01]  SESSION  AA:BB:CC:DD:EE:FF
  [12:45:02]  read 0x0003  →  42 75 74 74 65 72 66 6C 79
  gatt://AA:BB:CC:DD:EE:FF> _
```

| Key | Action |
|-----|--------|
| `Ctrl+C` | Send `quit` — disconnect and return to dashboard |
| `Ctrl+L` | Clear shell log |

---

## Hardware Support

| Device | Interface | Protocols |
|--------|-----------|-----------|
| Makerdiary nRF52840 MDK (ButteRFly firmware) | `uart0` | BLE (all modes), ZigBee/802.15.4, ESB (Scanner) |
| RfStorm (nRF24L01+) | `rfstorm0` | ESB Sniffer (all-channel), Logitech Unifying API |
| YARD Stick One | `yardstickone0` | Sub-GHz PHY (300–928 MHz) |
| Ubertooth One | `ubertooth0` | Passive BLE sniffer (supplementary S1/S2 range) |

All devices are auto-detected from `whadup` at startup. Stages are automatically routed to the best available hardware. **The framework runs with any subset of hardware connected** — missing devices produce warnings and skip the relevant stages rather than aborting.

---

## Requirements

| Item | Detail |
|------|--------|
| Python | 3.10+ |
| WHAD | `whad>=1.2.13` — all CLI tools and Python connectors |
| Textual | `textual==0.89.0` — TUI framework |
| Optional | `scapy>=2.5.0` for raw PDU probe in Stage 8 |
| Optional | `hcitool`, `sdptool` for Stage 21 BR/EDR scan |
| Optional | `ubertooth-br`, `ubertooth-rx` for Stage 21 piconet sniff |

**WHAD CLI tools used:**
`wble-connect`, `wble-central`, `wble-proxy`, `wble-spawn`, `wplay`, `wanalyze`,
`wsniff`, `winject`, `wuni-scan`, `wuni-keyboard`, `wuni-mouse`, `whadup`

---

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
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
# - ubertooth0
#   Type: UbertoothOne
```

**Manufacturer data files (optional, in repo root):**

| File | Source | Entries |
|------|--------|---------|
| `oui.csv` | [IEEE MA-L registry](https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries) | ~35,000 OUI → vendor name mappings |
| `company_identifiers.yaml` | [Bluetooth SIG assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/) | 7,200+ company ID → company name mappings |

Both files are loaded at import time. If absent, OUI and company ID lookups are silently skipped — classification still works from name patterns and service UUIDs.

---

## Usage

```bash
# TUI mode (default) — interactive form before launch
python rubywaves.py

# TUI with pre-filled fields
python rubywaves.py -n "Engagement1" -l "Building A"

# CLI mode — explicit stage list, no TUI
python rubywaves.py -n "Engagement1" -l "Building A" --stages 1,2,5,7,8,10,14

# Enable all opt-in stages at once (4=jam, 6=proxy, 9=inject, 16=L2CAP,
#   17=sub-GHz, 18=ESB active, 19=Unifying API, 20=hijack, 22=RF4CE) — each
#   still requires operator confirmation at the active-gate prompt
python rubywaves.py -n "Engagement1" -l "Building A" --opt-in

# Specific BLE target only
python rubywaves.py -n "Engagement1" -l "Building A" --target AA:BB:CC:DD:EE:FF

# Override hardware interfaces manually
python rubywaves.py --interface uart0 --esb-interface rfstorm0 \
               --phy-interface yardstickone0 --ubertooth-interface ubertooth0

# ESB/sub-GHz only (no BLE dongle connected)
python rubywaves.py -n "Engagement1" --stages 10,14,17

# Extended BLE scan, skip prompts
python rubywaves.py -n "Engagement1" --scan-duration 300 --no-gate

# Debug logging
python rubywaves.py -n "Engagement1" --debug
```

---

## Stage Reference

### BLE Stages (uart0 / ButteRFly)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 1 | Environment Mapping | Passive | BLE advertisement scan — discovers targets, classifies devices (access control, medical, industrial, it_gear, sensor), scores risk 0–10. Ubertooth One supplements scan range in a parallel thread when connected. |
| 2 | Connection Intelligence | Passive | Sniffs CONNECT_IND PDUs; extracts pairing/LTK/IRK/CSRK key material via `wanalyze`; recovers passive GATT profiles from PCAP. |
| 3 | Identity Cloning | Active | Rogue peripheral cloning target BD address and full GATT profile. Write-capture hooks record anything a connecting central writes. Transparent relay via `wble-spawn` (opt-in via `S3_SPAWN_MODE`). |
| 4 | Reactive Jamming | Active | Disrupts BLE advertising/connections via `reactive_jam`. Operator selects target at runtime. **Always opt-in** — requires `--opt-in` or explicit `--stages 4`. |
| 5 | GATT Enumeration + Shell | Active | Connects and enumerates full GATT profile; reads Battery, DIS, HeartRate services; exports writable handles and JSON profile to `reports/`. MTU negotiated to 247. After enumeration, operator is offered an **interactive GATT shell** (see below). |
| 6 | MITM Proxy | Active | Transparent BLE MITM via `wble-proxy`. Optional `--link-layer` mode intercepts all L2CAP PDUs (SMP, ATT, signalling) — invisible to GATT-only monitors. Requires two RF interfaces (`--proxy-interface`). Always opt-in. |
| 7 | GATT Write Fuzzer | Active | Feeds oversized/malformed payloads to all writable handles; identifies handles that accept arbitrary writes vs those that enforce length/type validation. |
| 8 | Semantic PoC | Active | Targeted GATT writes — operator-specified device rename written to 0x2A00 (confirmed by read-back), alert trigger (0x2A06), HR control reset (0x2A39), proprietary channel probe (up to 5 unknown chars × 12 probe bytes), raw ATT PDU probe, inline LESC pairing escalation for auth-gated handles. |
| 9 | Packet Injection | Active | Runtime mode prompt: **[A]** ADV flood/replay via `wsniff`+`winject` (scan DoS / advertisement cache poisoning); **[I]** InjectaBLE PDU injection into a live connection using S2 channel parameters (AA, CRC, hop) — if no S2 data exists, a live capture is offered before injection proceeds. Always opt-in. |
| 11 | ZigBee / 802.15.4 | Passive/Active | Runtime mode prompt: **[P]** Passive — energy-detect channel survey across 11–26 then targeted sniff on active channels; `discover_networks()` extracts PAN IDs and coordinator addresses; auto-decrypts, recovers network keys. **[C]** Coordinator — `start_network()`/`network_formation()` creates rogue PAN, broadcasts beacon, opens join window; devices that join without install-code enforcement reveal key material. **[E]** EndDevice — joins a real PAN via `end_device.send()`, streams group traffic to prove open association. |
| 12 | PHY ISM Survey | Passive | Sweeps 2402–2480 MHz in 2 MHz steps with GFSK; aggregates activity into 5 MHz bands; reports packet count and peak RSSI. **LoRa scan** — probes 433/868/915 MHz with SF7, SF9, and SF12 spreading factors to detect LoRa activity without a dedicated LoRa radio. |
| 13 | SMP Pairing Scan | Active | Tests 4 pairing modes (LESC/Legacy × Just Works/Bonding); extracts distributed keys from security database; thread-guarded against pairing() hanging indefinitely. |
| 15 | LoRaWAN Recon | Passive | Python `_python_lorawan_sniff()` via `whad.lorawan.LWGateway` + sniff callbacks captures JoinRequest (DevEUI, AppEUI, DevNonce) and DataUp frames before falling back to CLI. Tests DevNonce replay. Requires external LoRa radio hardware (not nRF52840). |
| 16 | L2CAP CoC | Active | Tests LE L2CAP Connection-Oriented Channels via Linux `AF_BLUETOOTH` sockets. Probes PSMs 0x0023–0x00FF for unauthenticated open channels; fuzzes accepted channels with malformed/oversized SDUs to detect buffer overflows. Prompts for target BD address at runtime. **Always opt-in.** |
| 20 | BLE Connection Hijacker | Active | **InjectaBLE technique** — synchronises to a live BLE connection captured in S2 (Access Address, CRC init, channel map, hop parameters), evicts the legitimate Central via `LL_TERMINATE`, and takes over as Central. On successful hijack, opens an inline GATT shell against the hijacked peripheral. Requires `can_reactive_jam`. Always opt-in. |

#### Interactive GATT Shell (Stage 5 / Stage 20 post-hijack)

After GATT enumeration (S5) or a successful hijack (S20), an embedded shell lets you interact with the connected peripheral without leaving the framework. In TUI mode, this opens as a dedicated screen. In CLI mode, it runs in the terminal.

| Command | Description |
|---------|-------------|
| `read <handle>` | ATT Read Request, hex output |
| `write <handle> <hex>` | ATT Write Request |
| `wnr <handle> <hex>` | Write then read-back for confirmation |
| `sub <handle>` | Enable notifications on characteristic |
| `unsub <handle>` | Disable notifications |
| `notify <handle>` | Harvest one notification value |
| `info` | Print full GATT profile table |
| `connupdate <ms> [lat] [to_ms]` | LL Connection Parameter Update (stress/timing test) |
| `whack` | Oscillate interval 7.5 ms ↔ 4000 ms × 5 rounds (connection stress) |
| `pyshell` | Drop to Python REPL with `central`, `periph_dev`, `target` in scope |
| `quit` | Disconnect and exit shell |

### ESB / Unifying Stages (rfstorm0 / RfStorm preferred; falls back to uart0)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 10 | Logitech Unifying / MouseJack | Active | Four operator-selected modes: **sniff** (Python `whad.unifying.Sniffer` pre-flight for 10 s, then passive scan + keylog + `wanalyze keystroke pairing_cracking` pipeline on PCAP), **inject** (MouseJack text injection with locale), **ducky** (DuckyScript file playback via `wuni-keyboard -d`), **mouse** (scripted move+click or hardware relay via `wuni-mouse -d`). Python mouselog pre-flight runs before CLI in sniff mode. |
| 14 | ESB Raw Scan | Passive | RfStorm: uses `whad.esb.Sniffer(channel=None)` — stable all-channel loop. nRF52840: uses `whad.esb.Scanner` with monkey-patch for kwargs bug. Flags low-entropy (plaintext) payloads. Concurrent scanning threads for improved channel coverage. |
| 18 | ESB PRX/PTX Active | Active | **PRX** — listen as Primary Receiver for frames addressed to a device; `prepare_acknowledgment()` arms a reply payload in the PRX stream loop; capture and entropy-check content. **PTX** — `synchronize()` to device channel then `send_data(waiting_ack=True)` to inject unauthenticated frames; ACK confirmation reported. Always opt-in. |
| 19 | Unifying Python API | Active | `whad.unifying.Mouse` and `whad.unifying.Keyboard` connectors. Sub-modes: **Dongle** (raw `whad.unifying.Dongle` enumeration) and **Injector** (low-level `whad.unifying.Injector`). **Mouse** mode: `synchronize()` + move spiral + left click. **Keyboard** mode: `synchronize()` + `send_text()`; exposes `keyboard.key` and `aes_counter` introspection. **Ducky** mode: full DuckyScript parser (STRING, ENTER, DELAY, modifier keys, volume tokens VOLUMEUP/VOLUMEDOWN/MUTE) via `Keyboard.send_key()`. Always opt-in. |

### Raw 802.15.4 / RF4CE Stages (uart0 / ButteRFly)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 22 | RF4CE Recon | Passive | Scans IEEE 802.15.4 channels 15, 20, and 25 (RF4CE band plan) using `whad.rf4ce` if available, falling back to raw `whad.dot15d4`. Identifies remote control / set-top-box pairing frames; records node addresses and PAN IDs. **Always opt-in.** |
| 23 | Raw 802.15.4 Survey | Passive | Full 16-channel (11–26) raw 802.15.4 scan using `whad.dot15d4`. Protocol classifier tags each frame as ZigBee, Thread, WirelessHART, RF4CE, or Unknown based on frame fields. Reports per-channel activity, frame counts, and unique source addresses. Auto-selected whenever S11 (ZigBee) is selected. |

### Sub-GHz PHY Stage (yardstickone0 / YardStickOne)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 17 | Sub-GHz PHY Survey | Passive | GFSK sweep of 136 frequencies across 300–348 MHz, 391–464 MHz, 782–928 MHz in 2 MHz steps; aggregates into 5 MHz bands with protocol hints (Z-Wave, 433 MHz remotes, LoRa, TPMS). OOK/ASK second pass at [315, 433, 434, 868, 915] MHz for garage doors, alarms, keyfobs. Always opt-in. |

### Bluetooth Classic Stage (hcitool / Ubertooth One)

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 21 | BR/EDR Scout | Passive/Active | `hcitool inquiry` to discover BR/EDR devices; `sdptool browse --xml` enumerates exposed services; flags risky profiles (SPP, OBEX Push/FTP, BNEP/PAN). Ubertooth One passive piconet sniff via `ubertooth-br` / `ubertooth-rx`. Auto-selected when HCI adapter or Ubertooth is present. |

---

## Auto Stage Selection

When `--stages auto` (default), the framework probes hardware capabilities after startup and selects stages automatically:

- **BLE stages** 1, 2, 3, 5, 7, 8, 13 selected by `can_scan`, `can_sniff`, `can_peripheral`, `can_central` flags
- **S10 / S14** selected when any connected dongle has `can_unifying` / `can_esb`
- **S11 / S12 / S15** selected by `can_zigbee`, `can_phy`, `can_lorawan`
- **S23** auto-selected whenever S11 is selected (`can_zigbee`)
- **S17** auto-selected when a YardStickOne is detected; also included in `--opt-in` for explicit stage lists without hardware
- **S21** selected when an HCI adapter or Ubertooth One is detected
- **Opt-in stages** (4, 6, 9, 16, 18, 19, 20, 22) are **never auto-selected** — use `--opt-in` or explicit `--stages N`

```
# Full hardware (ButteRFly + rfstorm0 + yardstickone0 + ubertooth0):
Auto-selected stages : 1, 2, 3, 5, 7, 8, 10, 11, 12, 13, 14, 17, 21, 23

# With --opt-in:
Auto-selected stages : 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23
```

In TUI mode, the LaunchScreen pre-checks matching boxes based on the same logic. The operator can override any selection before launch.

---

## Device Classification

Stage 1 classifies every discovered device using a three-source lookup chain:

```
BD Address OUI                  Device Name / Manufacturer Name       BLE Services
     │                                      │                               │
     ▼                                      ▼                               ▼
oui.csv lookup             name_patterns regex match              service_uuids match
(IEEE MA-L registry)       (checked against both t.name           (discovered from
→ t.manufacturer             and t.manufacturer)                   GATT enumeration)
```

**Manufacturer resolution order (for t.manufacturer field):**

| Priority | Source | Coverage |
|----------|--------|----------|
| 1 | OUI lookup via `oui.csv` | Public-address devices — maps first 3 MAC bytes to registered IEEE vendor |
| 2 | SIG company ID via `company_identifiers.yaml` | Manufacturer-specific AD record company ID → registered company name |
| 3 | `config.COMPANY_IDS` hardcoded dict | Supplemental / override entries when YAML is absent |

**Device classes and their matching rules:**

| Class | Matched By |
|-------|-----------|
| `access_control` | Name patterns: lock, keypad, badge, door, entry; service UUIDs: access control profiles |
| `medical` | Name patterns: glucose, pulse ox, weight scale, thermometer; service UUIDs: HRS, BLS, GLS |
| `industrial` | Name patterns: PLC, sensor, gateway, HVAC; manufacturer patterns from industrial OUIs |
| `smart_home` | Name patterns: bulb, plug, thermostat, hub, sensor; common smart home OUI vendors |
| `mobile_device` | Name patterns: iPhone, iPad, MacBook, Galaxy, Pixel; manufacturer: Apple Inc, Samsung, Google (via OUI) |
| `peripheral` | Name patterns: keyboard, mouse, headset, controller, speaker; manufacturer patterns |
| `it_gear` | Name patterns: router, AP, switch, NIC, dongle |
| `sensor` | Name patterns: beacon, tag, tracker, temperature, humidity |

Classification priority: **name pattern → manufacturer pattern → service UUID**. Unmatched devices are tagged `unknown`.

Risk scores (0–10) factor in: device class, connectable flag, address type (public = +1), RSSI proximity, and high-value name hits (+3). Devices scoring ≥ 8 are marked CRIT in the TUI target selection modal.

---

## Key Configuration (`config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `uart0` | Primary BLE dongle |
| `ESB_INTERFACE` | auto | ESB/Unifying dongle (auto-detected rfstorm0) |
| `PHY_SUBGHZ_INTERFACE` | auto | Sub-GHz PHY dongle (auto-detected yardstickone0) |
| `UBERTOOTH_INTERFACE` | auto | Passive BLE sniffer (auto-detected ubertooth0) |
| `PROXY_INTERFACE` | `hci0` | Second interface for S6 MITM proxy |
| `SCAN_DURATION` | 120 | Stage 1 BLE scan seconds |
| `RSSI_MIN_FILTER` | 0 | Ignore devices weaker than N dBm (0 = off) |
| `ACTIVE_GATE` | True | Require confirmation before active stages |
| `VERBOSE_MODE` | False | Print WHAD narration lines — useful for training/classroom demos |
| `UNIFYING_LOCALE` | `us` | Keyboard locale for `wuni-keyboard -l` |
| `UNIFYING_DUCKY_SCRIPT` | None | Path to DuckyScript file for S10 ducky / S19 ducky mode |
| `UNIFYING_KBD_TEXT` | `Hello from WHAD` | S19 keyboard injection text |
| `ESB_PRX_TIMEOUT` | 30 | S18 PRX listen window (seconds) |
| `ESB_PTX_PAYLOAD` | `050000000000` | S18 PTX injection payload (hex) |
| `SUBGHZ_SWEEP_SECS` | 120 | S17 total sweep budget |
| `SUBGHZ_PER_FREQ_SECS` | 2 | S17 dwell time per frequency |
| `LORAWAN_REGION` | `EU868` | S15 LoRaWAN regional plan (`EU868` or `US915`) |
| `ZIGBEE_COORD_SECS` | 60 | S11 coordinator join window (seconds) |
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
| `ble_connection_hijacked` | critical | 20 |
| `ble_hijack_attempted` | info | 20 |
| `mitm_proxy` | critical/high/medium | 6 |
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
| `zigbee_coordinator_join` | high | 11 |
| `zigbee_enddevice_joined` | critical | 11 |
| `zigbee_enddevice_rejected` | info | 11 |
| `phy_rf_activity` | info | 12 |
| `l2cap_coc_open_psm` | critical/high | 16 |
| `phy_subghz_rf_activity` | info | 17 |
| `phy_subghz_ook_activity` | info | 17 |
| `esb_replay_accepted` | critical/high | 18 |
| `smp_pairing_vulnerable` | high/medium | 13 |
| `lorawan_fcnt_anomaly` | medium | 15 |
| `btc_device_found` | info | 21 |
| `btc_exposed_services` | medium | 21 |
| `btc_weak_security_mode` | high | 21 |
| `btc_piconet_sniffed` | high | 21 |
| `rf4ce_device_discovered` | medium | 22 |
| `rf4ce_pairing_frame` | high | 22 |
| `dot15d4_rf_activity` | info | 23 |
| `dot15d4_protocol_classified` | info | 23 |

---

## Troubleshooting

**`WhadDeviceTimeout` at startup**
The ButteRFly firmware does not re-emit DeviceReady after initial boot, so `reset()` times out. The framework patches `reset()` to a no-op and injects a synthetic DeviceInfo during connector init — this is expected and handled automatically.

**`whadup: command not found`**
Activate the virtual environment: `source .venv/bin/activate`

**`Permission denied: /dev/ttyACM0`** (Linux)
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**No BLE dongle — only rfstorm0 / yardstickone0 connected**
The framework detects all available hardware. BLE stages (1–9, 11–13, 15–16) are skipped with a warning; ESB/sub-GHz stages run normally. Connect a ButteRFly or use `--interface` if the BLE dongle is on a different port.

**TUI rendering issues over SSH**
Ensure the remote terminal is set correctly: `export TERM=xterm-256color`. Textual requires a 256-color terminal. For low-bandwidth sessions, use `python rubywaves.py --stages 1,2,5 --no-gate` to bypass the TUI and run CLI mode directly.

**Stage 5/7 returns "No characteristics parsed"**
Target may not support the `wble-central profile` command format. Stage 8 self-profiles via the Python WHAD API and will still attempt semantic PoC writes.

**Stage 10 — no Unifying devices found**
`wuni-scan` may exit quickly if no devices are present. The scanner restarts in a loop for the full `UNIFYING_SNIFF_SECS` window. Verify the dongle is rfstorm0 (`whadup`) and devices are actively transmitting.

**Stage 14 — ESB Scanner TypeError on nRF52840**
Known WHAD v1.2.x bug (`whad.esb.Scanner` kwargs mismatch). The framework monkey-patches `Connector.sniff()` to absorb the extra kwargs. For reliable ESB scanning, use an RfStorm dongle (rfstorm0) — it uses `whad.esb.Sniffer` which does not have this bug.

**Stage 18/19 `synchronize()` fails**
Target device must be actively transmitting. Ensure the RfStorm dongle is within range (typically <10 m) and the device is in use (mouse moving, keyboard typing). If using nRF52840 as fallback, synchronize() success is not guaranteed.

**Stage 20 — hijack never syncs**
The InjectaBLE technique requires the target connection to still be active and within range. S2 must have captured valid connection parameters (AA, CRC init, channel map) within the same session. The dongle must support `can_reactive_jam`.

**Stage 21 — `hcitool: command not found`**
Install BlueZ: `sudo apt install bluez`. For Ubertooth sniffing, install `ubertooth` package and ensure `ubertooth-br` is in PATH.

**All devices classified as `mobile_device`**
This indicates the `company_identifiers.yaml` file is present and matching too broadly, or that `t.company_id` is being set from manufacturer-specific AD records containing common protocol company IDs (e.g. 0x004C for iBeacon). Classification falls back to OUI-derived `t.manufacturer` when the YAML is absent. OUI lookup from `oui.csv` is the most reliable source for device class identification.
