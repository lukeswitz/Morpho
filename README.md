<div align="center">


<img width="1792" height="592" alt="morphoImg" src="https://github.com/user-attachments/assets/f20b6789-bb63-44f4-ba0d-1ed6a0c8e47e" />

<h4>Multi-protocol wireless red team framework built on <a href="https://github.com/whad-team/whad-client">WHAD</a></h3>

<p>BLE · ESB · Logitech Unifying · ZigBee · LoRaWAN · Sub-GHz PHY · Bluetooth Classic · RF4CE · 802.15.4</p>

</div>

> [!IMPORTANT]
> **Authorization required.** This tool transmits RF packets and connects to wireless devices. Only operate against equipment you own or have written authorization to test.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Hardware Support](#hardware-support)
- [CLI Reference](#cli-reference)
- [Common Invocations](#common-invocations)
- [Terminal UI](#terminal-ui)
- [Stage Reference](#stages)
  - [BLE Stages](#ble-stages)
  - [ESB / Unifying Stages](#esb--unifying-stages)
  - [802.15.4 / RF4CE Stages](#802154-and-rf4ce-stages)
  - [Sub-GHz PHY Stage](#sub-ghz-phy-stage)
  - [Bluetooth Classic Stage](#bluetooth-classic-stage)
  - [GATT Shell](#gatt-shell)
- [Auto Stage Selection](#auto-stage-selection)
- [Device Classification](#device-classification)
- [Configuration](#configuration)
- [Output](#output)
- [Finding Types](#finding-types)
- [Troubleshooting](#troubleshooting)
- [Legal](#legal)

---

## What It Does

Morpho walks a known practical attack surface across short-range RF protocols; passively where possible.

- Scans, fingerprints, and risk-scores every wireless device in range
- Sniffs BLE connections and extracts key material (LTK, IRK, CSRK) from the air
- Clones peripheral identities and impersonates them to centrals
- Hijacks live BLE connections mid-session, hands you an interactive GATT shell
- Injects keystrokes and mouse events into Logitech wireless devices — no pairing required
- Plays DuckyScript payloads over the air against unencrypted ESB targets
- Transparently proxies BLE traffic between device and host, reading everything
- Fuzzes every writable GATT handle with malformed payloads, records what breaks
- Opens rogue ZigBee coordinators, joins real PANs to prove association is open
- Sweeps Sub-GHz bands and fingerprints active protocols by signature
- Enumerates Bluetooth Classic services, flags dangerous exposed profiles
- Saves everything: SQLite findings DB, Markdown and JSON reports, per-stage PCAPs
- The TUI keeps it operator-friendly. **--plain makes it scriptable.** The gate system prevents irreversible actions without explicit confirmation.

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/lukeswitz/Morpho.git
cd Morpho
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Install WHAD
pip install whad

# Or from source for latest fixes
git clone https://github.com/whad-team/whad-client.git
cd whad-client
pip install -e .
cd ..

# 3. Linux — USB permissions (one-time)
sudo usermod -aG dialout $USER && newgrp dialout

# 4. Verify connected hardware
whadup
```

**Optional data files** 

| File | Source | Purpose |
|------|--------|---------|
| `oui.csv` | [IEEE MA-L registry](https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries) | ~35,000 OUI → vendor mappings |
| `company_identifiers.yaml` | [Bluetooth SIG assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/) | 7,200+ company ID → name mappings |

Both are optional — classification still works from name patterns and service UUIDs if absent.

---

## Hardware Support

> [!TIP]
>  nRF52840 MDK (ButteRFly firmware) will perform 90% of the current stages


| Device | Interface | Protocols |
|--------|-----------|-----------|
| Makerdiary nRF52840 MDK (ButteRFly firmware) | `uart0` | BLE (all modes), ZigBee/802.15.4, ESB scanner |
| RfStorm (nRF24L01+) | `rfstorm0` | ESB sniffer (all-channel), Logitech Unifying |
| YARD Stick One | `yardstickone0` | Sub-GHz PHY (300–928 MHz) |
| Ubertooth One | `ubertooth0` | Passive BLE sniff (supplements S1/S2) |

All devices are **auto-detected** from `whadup` at startup. Stages route to the best available hardware automatically. **The framework runs with any subset of hardware** — missing devices produce warnings and skip relevant stages rather than aborting.

---

## CLI Reference

```
python morpho.py [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--name` | `-n` | `unnamed` | Engagement name for reporting |
| `--location` | `-l` | _(empty)_ | Physical location being assessed |
| `--engagement` | `-e` | _(auto)_ | Engagement ID (auto-generated if omitted) |
| `--interface` | `-i` | `uart0` | Primary BLE WHAD interface |
| `--esb-interface` | | _(auto)_ | ESB/Unifying interface (auto-detects `rfstorm0`) |
| `--phy-interface` | | _(auto)_ | Sub-GHz PHY interface (auto-detects `yardstickone0`) |
| `--ubertooth-interface` | | _(auto)_ | Passive BLE sniffer (auto-detects `ubertooth0`) |
| `--proxy-interface` | | `hci0` | Second interface for S6 MITM proxy |
| `--stages` | | `auto` | Comma-separated stage list or `auto` |
| `--opt-in` | | off | Enable all opt-in stages (still gate-confirmed at runtime) |
| `--no-gate` | | off | Disable active-stage confirmation prompts |
| `--target` | | _(none)_ | Focus on a specific BD address (repeatable) |
| `--scan-duration` | | `60` | Stage 1 BLE scan duration in seconds |
| `--plain` | | off | Disable TUI; use stdin prompts (SSH / headless) |
| `--redact` | | off | Redact MACs and device names from all output |
| `--debug` | | off | Enable DEBUG-level logging |

---

## Common Invocations

```bash
# TUI mode — interactive launch form (default when stdout is a TTY)
python morpho.py

# TUI with pre-filled fields
python morpho.py -n "Engagement1" -l "Building A"

# Plain / SSH mode — no TUI, stdin prompts
python morpho.py --plain -n "Engagement1" -l "Building A"

# Explicit stage list (plain mode)
python morpho.py --plain -n "Engagement1" --stages 1,2,5,7,8

# Enable all opt-in stages (gate prompt still required for each)
python morpho.py -n "Engagement1" --opt-in

# Focus on a specific target
python morpho.py -n "Engagement1" --target AA:BB:CC:DD:EE:FF

# ESB / sub-GHz only (no BLE dongle required)
python morpho.py -n "Engagement1" --stages 10,14,17

# Extended scan, skip prompts (automated / scripted use)
python morpho.py -n "Engagement1" --scan-duration 300 --no-gate

# Override all hardware interfaces manually
python morpho.py \
  --interface uart0 \
  --esb-interface rfstorm0 \
  --phy-interface yardstickone0 \
  --ubertooth-interface ubertooth0

# Debug logging
python morpho.py -n "Engagement1" --debug
```

---

## Terminal UI

Morpho ships a Textual-based TUI by default when stdout is a TTY. Use `--plain` to disable it for SSH or headless use.

### Dashboard

Three-panel live view during stage execution:

- **Stage list** — shows status (PENDING / RUNNING / COMPLETE / SKIPPED) for each stage
- **Log pane** — timestamped, colored framework output
- **Target table** — discovered devices with address, class, RSSI, and finding count

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| `Ctrl+C` | Abort run |
| `Ctrl+X` | Skip current stage |
| `Ctrl+L` | Toggle log pane |
| `Ctrl+R` | Toggle redaction (replaces MACs/names for screen-sharing) |

### Active Gate Modal

Every opt-in stage raises a full-screen confirmation modal before any RF transmission. The operator must explicitly choose **proceed**, **skip**, or **abort** — there is no default.

### Target Selection Modal

Stages that require a target present a table sorted by risk score. Accepts: `1,3` (numbers), `all`, `smart` (excludes low-value classes), or `skip`.

## Stages

### BLE Stages

_(uart0 / ButteRFly)_

| # | Name | Mode | What it does |
|---|------|------|-------------|
| 1 | Environment Mapping | Passive | BLE advertisement scan. Classifies devices, scores risk 0–10. Ubertooth One supplements range in a parallel thread when connected. |
| 2 | Connection Intelligence | Passive | Sniffs `CONNECT_IND` PDUs. Extracts pairing/LTK/IRK/CSRK key material via `wanalyze`. Recovers passive GATT profiles from PCAP. |
| 3 | Identity Cloning | Active | Rogue peripheral cloning target BD address and GATT profile. Write-capture hooks record central writes. Optional transparent relay via `wble-spawn` (`S3_SPAWN_MODE`). |
| 4 | Reactive Jamming | **OPT-IN** | Disrupts BLE advertising/connections via `reactive_jam`. Target selected at runtime. |
| 5 | GATT Enum + Shell | Active | Connects and enumerates full GATT profile. Reads Battery/DIS/HR services. Exports writable handles and JSON profile. MTU negotiated to 247. Launches [GATT shell](#gatt-shell) after enumeration. |
| 6 | MITM Proxy | **OPT-IN** | Transparent BLE MITM via `wble-proxy`. Optional `--link-layer` mode intercepts all L2CAP PDUs. Requires two RF interfaces. |
| 7 | GATT Fuzzer | Active | Feeds oversized/malformed payloads to all writable handles. Identifies which handles enforce length/type validation. |
| 8 | Semantic PoC | Active | Targeted GATT writes — device rename (0x2A00), alert trigger (0x2A06), HR control reset (0x2A39), proprietary channel probing, raw ATT PDU probe, inline LESC pairing escalation for auth-gated handles. |
| 9 | Packet Injection | **OPT-IN** | **[A]** ADV flood/replay via `wsniff`+`winject`. **[I]** InjectaBLE PDU injection into a live connection using S2 channel parameters. |
| 11 | ZigBee / 802.15.4 | Passive/Active | **[P]** Passive channel survey, PAN ID extraction, auto-decrypt, key recovery. **[C]** Rogue coordinator — opens join window, captures key material. **[E]** End device — joins a real PAN to prove open association. |
| 12 | PHY ISM Survey | Passive | Sweeps 2402–2480 MHz in 2 MHz steps with GFSK. Aggregates into 5 MHz bands with packet count and peak RSSI. Also probes 433/868/915 MHz for LoRa activity. |
| 13 | SMP Pairing Scan | Active | Tests 4 pairing modes (LESC/Legacy × Just Works/Bonding). Extracts distributed keys from security database. |
| 15 | LoRaWAN Recon | Passive | `whad.lorawan.LWGateway` captures JoinRequest (DevEUI, AppEUI, DevNonce) and DataUp frames. Tests DevNonce replay. Requires external LoRa radio hardware. |
| 16 | L2CAP CoC | **OPT-IN** | Tests LE L2CAP Connection-Oriented Channels via `AF_BLUETOOTH` sockets. Probes PSMs 0x0023–0x00FF for unauthenticated channels; fuzzes accepted channels with malformed SDUs. |
| 20 | BLE Connection Hijacker | **OPT-IN** | InjectaBLE technique — syncs to a live BLE connection from S2 parameters, evicts the legitimate Central via `LL_TERMINATE`, takes over, opens a [GATT shell](#gatt-shell). Requires `can_reactive_jam`. |

### ESB / Unifying Stages

_(rfstorm0 preferred; falls back to uart0)_

| # | Name | Mode | What it does |
|---|------|------|-------------|
| 10 | Logitech Unifying / MouseJack | Active | **sniff** — passive scan + keylog + `wanalyze keystroke pairing_cracking` pipeline. **inject** — MouseJack text injection. **ducky** — DuckyScript playback. **mouse** — scripted move+click or hardware relay. |
| 14 | ESB Raw Scan | Passive | RfStorm: `whad.esb.Sniffer(channel=None)` all-channel loop. nRF52840: `whad.esb.Scanner` with monkey-patch for kwargs bug. Flags low-entropy (plaintext) payloads. |
| 18 | ESB PRX/PTX Active | **OPT-IN** | **PRX** — listen as Primary Receiver, arm ACK payloads, capture and entropy-check frames. **PTX** — `synchronize()` then `send_data(waiting_ack=True)` to inject unauthenticated frames. |
| 19 | Unifying Python API | **OPT-IN** | `whad.unifying.Mouse` + `whad.unifying.Keyboard`. Sub-modes: Dongle enumeration, Injector, Mouse spiral+click, Keyboard `send_text()`, DuckyScript parser (STRING/ENTER/DELAY/modifiers). |

### 802.15.4 and RF4CE Stages

_(uart0 / ButteRFly)_

| # | Name | Mode | What it does |
|---|------|------|-------------|
| 22 | RF4CE Recon | **OPT-IN** | Scans IEEE 802.15.4 channels 15, 20, 25 (RF4CE band plan). Identifies remote control / set-top-box pairing frames, records node addresses and PAN IDs. |
| 23 | Raw 802.15.4 Survey | Passive | Full 16-channel (11–26) scan. Classifies each frame as ZigBee, Thread, WirelessHART, RF4CE, or Unknown. Reports per-channel activity, frame counts, and unique source addresses. Auto-selected with S11. |

### Sub-GHz PHY Stage

_(yardstickone0 / YardStickOne)_

| # | Name | Mode | What it does |
|---|------|------|-------------|
| 17 | Sub-GHz PHY Survey | **OPT-IN** | GFSK sweep across 300–348 MHz, 391–464 MHz, 782–928 MHz in 2 MHz steps with protocol hints (Z-Wave, 433 MHz remotes, LoRa, TPMS). OOK/ASK pass at [315, 433, 434, 868, 915] MHz. |

### Bluetooth Classic Stage

_(hcitool / Ubertooth One)_

| # | Name | Mode | What it does |
|---|------|------|-------------|
| 21 | BR/EDR Scout | Passive/Active | `hcitool inquiry` discovers BR/EDR devices. `sdptool browse` enumerates services; flags risky profiles (SPP, OBEX Push/FTP, BNEP/PAN). Ubertooth passive piconet sniff via `ubertooth-br`/`ubertooth-rx`. Auto-selected when HCI adapter or Ubertooth is present. |

### GATT Shell

Available after Stage 5 enumeration or a Stage 20 hijack.

| Command | Description |
|---------|-------------|
| `read <handle>` | ATT Read Request — hex output |
| `write <handle> <hex>` | ATT Write Request |
| `wnr <handle> <hex>` | Write then read-back for confirmation |
| `sub <handle>` | Enable notifications |
| `unsub <handle>` | Disable notifications |
| `notify <handle>` | Harvest one notification value |
| `info` | Print full GATT profile table |
| `connupdate <ms> [lat] [to_ms]` | LL Connection Parameter Update |
| `whack` | Oscillate interval 7.5 ms ↔ 4000 ms × 5 rounds (stress test) |
| `pyshell` | Python REPL with `central`, `periph_dev`, `target` in scope |
| `quit` | Disconnect and exit |

**Shell keyboard shortcuts** (TUI mode only):

| Key | Action |
|-----|--------|
| `Ctrl+C` | Disconnect and return to dashboard |
| `Ctrl+L` | Clear shell log |

---

## Auto Stage Selection

When `--stages auto` (default), hardware capabilities determine the stage list:

| Capability | Stages selected |
|-----------|----------------|
| `can_scan` / `can_sniff` / `can_central` / `can_peripheral` | 1, 2, 3, 5, 7, 8, 13 |
| `can_unifying` | 10 |
| `can_esb` | 14 |
| `can_zigbee` | 11, 23 |
| `can_phy` | 12 |
| `can_lorawan` | 15 |
| YardStickOne detected | 17 |
| HCI adapter or Ubertooth detected | 21 |
| `--opt-in` flag | + 4, 6, 9, 16, 17, 18, 19, 20, 22 |

**Opt-in stages (4, 6, 9, 16, 17, 18, 19, 20, 22) are never auto-selected.** Use `--opt-in` or include them explicitly in `--stages`.

Full hardware example:
```
Auto:         1, 2, 3, 5, 7, 8, 10, 11, 12, 13, 14, 17, 21, 23
With --opt-in: all of the above + 4, 6, 9, 16, 18, 19, 20, 22
```

---

## Device Classification

Stage 1 classifies every discovered device using a three-source chain:

1. **OUI lookup** (`oui.csv`) — maps first 3 MAC bytes to IEEE vendor
2. **SIG company ID** (`company_identifiers.yaml`) — manufacturer-specific AD record
3. **Hardcoded fallback** (`config.COMPANY_IDS`) — supplemental entries

**Device classes:**

| Class | Matched by |
|-------|-----------|
| `access_control` | lock, door, access, badge, gate, Schlage, August, Yale, Nuki… |
| `medical` | patient, monitor, pump, SPO2, glucose, Omron, Withings… |
| `industrial` | PLC, HMI, SCADA, relay, actuator, Modbus, gateway… |
| `smart_home` | Govee, Philips Hue, LIFX, Wyze, Shelly, Tuya, SwitchBot… |
| `mobile_device` | iPhone, iPad, Galaxy, Pixel, AirPods, Apple Watch… |
| `peripheral` | Razer, Logitech, keyboard, earbud, headset, Jabra, Bose… |
| `sensor` | HVAC, temp, humid, smoke, Ruuvi, SensorPush, BTHome… |

Priority: **name pattern → manufacturer pattern → service UUID**. Unmatched devices are tagged `unknown`.

**Risk scoring (0–10):** factors in device class, connectable flag, address type (public +1), RSSI proximity, and high-value name hits (+3). Devices scoring ≥ 8 are marked **CRIT** in the target selection modal.

---

## Configuration

Edit [`config.py`](config.py) to change defaults. CLI flags override config at runtime.

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `uart0` | Primary BLE dongle |
| `ESB_INTERFACE` | auto | ESB/Unifying dongle |
| `PHY_SUBGHZ_INTERFACE` | auto | Sub-GHz PHY dongle |
| `UBERTOOTH_INTERFACE` | auto | Passive BLE sniffer |
| `PROXY_INTERFACE` | `hci0` | Second interface for S6 MITM proxy |
| `SCAN_DURATION` | `60` | S1 BLE scan duration (seconds) |
| `RSSI_MIN_FILTER` | `0` | Ignore devices weaker than N dBm (`0` = off) |
| `ACTIVE_GATE` | `True` | Require confirmation before active stages |
| `VERBOSE_MODE` | `False` | Print WHAD narration lines (training/classroom mode) |
| `S3_SPAWN_MODE` | `False` | Transparent `wble-spawn` relay in S3 instead of static clone |
| `UNIFYING_LOCALE` | `us` | Keyboard locale for `wuni-keyboard -l` |
| `UNIFYING_DUCKY_SCRIPT` | `None` | Path to DuckyScript file (S10/S19 ducky mode) |
| `UNIFYING_KBD_TEXT` | `Hello from WHAD` | S19 keyboard injection text |
| `UNIFYING_SYNC_TIMEOUT` | `15` | Seconds to wait for `synchronize()` |
| `ESB_PRX_TIMEOUT` | `30` | S18 PRX listen window (seconds) |
| `ESB_PTX_PAYLOAD` | `050000000000` | S18 PTX injection payload (hex) |
| `SUBGHZ_SWEEP_SECS` | `120` | S17 total sweep budget |
| `SUBGHZ_PER_FREQ_SECS` | `2` | S17 dwell time per frequency |
| `LORAWAN_REGION` | `EU868` | S15 LoRaWAN regional plan (`EU868` or `US915`) |
| `ZIGBEE_COORD_SECS` | `60` | S11 coordinator join window (seconds) |
| `RF4CE_SNIFF_SECS` | `30` | S22 dwell per channel |

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

<details>
<summary>Expand full findings table</summary>

| Finding | Severity | Stage |
|---------|----------|-------|
| `gatt_poc` | high / medium / low | 8 |
| `ble_connection_hijacked` | critical | 20 |
| `ble_hijack_attempted` | info | 20 |
| `mitm_proxy` | critical / high / medium | 6 |
| `mousejack_keystroke_injection` | critical | 10 |
| `mousejack_ducky_injection` | critical | 10 |
| `mousejack_mouse_injection` | medium | 10 |
| `unifying_device_discovered` | medium | 10 |
| `unifying_keystrokes_captured` | high | 10 |
| `unifying_pairing_key_recovered` | critical | 10 |
| `esb_device_discovered` | info | 14 |
| `esb_unencrypted_traffic` | medium | 14 |
| `esb_prx_frames_captured` | high / medium | 18 |
| `esb_ptx_injection` | critical / high | 18 |
| `esb_replay_accepted` | critical / high | 18 |
| `unifying_api_mouse_injection` | critical | 19 |
| `unifying_api_keyboard_injection` | critical | 19 |
| `unifying_api_ducky_injection` | critical | 19 |
| `zigbee_network_discovered` | medium | 11 |
| `zigbee_keys_recovered` | high | 11 |
| `zigbee_coordinator_join` | high | 11 |
| `zigbee_enddevice_joined` | critical | 11 |
| `zigbee_enddevice_rejected` | info | 11 |
| `phy_rf_activity` | info | 12 |
| `phy_subghz_rf_activity` | info | 17 |
| `phy_subghz_ook_activity` | info | 17 |
| `l2cap_coc_open_psm` | critical / high | 16 |
| `smp_pairing_vulnerable` | high / medium | 13 |
| `lorawan_fcnt_anomaly` | medium | 15 |
| `btc_device_found` | info | 21 |
| `btc_exposed_services` | medium | 21 |
| `btc_weak_security_mode` | high | 21 |
| `btc_piconet_sniffed` | high | 21 |
| `rf4ce_device_discovered` | medium | 22 |
| `rf4ce_pairing_frame` | high | 22 |
| `dot15d4_rf_activity` | info | 23 |
| `dot15d4_protocol_classified` | info | 23 |

</details>

---

## Troubleshooting

**`whadup: command not found`**
```bash
source .venv/bin/activate
```

**`Permission denied: /dev/ttyACM0`**
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**`WhadDeviceTimeout` at startup**
The ButteRFly firmware does not re-emit DeviceReady after boot, so `reset()` times out. The framework patches `reset()` to a no-op and handles this automatically — it's expected behaviour.

**TUI rendering issues over SSH**
```bash
export TERM=xterm-256color
# Or use plain mode:
python morpho.py --plain --stages 1,2,5 --no-gate
```

**No BLE dongle — only rfstorm0 / yardstickone0 connected**
BLE stages are skipped with a warning. ESB and sub-GHz stages run normally.

**Stage 5/7 — "No characteristics parsed"**
Target may not support the `wble-central profile` format. Stage 8 self-profiles via the Python WHAD API and will still attempt semantic PoC writes.

**Stage 10 — no Unifying devices found**
`wuni-scan` exits quickly when no devices are present. The scanner restarts for the full `UNIFYING_SNIFF_SECS` window. Verify the dongle is `rfstorm0` (`whadup`) and devices are actively transmitting.

**Stage 14 — ESB Scanner TypeError on nRF52840**
Known WHAD v1.2.x bug. The framework monkey-patches `Connector.sniff()` to absorb the extra kwargs. For reliable ESB scanning, use an RfStorm dongle — it uses `whad.esb.Sniffer` which does not have this issue.

**Stage 18/19 — `synchronize()` fails**
The target device must be actively transmitting. Ensure the dongle is within ~10 m and the device is in use (mouse moving, keyboard typing).

**Stage 20 — hijack never syncs**
The InjectaBLE technique requires the target connection to still be active and within range. S2 must have captured valid connection parameters (AA, CRC init, channel map, hop) within the same session. The dongle must support `can_reactive_jam`.

**Stage 21 — `hcitool: command not found`**
```bash
sudo apt install bluez
# For Ubertooth sniffing:
sudo apt install ubertooth
```

**All devices classified as `mobile_device`**
`company_identifiers.yaml` may be matching too broadly on manufacturer-specific AD records (e.g. `0x004C` for iBeacon). Remove the file to fall back to OUI-based classification, which is more reliable for device class identification.


## Legal

This software is provided for authorized security research and professional penetration testing only.

You are solely responsible for how you use this tool.

Operating Morpho against wireless devices, networks, or infrastructure you do not own or lack explicit written authorization to test may violate one or more of the following, depending on jurisdiction:

- United States: Computer Fraud and Abuse Act (18 U.S.C. § 1030), Electronic Communications Privacy Act (18 U.S.C. §§ 2510–2523), FCC Part 15 / Part 97 regulations
- European Union: Directive on Attacks Against Information Systems (2013/40/EU), national implementations thereof
- United Kingdom: Computer Misuse Act 1990
- Canada: Criminal Code §§ 342.1, 184, 193
- Australia: Criminal Code Act 1995 §§ 477–478

RF transmission may additionally implicate spectrum licensing law independent of computer crime statutes.

The authors, contributors, and distributors of Morpho:

- Make no warranty, express or implied, regarding fitness for any purpose
Accept no liability for damages, legal consequences, or harm arising from use or misuse

- Do not endorse or authorize any use that violates applicable law or third-party rights

Before using this tool:

- Obtain written authorization scoped to specific devices, frequency bands, and time windows
- Confirm RF transmission is permitted in your jurisdiction and location
- Coordinate with facility owners, RF spectrum regulators, and legal counsel as appropriate

This software is released under the MIT License. See LICENSE for terms.

If you are unsure whether your intended use is lawful, do not proceed.
