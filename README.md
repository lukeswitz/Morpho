# Butterfly-RedTeam

Automated BLE red team framework built on [WHAD](https://github.com/whad-team/whad-client). Runs a structured 9-stage assessment pipeline against BLE targets — passive recon through active exploitation — with per-stage authorization gates, SQLite findings storage, and Markdown/JSON reporting.

> **Authorization required.** This tool transmits RF packets and connects to BLE devices. Only operate against equipment you own or have written authorization to test.

---

## Requirements

| Item | Detail |
|------|--------|
| Hardware | Makerdiary nRF52840 MDK dongle with ButteRFly firmware |
| OS | Linux (primary), macOS (supported) |
| Python | 3.9+ |
| WHAD CLI tools | `wble-connect`, `wble-central`, `wble-proxy`, `wplay`, `wanalyze`, `wsniff`, `winject` |

---

## Install

```bash
python3 -m venv venv && source venv/bin/activate
pip install whad scapy
```

**Linux — USB permissions:**
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**Verify dongle:**
```bash
whadup   # expected: uart0   ButteRFly   /dev/ttyACM0
```

---

## Usage

```bash
# Default pipeline (stages 1–3, 5, 7–8)
python main.py -n "Engagement1" -l "Building A"

# Custom stage selection
python main.py -n "Engagement1" -l "Building A" --stages 1,5,7,8

# Single target
python main.py -n "Engagement1" -l "Building A" --target AA:BB:CC:DD:EE:FF

# Extended scan window
python main.py -n "Engagement1" -l "Building A" --scan-duration 300

# Suppress interactive gate prompts (unattended / scripted runs)
python main.py -n "Engagement1" -l "Building A" --no-gate
```

---

## Stage Reference

| Stage | Name | Mode | Description |
|-------|------|------|-------------|
| 1 | Environment Mapping | Passive | BLE scan — discovers targets, classifies devices, scores risk |
| 2 | Connection Intelligence | Passive | Sniffs BLE connections, extracts pairing/key material via `wanalyze`, recovers GATT profiles from PCAP |
| 3 | Identity Cloning | Active | Rogue peripheral — clones target BD address and GATT profile, detects centrals that auto-connect |
| 4 | Reactive Jamming | Active | Disrupts BLE advertising using `reactive_jam`; must be explicitly requested (`--stages ...4...`) |
| 5 | GATT Enumeration | Active | Connects and reads full GATT profile; exports writable handles and characteristic values |
| 6 | MITM Proxy | Active | Transparent BLE proxy via `wble-proxy`; requires two RF interfaces |
| 7 | GATT Write Fuzzer | Active | Feeds oversized/malformed payloads to all writable handles; detects crashes and error rates |
| 8 | Semantic PoC | Active | Targeted GATT writes — device rename (0x2A00), alert trigger (0x2A06), HR control reset (0x2A39), proprietary probe |
| 9 | Packet Injection | Active | ADV flood/replay via `wsniff`+`winject`; InjectaBLE PDU injection into live connections (requires S2 data) |
| 10 | Logitech Unifying | Active | Passive scan for Unifying mice/keyboards on 2.4 GHz ESB channels; MouseJack keystroke/mouse injection into vulnerable receivers (`whad.unifying`) |

Stages 4, 9, and 10 are excluded from the default pipeline and must be added explicitly via `--stages`.

---

## Output

| Artifact | Location |
|----------|----------|
| SQLite findings DB | `./findings.db` |
| Markdown report | `./reports/report_<eng_id>.md` |
| JSON report | `./reports/report_<eng_id>.json` |
| Per-stage PCAPs | `./pcaps/<eng_id>/s<N>_<addr>.pcap` |

---

## Troubleshooting

**`DongleCapabilityError: Dongle does not support 'can_scan'`**
The dongle needs a moment to enumerate after USB connection. Unplug, wait 5 seconds, reconnect, and retry.

**`whadup: command not found`**
Activate the virtual environment: `source venv/bin/activate`

**`Permission denied: /dev/ttyACM0`** (Linux)
```bash
sudo usermod -aG dialout $USER && newgrp dialout
```

**Stage 5/7 returns "No characteristics parsed"**
Target may not support the `wble-central profile` command format. Stage 8 will self-profile via the Python WHAD API on its next run if handles were found by S7.
