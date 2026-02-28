# Butterfly-RedTeam

WHAD wrapper for fast, targeted redteam engagements.

# Installation & Setup

## Requirements 

- Python 3.9+
- `pip` package manager
- USB access to Makerdiary nRF52840 MDK dongle
- Linux/macOS (Windows not tested with WHAD)

## Quick Install

```bash
# 1. Clone repo
git clone <repo> butterfly-ble-redteam
cd butterfly-ble-redteam

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 4. Verify WHAD installation
whadup  # Should list connected devices

# 5. Run a test scan
python main.py --scan-duration 30 -n "Test" -l "Lab"
```

## Manual Step-by-Step

### Step 1: Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Core Dependencies

```bash
pip install --upgrade pip setuptools wheel
```

### Step 3: Install WHAD (Multi-Protocol Red Team Library)

WHAD requires the nRF52840 dongle with ButteRFly firmware flashed.

```bash
# Install WHAD from PyPI
pip install whad
```

Or if using development version from source:

```bash
git clone https://github.com/Joulot/whad.git
cd whad
pip install -e .
cd ..
```

### Step 4: Install Additional Dependencies

```bash
pip install scapy  # BLE packet parsing
```

### Step 5: Verify Dongle Connection

```bash
# List connected WHAD devices
whadup

# Expected output:
#   uart0    ButteRFly  /dev/ttyACM0
```

If `whadup: command not found`, restart terminal or:

```bash
source venv/bin/activate
which whadup  # Should show venv path
```

### Step 6: Set USB Permissions (Linux only)

```bash
# Allow non-root USB access to ButteRFly
sudo usermod -aG dialout $USER

# Apply group membership (requires logout/login or):
newgrp dialout
```

Verify:

```bash
ls -l /dev/ttyACM0  # Should be readable by dialout group
```

### Step 7: Test Installation

```bash
# Run a 30-second test scan
python main.py --scan-duration 30 -n "VerificationRun" -l "Rooftop"

# Expected output:
#   - Banner showing engagement ID
#   - Dongle capabilities check
#   - 20+ BLE devices discovered
#   - Reports generated in ./reports/
#   - Database written to ./findings.db
```

## Troubleshooting

**`whadup: command not found`** — Reinstall WHAD:

```bash
source venv/bin/activate
pip uninstall whad -y && pip install whad
```

**No WHAD device found** — Check dongle:

```bash
lsusb | grep -i nrf  # Verify device is connected
ls -la /dev/ttyACM0  # Check USB device exists
```

**Permission denied:** /dev/ttyACM0 (Linux only):

```bash
sudo usermod -aG dialout $USER
newgrp dialout
```

## Usage

```bash
# Full pipeline (Stages 1-8)
python main.py -n "Engagement1" -l "Location" --scan-duration 60

# Specific stages only
python main.py -n "Scan Only" -l "Lab" --stages 1,5,7,8

# Single target device
python main.py -n "Target" -l "Lab" --target AA:BB:CC:DD:EE:FF

# Explain a stage
python main.py --explain-stage 3

# Skip interactive gates (dangerous)
python main.py -n "AutoRun" -l "Lab" --no-gate

# Deactivate venv when done
deactivate
```
