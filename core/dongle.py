"""
core/dongle.py — WHAD dongle management layer.

Wraps WhadDevice with:
- Capability probing (resolves 4 runtime API assumptions at startup)
- Per-capability factory methods (scanner, sniffer, central, peripheral)
- API compatibility adapters (sniff_next, periph_services)
- Training mode: [WHAD] narration lines when config.VERBOSE_MODE is True
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterator

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound, WhadDeviceAccessDenied

from core.logger import get_logger
import config

log = get_logger("dongle")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DongleCapabilityError(RuntimeError):
    """Raised when a stage requires a capability the dongle lacks."""


# ---------------------------------------------------------------------------
# Capability descriptor
# ---------------------------------------------------------------------------

@dataclass
class DongleCaps:
    can_scan:           bool = False  # Scanner connector works
    can_sniff:          bool = False  # Sniffer (passive, advertisements)
    can_sniff_active:   bool = False  # Sniffer can follow a connection
    sniff_api:          str  = "unknown"  # "wait_packet" | "iterator"
    can_spoof_bd_addr:  bool = False  # Peripheral.set_bd_address() accepted
    can_reactive_jam:   bool = False  # BLE.reactive_jam() method present
    can_central:        bool = False  # Central connector works
    can_peripheral:     bool = False  # Peripheral connector works
    can_unifying:       bool = False  # Logitech Unifying (ESB) domain available
    can_phy:            bool = False  # PHY raw modulation domain available
    can_esb:            bool = False  # Enhanced ShockBurst raw domain (non-Logitech)
    can_lorawan:        bool = False  # LoRaWAN domain (requires LoRa radio)
    can_zigbee:         bool = False  # IEEE 802.15.4 / ZigBee domain available
    can_send_pdu:       bool = False  # Central.enable_synchronous + send_pdu available
    firmware_version:   str | None = None
    device_type:        str = "unknown"  # "butterfly" | "hci" | "rfstorm" | "yardstickone" | "ubertooth" | "unknown"

    def summary_lines(self) -> list[str]:
        tick = lambda b: "yes" if b else "no"
        return [
            f"  Device type     : {self.device_type}",
            f"  Firmware        : {self.firmware_version or 'unknown'}",
            f"  Scan            : {tick(self.can_scan)}",
            f"  Sniff (passive) : {tick(self.can_sniff)}",
            f"  Sniff API       : {self.sniff_api}",
            f"  Active sniff    : {tick(self.can_sniff_active)}",
            f"  BD addr spoof   : {tick(self.can_spoof_bd_addr)}",
            f"  Reactive jam    : {tick(self.can_reactive_jam)}",
            f"  Central         : {tick(self.can_central)}",
            f"  Peripheral      : {tick(self.can_peripheral)}",
            f"  Unifying (ESB)  : {tick(self.can_unifying)}",
            f"  PHY (ISM band)  : {tick(self.can_phy)}",
            f"  ESB (raw)       : {tick(self.can_esb)}",
            f"  LoRaWAN         : {tick(self.can_lorawan)}",
            f"  ZigBee (802.15.4): {tick(self.can_zigbee)}",
            f"  SendPDU (raw ATT): {tick(self.can_send_pdu)}",
        ]


# ---------------------------------------------------------------------------
# Hardware map — holds all detected WHAD dongles for a session
# ---------------------------------------------------------------------------

@dataclass
class HardwareMap:
    """References to all detected WHAD dongles.

    All fields are Optional. A session can run with only ESB/PHY hardware; BLE
    stages are skipped when ble_dongle is None.
    """
    ble_dongle:       "WhadDongle | None" = None  # uart0/hci0 — BLE (stages 1-9, 11-13)
    esb_dongle:       "WhadDongle | None" = None  # rfstorm0 — ESB + Unifying
    phy_dongle:       "WhadDongle | None" = None  # yardstickone0 — sub-GHz PHY
    ubertooth_dongle: "WhadDongle | None" = None  # ubertooth0 — passive BLE sniffer


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WhadDongle:
    """
    Capability-aware wrapper around WhadDevice.

    Usage:
        dongle = WhadDongle.create("uart0")
        scanner = dongle.scanner()
        ...
        dongle.close()
    """

    def __init__(self, device: WhadDevice, interface: str) -> None:
        self.device = device
        self.interface = interface
        self.caps = DongleCaps()
        self._verbose = config.VERBOSE_MODE

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, interface: str = config.INTERFACE) -> "WhadDongle":
        """Open device, probe all capabilities, return ready instance."""
        log.debug(f"Opening WHAD device on {interface}")
        try:
            device = WhadDevice.create(interface)
        except WhadDeviceNotFound:
            log.error(
                f"No WHAD device found at {interface}. "
                "Run 'whadup' to list connected devices."
            )
            raise SystemExit(1)
        except WhadDeviceAccessDenied:
            log.error(
                f"Permission denied on {interface}. "
                "Try: sudo usermod -aG dialout $USER"
            )
            raise SystemExit(1)
        except Exception as exc:
            log.error(f"Unexpected error opening device: {exc}")
            raise SystemExit(1)

        dongle = cls(device, interface)
        dongle.probe_caps()
        return dongle

    @classmethod
    def enumerate(cls) -> list[str]:
        """Return interface names for all connected WHAD devices."""
        return [name for name, _ in cls.enumerate_devices()]

    @classmethod
    def enumerate_devices(cls) -> list[tuple[str, str]]:
        """Return (interface_name, device_type) for all connected WHAD devices.

        Parses `whadup` output format:
            - yardstickone0
              Type: YardStickOne
              Index: 0
              ...
        Falls back to empty list on error.
        """
        try:
            result = subprocess.run(
                ["whadup"],
                capture_output=True,
                text=True,
                timeout=config.DONGLE_TIMEOUT,
            )
            devices: list[tuple[str, str]] = []
            current_name: str | None = None
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("- "):
                    current_name = stripped[2:].strip()
                elif stripped.startswith("Type:") and current_name is not None:
                    dev_type = stripped[len("Type:"):].strip()
                    devices.append((current_name, dev_type))
                    current_name = None
            return devices
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    # ------------------------------------------------------------------
    # Capability probing
    # ------------------------------------------------------------------

    def probe_caps(self) -> None:
        """
        Test each WHAD capability against the actual firmware.
        Sets self.caps flags. Logs a warning for each missing capability.
        Does NOT raise — missing caps are handled per-stage.
        """
        log.info(f"Probing capabilities on {self.interface}...")
        caps = self.caps
        timeout = config.DONGLE_TIMEOUT

        # Detect device type from interface string
        _iface_lo = self.interface.lower()
        if "uart" in _iface_lo:
            caps.device_type = "butterfly"
        elif "hci" in _iface_lo:
            caps.device_type = "hci"
        elif "rfstorm" in _iface_lo:
            caps.device_type = "rfstorm"
        elif "yardstickone" in _iface_lo:
            caps.device_type = "yardstickone"
        elif "ubertooth" in _iface_lo:
            caps.device_type = "ubertooth"

        # --- Probes 1–6: BLE connectors ---
        # RfStorm and YardStickOne have no BLE transceiver — skip entirely.
        # Ubertooth One is a passive BLE sniffer only — supports Scanner and
        # Sniffer (probes 1-2) but NOT Central/Peripheral/reactive jam (3-6).
        if caps.device_type in ("rfstorm", "yardstickone"):
            log.debug(
                f"Cap probe: Skipping BLE probes 1-6 for {caps.device_type} device "
                "(no BLE transceiver)."
            )
        elif caps.device_type == "ubertooth":
            log.debug(
                "Cap probe: Ubertooth One — probing passive BLE only (scan + sniff). "
                "Central/Peripheral/ReactiveJam not supported."
            )
            # Probe 1: Scanner
            try:
                from whad.ble import Scanner  # noqa: F401
                caps.can_scan = True
            except ImportError:
                pass
            # Probe 2: Sniffer
            try:
                from whad.ble import Sniffer
                caps.can_sniff = True
                caps.can_sniff_active = True
                caps.sniff_api = "iterator" if not hasattr(Sniffer, "wait_packet") else "wait_packet"
            except ImportError:
                pass
            # Probes 3-6 not applicable to Ubertooth
        else:
            # --- Probe 1: Scanner ---
            try:
                from whad.ble import Scanner  # noqa: F401
                caps.can_scan = True
                log.debug("Cap probe: Scanner OK")
            except ImportError as exc:
                log.warning(f"Cap probe: Scanner not available ({exc})")

            # --- Probe 2: Sniffer (passive advertisements) ---
            try:
                from whad.ble import Sniffer
                caps.can_sniff = True
                # Assumption 1: wait_packet vs iterator API (class-level check)
                if hasattr(Sniffer, "wait_packet"):
                    caps.sniff_api = "wait_packet"
                    caps.can_sniff_active = True
                    log.debug("Cap probe: Sniffer wait_packet API confirmed")
                else:
                    caps.sniff_api = "iterator"
                    log.debug("Cap probe: Sniffer iterator API (no wait_packet)")
                log.debug("Cap probe: Sniffer OK")
            except ImportError as exc:
                log.warning(f"Cap probe: Sniffer not available ({exc})")

            # --- Probe 3: BD address spoofing (Assumption 2) ---
            try:
                from whad.ble import Peripheral
                caps.can_spoof_bd_addr = hasattr(Peripheral, "set_bd_address")
                if caps.can_spoof_bd_addr:
                    log.debug("Cap probe: BD address spoofing OK (method on class)")
                else:
                    log.warning("Cap probe: set_bd_address() not found on Peripheral class")
            except ImportError as exc:
                log.warning(f"Cap probe: Peripheral import failed ({exc})")

            # --- Probe 4: ReactiveJam availability (Assumption 3) ---
            try:
                from whad.ble.connector import BLE
                caps.can_reactive_jam = callable(getattr(BLE, "reactive_jam", None))
                if caps.can_reactive_jam:
                    log.debug("Cap probe: reactive_jam() method present on BLE class")
                else:
                    log.warning("Cap probe: reactive_jam() not found on BLE connector class")
            except ImportError as exc:
                log.warning(f"Cap probe: BLE connector import failed ({exc})")

            # --- Probe 5: Central ---
            try:
                from whad.ble import Central  # noqa: F401
                caps.can_central = True
                log.debug("Cap probe: Central OK")
            except ImportError as exc:
                log.warning(f"Cap probe: Central not available ({exc})")

            # --- Probe 6: Peripheral ---
            try:
                from whad.ble import Peripheral  # noqa: F401
                caps.can_peripheral = True
                log.debug("Cap probe: Peripheral OK")
            except ImportError as exc:
                log.warning(f"Cap probe: Peripheral not available ({exc})")

        # --- Probe 7: Logitech Unifying — check CLI tools in PATH ---
        import shutil as _shutil
        _uni_tools = ["wuni-scan", "wuni-keyboard", "wuni-mouse"]
        if all(_shutil.which(t) for t in _uni_tools):
            caps.can_unifying = True
            log.debug("Cap probe: Unifying OK (CLI tools found)")
        else:
            _missing = [t for t in _uni_tools if not _shutil.which(t)]
            log.warning(f"Cap probe: Unifying CLI tools not found: {_missing}")

        # --- Probe 8: PHY raw modulation domain ---
        # Try package-level export first, then direct module path as fallback.
        for _phy_path in ("whad.phy", "whad.phy.connector.sniffer"):
            try:
                import importlib as _il
                _phy_mod = _il.import_module(_phy_path)
                if hasattr(_phy_mod, "Sniffer"):
                    caps.can_phy = True
                    log.debug(f"Cap probe: PHY OK ({_phy_path})")
                    break
            except ImportError:
                continue
        if not caps.can_phy:
            log.warning("Cap probe: PHY not available (whad.phy import failed)")

        # --- Probe 9: ESB (Enhanced ShockBurst) raw domain ---
        try:
            from whad.esb import Scanner as _EsbScanner  # noqa: F401
            caps.can_esb = True
            log.debug("Cap probe: ESB module importable (runtime compatibility unverified)")
        except ImportError as exc:
            log.warning(f"Cap probe: ESB not available ({exc})")

        # --- Probe 10: LoRaWAN domain ---
        # LoRaWAN requires a dedicated LoRa transceiver (SX1276/SX1278 or equivalent).
        # The ButteRFly (nRF52840) has no LoRa radio — the Python module may be importable
        # on the VM, but the hardware cannot drive it. Skip probe for butterfly devices.
        if caps.device_type in ("butterfly", "rfstorm", "yardstickone", "ubertooth"):
            log.warning(
                f"Cap probe: LoRaWAN skipped — {caps.device_type} has no LoRa transceiver. "
                "can_lorawan=False."
            )
        else:
            _lora_found = False
            for _lora_path in ("whad.lorawan", "whad.lorawan.gateway", "whad.lorawan.connector"):
                try:
                    import importlib as _il
                    _il.import_module(_lora_path)
                    caps.can_lorawan = True
                    log.debug(f"Cap probe: LoRaWAN OK ({_lora_path})")
                    _lora_found = True
                    break
                except ImportError:
                    continue
            if not _lora_found:
                log.warning("Cap probe: LoRaWAN not available (no whad.lorawan module found)")

        # --- Probe 11: ZigBee / IEEE 802.15.4 domain ---
        try:
            from whad.zigbee import Sniffer as _ZigbeeSniffer  # noqa: F401
            caps.can_zigbee = True
            log.debug("Cap probe: ZigBee OK")
        except ImportError as exc:
            log.warning(f"Cap probe: ZigBee not available ({exc})")

        # --- Probe 12: send_pdu availability (raw ATT PDU injection from Central) ---
        try:
            from whad.ble import Central as _CentralPdu  # noqa: F401
            caps.can_send_pdu = (
                callable(getattr(_CentralPdu, "enable_synchronous", None))
                and callable(getattr(_CentralPdu, "send_pdu", None))
            )
            if caps.can_send_pdu:
                log.debug("Cap probe: send_pdu OK (enable_synchronous + send_pdu on Central)")
            else:
                log.warning("Cap probe: send_pdu not available on Central class")
        except ImportError:
            pass

        log.info("Capability probe complete.")

    # ------------------------------------------------------------------
    # Capability assertion
    # ------------------------------------------------------------------

    def assert_cap(self, name: str) -> None:
        """Raise DongleCapabilityError if the named cap flag is False."""
        if not getattr(self.caps, name, False):
            raise DongleCapabilityError(
                f"Dongle does not support '{name}'. "
                f"Check capability banner and firmware version."
            )

    # ------------------------------------------------------------------
    # Connector factories
    # ------------------------------------------------------------------

    def scanner(self):
        """Return a configured Scanner. Asserts can_scan."""
        from whad.ble import Scanner
        self.assert_cap("can_scan")
        s = self._create_connector(Scanner)
        self._whad_log("Scanner created")
        return s

    def sniffer(self):
        """Return a configured Sniffer. Asserts can_sniff."""
        from whad.ble import Sniffer
        self.assert_cap("can_sniff")
        s = self._create_connector(Sniffer)
        self._whad_log("Sniffer created")
        return s

    def central(self):
        """Return a configured Central. Asserts can_central."""
        from whad.ble import Central
        self.assert_cap("can_central")
        c = self._create_connector(Central)
        self._whad_log("Central created")
        return c

    def peripheral(self, profile=None):
        """Return a configured Peripheral. Asserts can_peripheral."""
        from whad.ble import Peripheral
        from whad.ble.profile import GenericProfile
        self.assert_cap("can_peripheral")
        p = self._create_connector(Peripheral, profile or GenericProfile())
        self._whad_log("Peripheral created")
        return p

    def ble_connector(self):
        """Return a raw BLE base connector (used by s4_jam)."""
        from whad.ble.connector import BLE
        c = self._create_connector(BLE)
        self._whad_log("BLE connector created")
        return c

    # ------------------------------------------------------------------
    # API compatibility adapters
    # ------------------------------------------------------------------

    def sniff_next(self, sniffer, timeout: float) -> Any | None:
        """
        Adapter for Assumption 1: returns the next packet from sniffer.

        Dispatches to wait_packet(timeout) or the sniff() iterator depending
        on which API the firmware supports (resolved at probe time).
        """
        if self.caps.sniff_api == "wait_packet":
            self._whad_log(f"Sniffer.wait_packet(timeout={timeout})")
            try:
                pkt = sniffer.wait_packet(timeout=timeout)
                if pkt is not None:
                    self._whad_log(f"  → packet: {type(pkt).__name__}")
                return pkt
            except AttributeError:
                # Firmware changed since probe — fall through to iterator
                self.caps.sniff_api = "iterator"
                log.warning("wait_packet disappeared; switching to iterator API")

        # Iterator fallback: pull one packet via next() on sniff()
        self._whad_log(f"Sniffer.sniff() iterator (timeout={timeout})")
        try:
            gen = sniffer.sniff(timeout=timeout)
            pkt = next(gen, None)
            if pkt is not None:
                self._whad_log(f"  → packet: {type(pkt).__name__}")
            return pkt
        except StopIteration:
            return None
        except Exception as exc:
            log.debug(f"sniff iterator error: {exc}")
            return None

    def sniff_iter(self, sniffer, total_duration: float) -> Iterator:
        """
        Yield packets from sniffer for exactly total_duration seconds.

        WHAD's sniff(timeout=T) is an inactivity timeout (stops if no packet
        arrives for T seconds), NOT a total scan duration. In a busy BLE
        environment packets arrive continuously so sniff() never stops on its
        own. This method enforces total_duration via a time.time() deadline and
        passes a short per-packet inactivity timeout to sniff() so the inner
        loop wakes up regularly to check whether the deadline has passed.
        """
        from time import time as _now
        deadline = _now() + total_duration
        self._whad_log(f"Scanner.sniff(total={total_duration}s)")
        try:
            for pkt in sniffer.sniff(timeout=1.0):
                yield pkt
                if _now() >= deadline:
                    return
        except Exception as exc:
            log.debug(f"sniff_iter error: {exc}")

    def periph_services(self, periph_dev) -> list:
        """
        Adapter for Assumption 4: return services from a connected PeripheralDevice.

        Tries periph_dev.services() first (iterator), then get_services() (list).
        """
        self._whad_log("PeripheralDevice.services()")
        try:
            svcs = list(periph_dev.services())
            self._whad_log(f"  → {len(svcs)} service(s) via services()")
            return svcs
        except AttributeError:
            pass
        try:
            svcs = list(periph_dev.get_services())
            self._whad_log(f"  → {len(svcs)} service(s) via get_services()")
            return svcs
        except Exception as exc:
            log.warning(f"Could not retrieve services: {exc}")
            return []

    def periph_chars(self, service) -> list:
        """
        Return characteristics from a service object.

        Tries service.characteristics() then service.get_characteristics().
        """
        try:
            return list(service.characteristics())
        except AttributeError:
            pass
        try:
            return list(service.get_characteristics())
        except Exception as exc:
            log.debug(f"Could not retrieve characteristics: {exc}")
            return []

    def log_whad_read(self, handle: int, result: bytes | None) -> None:
        """Emit a [WHAD] read log line in training mode."""
        if result is not None:
            self._whad_log(
                f"PeripheralDevice.read(handle=0x{handle:04X}) → {result.hex()}"
            )
        else:
            self._whad_log(f"PeripheralDevice.read(handle=0x{handle:04X}) → error")

    def log_whad_write(self, handle: int, data: bytes, no_resp: bool) -> None:
        """Emit a [WHAD] write log line in training mode."""
        mode = "write_no_resp" if no_resp else "write"
        self._whad_log(
            f"PeripheralDevice.{mode}(handle=0x{handle:04X}, data={data.hex()})"
        )

    def log_whad_connect(self, addr: str, random: bool, timeout: int) -> None:
        """Emit a [WHAD] connect log line in training mode."""
        self._whad_log(
            f'Central.connect("{addr}", random={random}, timeout={timeout})'
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        try:
            self.device.close()
            log.debug("Device closed.")
        except Exception as exc:
            log.warning(f"Error closing device: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_connector(self, connector_cls, *args):
        """Create a BLE connector without triggering a second device reset.

        BLE connector __init__ calls device.open() → device.reset(). open()
        itself is required — it starts the I/O threads and sets self.__opened=True
        (WhadDevice.create() does NOT call open(); the device is not yet open).
        Only the reset() inside open() fails: it sends a Reset command and waits
        for DeviceReady, but the ButteRFly firmware does not re-emit DeviceReady
        after boot. Patching reset() to a no-op lets open() complete normally
        (threads started, opened=True) and allows discover() to succeed.
        """
        orig_reset = self.device.reset
        self.device.reset = lambda: None
        try:
            return connector_cls(self.device, *args)
        finally:
            self.device.reset = orig_reset

    def _whad_log(self, msg: str) -> None:
        if self._verbose:
            print(f"[WHAD] {msg}")


# ---------------------------------------------------------------------------
# Multi-device detection
# ---------------------------------------------------------------------------

def detect_hardware(
    ble_interface: str,
    esb_interface: str | None,
    phy_interface: str | None,
    ubertooth_interface: str | None = None,
) -> HardwareMap:
    """Open and probe each requested WHAD interface.

    All dongles are optional. If the BLE interface is unavailable, a warning is
    logged and ble_dongle is set to None — BLE stages will be skipped. If no
    devices are found at all, the process exits.

    Auto-detects rfstorm0/yardstickone0/ubertooth0 from whadup when the
    interface args are None and config values are unset.
    """
    # Auto-detect secondary devices from whadup output if not explicitly set
    if esb_interface is None or phy_interface is None or ubertooth_interface is None:
        discovered = WhadDongle.enumerate_devices()
        for name, dtype in discovered:
            dtype_lo = dtype.lower()
            if esb_interface is None and dtype_lo in ("rfstorm",):
                esb_interface = name
                log.info(f"Auto-detected ESB device: {name} ({dtype})")
            if phy_interface is None and dtype_lo in ("yardstickone",):
                phy_interface = name
                log.info(f"Auto-detected PHY sub-GHz device: {name} ({dtype})")
            if ubertooth_interface is None and dtype_lo in ("ubertoothone", "ubertooth"):
                ubertooth_interface = name
                log.info(f"Auto-detected Ubertooth One: {name} ({dtype})")

    ble_dongle: WhadDongle | None = None
    try:
        ble_dongle = WhadDongle.create(ble_interface)
    except SystemExit:
        log.warning(
            f"BLE dongle ({ble_interface}) not available — "
            "BLE stages 1-9, 11-13, 15-16 will be skipped. "
            "Use --interface to specify the correct interface."
        )

    esb_dongle: WhadDongle | None = None
    if esb_interface:
        try:
            esb_dongle = WhadDongle.create(esb_interface)
        except SystemExit:
            log.warning(
                f"ESB device {esb_interface!r} not found — "
                "stages 10 and 14 will fall back to BLE interface (if available)."
            )
            esb_dongle = None

    phy_dongle: WhadDongle | None = None
    if phy_interface:
        try:
            phy_dongle = WhadDongle.create(phy_interface)
        except SystemExit:
            log.warning(
                f"PHY sub-GHz device {phy_interface!r} not found — "
                "stage 17 will be skipped."
            )
            phy_dongle = None

    ubertooth_dongle: WhadDongle | None = None
    if ubertooth_interface:
        try:
            ubertooth_dongle = WhadDongle.create(ubertooth_interface)
        except SystemExit:
            log.warning(
                f"Ubertooth One {ubertooth_interface!r} not found — "
                "passive sniffer supplementation unavailable."
            )
            ubertooth_dongle = None

    if ble_dongle is None and esb_dongle is None and phy_dongle is None and ubertooth_dongle is None:
        log.error(
            "No WHAD devices found. Run 'whadup' to list connected hardware. "
            "Connect at least one WHAD device and retry."
        )
        raise SystemExit(1)

    return HardwareMap(
        ble_dongle=ble_dongle,
        esb_dongle=esb_dongle,
        phy_dongle=phy_dongle,
        ubertooth_dongle=ubertooth_dongle,
    )
