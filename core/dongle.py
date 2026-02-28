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
    firmware_version:   str | None = None
    device_type:        str = "unknown"  # "butterfly" | "hci" | "unknown"

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
        ]


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
        """
        Return a list of WHAD interface strings for all connected devices.
        Calls `whadup` and parses its output. Falls back to empty list on error.
        """
        try:
            result = subprocess.run(
                ["whadup"],
                capture_output=True,
                text=True,
                timeout=config.DONGLE_TIMEOUT,
            )
            interfaces: list[str] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                # whadup output lines look like:  uart0  UartDevice  /dev/ttyACM0
                if line.startswith("uart") or line.startswith("hci"):
                    parts = line.split()
                    if parts:
                        interfaces.append(parts[0])
            return interfaces
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
        if "uart" in self.interface.lower():
            caps.device_type = "butterfly"
        elif "hci" in self.interface.lower():
            caps.device_type = "hci"

        # Try to read firmware version from device info
        try:
            info = self.device.get_domain_info()
            if info and hasattr(info, "fw_version"):
                caps.firmware_version = str(info.fw_version)
        except Exception:
            pass

        # --- Probes 1–6: class-level checks only — NO instantiation ---
        # Instantiating a connector and calling start()/stop() registers it
        # with the WhadDevice and causes WhadDeviceTimeout on ButteRFly.
        # For ButteRFly firmware, capability == class importability, so
        # import + hasattr is sufficient for all connectors.

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
        s = Scanner(self.device)
        self._whad_log("Scanner created")
        return s

    def sniffer(self):
        """Return a configured Sniffer. Asserts can_sniff."""
        from whad.ble import Sniffer
        self.assert_cap("can_sniff")
        s = Sniffer(self.device)
        self._whad_log("Sniffer created")
        return s

    def central(self):
        """Return a configured Central. Asserts can_central."""
        from whad.ble import Central
        self.assert_cap("can_central")
        c = Central(self.device)
        self._whad_log("Central created")
        return c

    def peripheral(self, profile=None):
        """Return a configured Peripheral. Asserts can_peripheral."""
        from whad.ble import Peripheral
        from whad.ble.profile import GenericProfile
        self.assert_cap("can_peripheral")
        p = Peripheral(self.device, profile=profile or GenericProfile())
        self._whad_log("Peripheral created")
        return p

    def ble_connector(self):
        """Return a raw BLE base connector (used by s4_jam)."""
        from whad.ble.connector import BLE
        c = BLE(self.device)
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

    def _whad_log(self, msg: str) -> None:
        if self._verbose:
            print(f"[WHAD] {msg}")
