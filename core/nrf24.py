"""
core/nrf24.py — Bastille nRF Research Firmware USB interface.

Wraps the Bastille Research nRF Research Firmware dongle (VID 0x1915,
PID 0x0102) via PyUSB for MouseJack 2.4 GHz reconnaissance and injection.

Hardware: any nRF24L01+ USB dongle flashed with:
  https://github.com/BastilleResearch/nrf-research-firmware
Typically a CrazyRadio PA, SparkFun nRF24L01+ USB Dongle, or clone.

Protocol: USB bulk endpoint transfers.
  OUT (host→device): endpoint 0x01 — command byte prepended to data
  IN  (device→host): endpoint 0x81 — 64-byte response buffer

Source of truth: BastilleResearch/nrf-research-firmware tools/lib/nrf24.py
                 insecurityofthings/jackit jackit/lib/nrf24.py
"""

from __future__ import annotations

import time
from typing import Iterator

from core.logger import get_logger

log = get_logger("nrf24")

# USB device identifiers (Bastille nRF Research Firmware)
_VID = 0x1915
_PID = 0x0102

# USB bulk endpoints
_EP_OUT = 0x01   # host → device
_EP_IN  = 0x81   # device → host

# Firmware command bytes (prepended to each bulk write).
# Source: BastilleResearch/nrf-research-firmware tools/lib/nrf24.py
_CMD_TRANSMIT_PAYLOAD               = 0x04
_CMD_ENTER_SNIFFER_MODE             = 0x05
_CMD_ENTER_PROMISCUOUS_MODE         = 0x06
_CMD_ENTER_TONE_TEST_MODE           = 0x07
_CMD_TRANSMIT_ACK_PAYLOAD           = 0x08
_CMD_SET_CHANNEL                    = 0x09
_CMD_GET_CHANNEL                    = 0x0A
_CMD_ENABLE_LNA_PA                  = 0x0B
_CMD_TRANSMIT_PAYLOAD_GENERIC       = 0x0C
_CMD_ENTER_PROMISCUOUS_MODE_GENERIC = 0x0D
_CMD_RECEIVE_PAYLOAD                = 0x12

# Travis Goodspeed promiscuous trick: 2-byte address prefix that aligns with
# the nRF24L01+ preamble byte (0xAA = alternating bits). With CRC disabled
# the radio accepts all on-air packets regardless of their actual address.
_PROMISCUOUS_PREFIX: list[int] = [0xAA, 0x00]

_USB_TIMEOUT_MS = 2500

# Data rate labels (informational — firmware handles rate internally)
RATE_250K = 0
RATE_1M   = 1
RATE_2M   = 2

RATE_LABELS: dict[int, str] = {
    RATE_250K: "250kbps",
    RATE_1M:   "1Mbps",
    RATE_2M:   "2Mbps",
}


class MouseJackDongle:
    """
    USB interface to a Bastille nRF Research Firmware dongle.

    I/O uses USB bulk endpoint transfers (EP 0x01 OUT, EP 0x81 IN).
    Each command is a single byte prepended to the data payload.
    Receive is polled via RECEIVE_PAYLOAD (0x12) requests.

    Usage:
        dongle = MouseJackDongle.find()
        if dongle:
            with dongle:
                dongle.enter_promiscuous_mode()
                dongle.set_channel(0)
                payload = dongle.receive_payload()
    """

    def __init__(self, device: object) -> None:
        self._dev = device

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def find(cls, idx: int = 0) -> "MouseJackDongle | None":
        """Find and open the idx-th nRF Research Firmware dongle.

        Returns None if PyUSB is not installed or no device is present.
        """
        try:
            import usb.core
            import usb.util
        except ImportError:
            log.debug("PyUSB not installed — MouseJack stage unavailable.")
            return None

        devices = list(usb.core.find(idVendor=_VID, idProduct=_PID, find_all=True))
        if not devices:
            log.debug(
                f"No nRF Research Firmware device found "
                f"(VID={_VID:#06x}, PID={_PID:#06x}). "
                "Flash a CrazyRadio PA or nRF24L01+ dongle with the Bastille firmware."
            )
            return None
        if idx >= len(devices):
            log.warning(
                f"MouseJack device index {idx} requested but only "
                f"{len(devices)} device(s) found."
            )
            return None

        dev = devices[idx]
        try:
            dev.set_configuration()
        except usb.core.USBError as exc:
            if "already" not in str(exc).lower():
                log.warning(f"[nrf24] set_configuration: {exc}")
        try:
            usb.util.claim_interface(dev, 0)
        except usb.core.USBError as exc:
            log.warning(f"[nrf24] claim_interface: {exc}")

        dongle = cls(dev)
        dongle.enable_lna_pa()
        log.info(f"[nrf24] Dongle opened (VID={_VID:#06x} PID={_PID:#06x})")
        return dongle

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def close(self) -> None:
        try:
            import usb.util
            usb.util.release_interface(self._dev, 0)
            usb.util.dispose_resources(self._dev)
        except Exception as exc:
            log.debug(f"[nrf24] close: {exc}")

    def __enter__(self) -> "MouseJackDongle":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Low-level USB I/O ──────────────────────────────────────────────────

    def _send(self, command: int, data: list[int] | bytes = b"") -> None:
        """Write command + data to the bulk OUT endpoint (0x01)."""
        self._dev.write(_EP_OUT, [command] + list(data), timeout=_USB_TIMEOUT_MS)

    def _recv(self, length: int = 64) -> bytes:
        """Read up to `length` bytes from the bulk IN endpoint (0x81)."""
        return bytes(self._dev.read(_EP_IN, length, timeout=_USB_TIMEOUT_MS))

    # ── Radio control ──────────────────────────────────────────────────────

    def enable_lna_pa(self) -> None:
        """Enable LNA/PA for maximum receive sensitivity. Call once after open."""
        try:
            self._send(_CMD_ENABLE_LNA_PA, [1])
        except Exception as exc:
            log.debug(f"[nrf24] enable_lna_pa: {exc}")

    def set_channel(self, channel: int) -> None:
        """Set RF channel (0–99 → 2402–2501 MHz)."""
        self._send(_CMD_SET_CHANNEL, [max(0, min(99, channel))])

    def get_channel(self) -> int:
        """Read the currently tuned RF channel."""
        try:
            self._send(_CMD_GET_CHANNEL)
            result = self._recv(1)
            return result[0] if result else 0
        except Exception:
            return 0

    def enter_promiscuous_mode(self, prefix: list[int] | None = None) -> None:
        """Enter promiscuous capture mode (Goodspeed promiscuous trick).

        Sets a 2-byte address prefix aligned with the nRF preamble byte.
        The radio accepts all on-air packets — real device addresses must
        be extracted from the captured payload bytes.

        Args:
            prefix: Address prefix bytes. None → default 2-byte [0xAA, 0x00].
        """
        if prefix is None:
            prefix = _PROMISCUOUS_PREFIX
        self._send(_CMD_ENTER_PROMISCUOUS_MODE, [len(prefix)] + list(prefix))

    def enter_sniffer_mode(self, address: bytes) -> None:
        """Enter targeted sniffer mode for a known 5-byte device address.

        The firmware filters packets to this address and enables auto-ACK,
        making the sniff transparent to the target. Also used to configure
        the TX address before calling transmit_payload().

        Args:
            address: 5-byte ESB address (big-endian, MSB first).
        """
        self._send(_CMD_ENTER_SNIFFER_MODE, [len(address)] + list(address))

    def receive_payload(self) -> bytes | None:
        """Poll for one received packet. Returns None if the buffer is empty.

        Sends RECEIVE_PAYLOAD (0x12) and reads 64 bytes. Byte 0 of the
        response is a status/count field — zero means no packet queued.
        """
        try:
            self._send(_CMD_RECEIVE_PAYLOAD)
            result = self._recv(64)
        except Exception as exc:
            log.debug(f"[nrf24] receive_payload: {exc}")
            return None
        if not result or result[0] == 0:
            return None
        return bytes(result[1:])

    def transmit_payload(
        self,
        payload: bytes,
        timeout: int = 4,
        retransmits: int = 15,
    ) -> bool:
        """Transmit a raw ESB payload to the address set by enter_sniffer_mode().

        Payload wire format: [len(payload), timeout, retransmits] + payload.
        Returns True if the firmware acknowledged the transmit request.

        Args:
            payload: Raw ESB payload bytes (e.g. HID keyboard report).
            timeout: Per-attempt timeout (firmware units, default 4).
            retransmits: Number of retransmit attempts on no-ACK (default 15).
        """
        data = [len(payload), timeout, retransmits] + list(payload)
        try:
            self._send(_CMD_TRANSMIT_PAYLOAD, data)
            result = self._recv(64)
            return bool(result and result[0] > 0)
        except Exception as exc:
            log.debug(f"[nrf24] transmit_payload: {exc}")
            return False

    # ── Higher-level scan helpers ──────────────────────────────────────────

    def scan_promiscuous(
        self,
        channels: list[int],
        rate: int,
        dwell_ms: int = 100,
    ) -> Iterator[tuple[int, bytes]]:
        """Yield (channel, raw_payload) from promiscuous mode across channels.

        Rotates through `channels` spending `dwell_ms` on each.

        Args:
            channels: Channel numbers to cycle through (0–99).
            rate: Data rate constant (informational — not sent to firmware).
            dwell_ms: Milliseconds per channel before rotating.
        """
        self.enter_promiscuous_mode()
        dwell = dwell_ms / 1000.0
        for ch in channels:
            self.set_channel(ch)
            deadline = time.monotonic() + dwell
            while time.monotonic() < deadline:
                pkt = self.receive_payload()
                if pkt is not None:
                    yield ch, pkt
                else:
                    time.sleep(0.001)

    def sniff_address(
        self,
        address: bytes,
        channels: list[int],
        rate: int,
        duration_s: float,
        dwell_ms: int = 200,
    ) -> Iterator[tuple[int, bytes]]:
        """Yield (channel, payload) from targeted sniff of a known address.

        Hops through `channels` until `duration_s` elapses.

        Args:
            address: 5-byte device address.
            channels: Channels to scan.
            rate: Data rate constant (informational — not sent to firmware).
            duration_s: Total scan duration.
            dwell_ms: Per-channel dwell time.
        """
        self.enter_sniffer_mode(address)
        dwell = dwell_ms / 1000.0
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            for ch in channels:
                self.set_channel(ch)
                ch_deadline = min(deadline, time.monotonic() + dwell)
                while time.monotonic() < ch_deadline:
                    pkt = self.receive_payload()
                    if pkt is not None:
                        yield ch, pkt
                    else:
                        time.sleep(0.001)
