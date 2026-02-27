"""
core/device.py — backward-compatible shim.

New code should import WhadDongle from core.dongle directly.
This module exists so any external scripts using open_device / close_device
continue to work unchanged.
"""

from core.dongle import WhadDongle
import config


def open_device(interface: str = config.INTERFACE) -> WhadDongle:
    """Open device and probe capabilities. Returns a WhadDongle."""
    return WhadDongle.create(interface)


def close_device(dongle: WhadDongle) -> None:
    """Close the dongle's underlying device connection."""
    dongle.close()
