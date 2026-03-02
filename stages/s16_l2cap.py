"""
Stage 16 — L2CAP Connection-Oriented Channels (CoC) — Capability Gap

LE L2CAP CoC (Bluetooth Core 4.1+) provides a credit-based flow-control channel
above HCI for application data transfer. Security concerns include:

  - Unauthenticated CoC channels (PSM 0x0080–0x00FF) accepting connections
    without pairing — equivalent to unauth GATT writable characteristics
  - Credit exhaustion / flow-control abuse for denial-of-service
  - CoC spoofing on unencrypted connections

WHY THIS IS NOT IMPLEMENTED:
  The current WHAD version does not expose an L2CAP CoC connector or API.
  Neither `whad.ble.l2cap` nor an `L2CAPSniffer` class exists in the installed
  package. Direct HCI L2CAP_CoC_Connection_Request PDU injection via
  Central.enable_synchronous()/send_pdu() is theoretically possible but requires
  manual credit management — not implemented here.

FUTURE IMPLEMENTATION PATH:
  1. When WHAD adds a L2CAP CoC connector, wire it up here.
  2. Alternatively, use the Python `bleak` library on supported platforms,
     which exposes L2CAP CoC via asyncio sockets on Linux >= 5.10:
       sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
       sock.bind((local_addr, psm))
       sock.connect((target_addr, psm))
  3. Or send raw HCI L2CAP PDUs via Central.send_pdu() once WHAD exposes it.

This stub exists so the gap is visible rather than silently absent.
"""

from __future__ import annotations

from core.dongle import WhadDongle
from core.logger import get_logger

log = get_logger("s16_l2cap")


def run(dongle: WhadDongle, engagement_id: str) -> None:
    log.warning(
        "[S16] L2CAP CoC scanning is not implemented — WHAD does not expose an "
        "L2CAP CoC connector or PSM enumeration API in the current version. "
        "See stages/s16_l2cap.py for the gap description and future implementation path. "
        "Stage skipped."
    )
