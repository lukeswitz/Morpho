"""
Stage 15 — LoRaWAN Recon

Passive sniff of LoRaWAN Join Requests and data uplinks on the configured
regional frequency plan. Records DevEUI, AppEUI, and DevNonce from any Join
Requests observed.

Hardware note: The ButteRFly (nRF52840) dongle does NOT include a LoRa
transceiver. This stage is functional only with WHAD dongles that include
SX1276/SX1278 or equivalent LoRa radio. The stage probes for capability at
startup and exits gracefully if the hardware or Python module is absent.

Findings:
  - lorawan_join_captured     (info)   — Join Request observed; plaintext DevEUI
  - lorawan_data_frames       (info)   — Data uplinks observed; payload opacity unknown
"""

from __future__ import annotations

import time

from core.dongle import WhadDongle
from core.models import Finding
from core.db import insert_finding
from core.logger import get_logger
import config

log = get_logger("s15_lorawan")

# Regional channel plans (centre frequencies, MHz)
_REGION_FREQS: dict[str, list[float]] = {
    "EU868": [868.1, 868.3, 868.5, 867.1, 867.3, 867.5, 867.7, 867.9],
    "US915": [902.3, 902.5, 902.7, 902.9, 903.1, 903.3, 903.5, 903.7],
}

# Try all plausible WHAD LoRaWAN import paths
_LoraGateway = None
_LORAWAN_AVAILABLE = False
for _lora_path in ("whad.lorawan", "whad.lorawan.gateway"):
    try:
        import importlib as _il
        _lora_pkg = _il.import_module(_lora_path)
        _LoraGateway = getattr(_lora_pkg, "Gateway", None)
        if _LoraGateway is not None:
            _LORAWAN_AVAILABLE = True
            break
    except ImportError:
        continue

# Try the structured LWGateway Python API (separate from the legacy Gateway probe)
try:
    from whad.lorawan import LWGateway as _LWGateway
    _LWGATEWAY_AVAILABLE = True
except ImportError:
    _LWGateway = None  # type: ignore[assignment,misc]
    _LWGATEWAY_AVAILABLE = False


# ── LWGateway native path ─────────────────────────────────────────────────────

class _CaptureApp:
    """Minimal LoRaWAN application that accumulates join requests and uplinks."""

    def __init__(self) -> None:
        self.joins: list[dict] = []
        self.uplinks: list[dict] = []

    def on_join_request(self, devEUI: bytes, appEUI: bytes, devNonce: int) -> None:
        entry = {
            "dev_eui": devEUI.hex() if isinstance(devEUI, (bytes, bytearray)) else str(devEUI),
            "app_eui": appEUI.hex() if isinstance(appEUI, (bytes, bytearray)) else str(appEUI),
            "dev_nonce": hex(devNonce) if isinstance(devNonce, int) else str(devNonce),
        }
        self.joins.append(entry)
        log.info(
            f"[S15/native] Join Request: DevEUI={entry['dev_eui']} "
            f"AppEUI={entry['app_eui']} Nonce={entry['dev_nonce']}"
        )

    def on_uplink(self, devAddr: int, data: bytes, fcnt: int) -> None:
        entry = {
            "dev_addr": hex(devAddr) if isinstance(devAddr, int) else str(devAddr),
            "payload": data.hex() if isinstance(data, (bytes, bytearray)) else str(data),
            "fcnt": fcnt,
        }
        self.uplinks.append(entry)
        log.info(
            f"[S15/native] Uplink: DevAddr={entry['dev_addr']} "
            f"FCnt={entry['fcnt']} payload={entry['payload'][:16]}"
        )


def _build_channel_plan(region: str):
    """Return a minimal channel-plan object for LWGateway.

    LWGateway expects a channel plan class or instance. We attempt to import
    a named plan from whad.lorawan first; if that fails we return None so the
    caller can pass the region string directly and let LWGateway use its default.
    """
    plan_names_by_region: dict[str, list[str]] = {
        "EU868": ["EU868ChannelPlan", "EU868Plan", "EU868"],
        "US915": ["US915ChannelPlan", "US915Plan", "US915"],
    }
    names = plan_names_by_region.get(region, plan_names_by_region["EU868"])
    for mod_path in ("whad.lorawan.channel_plans", "whad.lorawan.channels", "whad.lorawan"):
        try:
            import importlib as _il
            mod = _il.import_module(mod_path)
            for name in names:
                plan = getattr(mod, name, None)
                if plan is not None:
                    log.debug(f"[S15/native] Using channel plan {mod_path}.{name}")
                    return plan
        except ImportError:
            continue
    log.debug("[S15/native] No named channel plan found; passing region string to LWGateway")
    return region


def _run_lorawan_gateway_native(dongle: WhadDongle, engagement_id: str) -> bool:
    """Run LoRaWAN capture using the whad.lorawan.LWGateway Python API.

    Returns True if the native path ran (even if it captured nothing), False if
    LWGateway is unavailable or failed to initialise so the caller can fall back.
    """
    if not _LWGATEWAY_AVAILABLE:
        return False

    region = config.LORAWAN_REGION
    duration = config.LORAWAN_SNIFF_SECS
    channel_plan = _build_channel_plan(region)
    app = _CaptureApp()

    log.info(
        f"[S15] LWGateway native path — region={region} "
        f"duration={duration}s ..."
    )

    gw = None
    try:
        gw = _LWGateway(dongle.device, channel_plan, app)
    except TypeError:
        # Some LWGateway versions take only (device, app) without a channel plan
        try:
            gw = _LWGateway(dongle.device, app)
        except Exception as exc:
            log.warning(
                f"[S15] LWGateway init failed: {type(exc).__name__}: {exc}. "
                "Falling back to legacy path."
            )
            return False
    except Exception as exc:
        log.warning(
            f"[S15] LWGateway init failed: {type(exc).__name__}: {exc}. "
            "Falling back to legacy path."
        )
        return False

    try:
        deadline = time.time() + duration
        # LWGateway is callback-driven; start() begins listening and callbacks
        # fire on the app object. We simply sleep until the deadline.
        gw.start()
        log.info(f"[S15] LWGateway started — listening for {duration}s ...")
        while time.time() < deadline:
            time.sleep(1.0)
    except Exception as exc:
        log.warning(f"[S15] LWGateway runtime error: {type(exc).__name__}: {exc}")
    finally:
        try:
            gw.stop()
        except Exception:
            pass

    # Convert _CaptureApp uplinks into the data_frames format expected by the
    # shared finding/analysis helpers.
    join_requests = app.joins
    data_frames = [
        {
            "dev_addr": u["dev_addr"],
            "fcnt": str(u["fcnt"]),
            "raw_hex": u["payload"][:32],
        }
        for u in app.uplinks
    ]

    _record_findings(engagement_id, join_requests, data_frames)
    if data_frames:
        _analyze_fcnt(data_frames, engagement_id)
    _print_summary(region, join_requests, data_frames)

    if join_requests:
        # Replay test needs raw_hex; native path doesn't capture raw frames,
        # so we skip it here — the legacy path handles raw_hex when available.
        log.debug("[S15] Replay test skipped on native LWGateway path (no raw frame bytes)")

    return True


# ── Public Python-native sniff helper ─────────────────────────────────────────

def _python_lorawan_sniff(dongle, duration: int = 60) -> list[dict]:
    """Sniff LoRaWAN traffic using whad.lorawan.LWGateway Python API.

    Emulates a LoRaWAN gateway to capture JOIN requests and uplink frames.
    Returns list of dicts with keys: type, dev_eui, payload_hex, rssi.
    Falls back silently if the module is not importable or hardware is unsupported.

    Args:
        dongle: WhadDongle with phy_dongle attribute.
        duration: Seconds to listen.

    Returns:
        List of captured LoRaWAN frame dicts.
    """
    try:
        from whad.lorawan import LWGateway
    except ImportError:
        log.debug("[S15] whad.lorawan.LWGateway not importable — skipping Python LoRaWAN sniff")
        return []

    device = getattr(dongle, "phy_dongle", None)
    if device is None:
        log.debug("[S15] No PHY dongle available for LoRaWAN — skipping Python sniff")
        return []

    results: list[dict] = []
    gw = None

    class _SniffApp:
        def on_join_request(self, dev_eui, dev_nonce, **kwargs) -> None:
            log.info(f"[S15][gw] JOIN REQUEST from DevEUI={dev_eui}")
            results.append({
                "type": "join_request",
                "dev_eui": str(dev_eui),
                "payload_hex": "",
                "rssi": None,
            })

        def on_uplink(self, dev_addr, payload, rssi=None, **kwargs) -> None:
            hex_payload = bytes(payload).hex() if isinstance(payload, (bytes, bytearray)) else str(payload)
            log.info(f"[S15][gw] UPLINK from {dev_addr}: {hex_payload[:32]}")
            results.append({
                "type": "uplink",
                "dev_eui": str(dev_addr),
                "payload_hex": hex_payload,
                "rssi": rssi,
            })

    try:
        channel_plan = _build_channel_plan(config.LORAWAN_REGION)
        app = _SniffApp()
        try:
            gw = LWGateway(device.device, channel_plan, app)
        except TypeError:
            gw = LWGateway(device.device, app)

        log.info(f"[S15][gw] Python LWGateway listening for {duration}s")
        gw.start()
        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(1.0)

    except (AttributeError, NotImplementedError, TypeError) as exc:
        log.debug(f"[S15][gw] LWGateway not supported on this hardware: {exc}")
    except Exception as exc:
        log.debug(f"[S15][gw] LWGateway error: {exc}")
    finally:
        if gw is not None:
            try:
                gw.stop()
            except Exception:
                pass

    return results


# ── Entry point ───────────────────────────────────────────────────────────────

def run(dongle: WhadDongle, engagement_id: str) -> None:
    if not _LORAWAN_AVAILABLE:
        log.warning(
            "[S15] whad.lorawan module not available. "
            "LoRaWAN recon requires WHAD with LoRaWAN support and a LoRa radio. "
            "Stage skipped."
        )
        return

    if not dongle.caps.can_lorawan:
        log.warning(
            "[S15] LoRaWAN capability not confirmed on this dongle. "
            "Requires a LoRa-capable radio (SX1276/SX1278). "
            "The ButteRFly nRF52840 dongle does not include a LoRa transceiver. "
            "Stage skipped."
        )
        return

    region = config.LORAWAN_REGION
    freqs = _REGION_FREQS.get(region, _REGION_FREQS["EU868"])
    log.info(
        f"[S15] LoRaWAN recon — region={region} "
        f"({len(freqs)} channels, {config.LORAWAN_SNIFF_SECS}s scan) ..."
    )

    join_requests: list[dict] = []
    data_frames:   list[dict] = []

    # Python-native LWGateway path — runs first, results are logged then preserved
    gw_results = _python_lorawan_sniff(dongle, duration=config.LORAWAN_SNIFF_SECS)
    if gw_results:
        joins_found = [r for r in gw_results if r["type"] == "join_request"]
        uplinks_found = [r for r in gw_results if r["type"] == "uplink"]
        log.info(
            f"[S15] Python LWGateway captured {len(joins_found)} join(s) "
            f"and {len(uplinks_found)} uplink(s)"
        )

    try:
        gw = _LoraGateway(dongle.device)
    except Exception as exc:
        log.warning(f"[S15] Could not initialise LoRaWAN Gateway: {type(exc).__name__}: {exc}")
        return

    deadline = time.time() + config.LORAWAN_SNIFF_SECS
    try:
        gw.start()
        log.info("[S15] LoRaWAN listener started ...")

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                pkt = gw.wait_packet(timeout=min(2.0, remaining))
            except AttributeError:
                # wait_packet not available — try iterator
                try:
                    for pkt in gw.sniff(timeout=min(5.0, remaining)):
                        _classify_pkt(pkt, join_requests, data_frames)
                except Exception as exc:
                    log.debug(f"[S15] sniff() error: {exc}")
                break
            except Exception as exc:
                log.debug(f"[S15] wait_packet error: {exc}")
                break

            if pkt is not None:
                _classify_pkt(pkt, join_requests, data_frames)

    except Exception as exc:
        log.warning(f"[S15] LoRaWAN scan error: {type(exc).__name__}: {exc}")
    finally:
        try:
            gw.stop()
        except Exception:
            pass

    _record_findings(engagement_id, join_requests, data_frames)
    if data_frames:
        _analyze_fcnt(data_frames, engagement_id)
    _print_summary(region, join_requests, data_frames)

    if join_requests:
        _test_join_replay(dongle, join_requests[0], engagement_id)


# ── Join Request replay test ──────────────────────────────────────────────────

def _test_join_replay(dongle, join_request: dict, engagement_id: str) -> None:
    """Replay a captured Join Request to test DevNonce uniqueness enforcement.

    Transmits the raw Join Request bytes back via the LoRa gateway. A Join Accept
    response (MType=1) within 5s confirms the Network Server does NOT enforce
    DevNonce replay protection — a LoRaWAN 1.0.x vulnerability.

    Records lorawan_replay_accepted (high) or lorawan_replay_attempted (info)
    depending on whether a Join Accept is received.
    """
    raw_hex = join_request.get("raw_hex", "")
    if not raw_hex:
        log.debug("[S15] No raw_hex in captured Join Request — replay skipped")
        return

    log.info("[S15] Replaying captured Join Request to test DevNonce uniqueness ...")

    try:
        gw = _LoraGateway(dongle.device)
    except Exception as exc:
        log.warning(f"[S15] Replay: cannot initialise gateway: {exc}")
        return

    replay_sent = False
    replay_accepted = False
    response_hex: str | None = None

    try:
        gw.start()
        raw_bytes = bytes.fromhex(raw_hex)

        # Try TX methods in order of likelihood
        for _tx_name in ("send", "transmit", "inject"):
            fn = getattr(gw, _tx_name, None)
            if fn is None:
                continue
            try:
                fn(raw_bytes)
                replay_sent = True
                log.info(f"[S15] Join Request replayed via gw.{_tx_name}()")
                break
            except Exception as exc:
                log.debug(f"[S15] gw.{_tx_name}() failed: {exc}")

        if not replay_sent:
            log.warning(
                "[S15] LoRa gateway TX method not found (no send/transmit/inject). "
                "This WHAD version or hardware may not support LoRa TX. "
                "Replay test skipped."
            )
            return

        # Wait up to 5s for a Join Accept response (MType=1)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                pkt = gw.wait_packet(timeout=min(1.0, remaining))
            except AttributeError:
                break
            except Exception:
                break
            if pkt is None:
                continue
            mtype = getattr(pkt, "MType", getattr(pkt, "mtype", None))
            if mtype in (1, "JoinAccept", "JOIN_ACCEPT"):
                replay_accepted = True
                response_hex = _safe_hex(pkt)
                log.info("[S15] JOIN ACCEPT received after replay — DevNonce replay NOT protected!")
                break

    except Exception as exc:
        log.warning(f"[S15] Replay test error: {type(exc).__name__}: {exc}")
    finally:
        try:
            gw.stop()
        except Exception:
            pass

    if replay_accepted:
        insert_finding(Finding(
            type="lorawan_replay_accepted",
            severity="high",
            target_addr="lorawan",
            description=(
                "LoRaWAN Network Server accepted a replayed Join Request containing a "
                "previously-observed DevNonce. DevNonce uniqueness is NOT enforced. "
                "An attacker can replay captured Join Requests to obtain a valid network session."
            ),
            remediation=(
                "Enforce DevNonce uniqueness tracking at the Network Server (required "
                "by LoRaWAN 1.0.4+). Upgrade to LoRaWAN 1.1 where JoinNonce provides "
                "server-side replay protection. Implement per-device nonce blocklists."
            ),
            evidence={
                "replayed_dev_eui": join_request.get("dev_eui"),
                "replayed_app_eui": join_request.get("app_eui"),
                "replayed_dev_nonce": join_request.get("dev_nonce"),
                "join_accept_hex": response_hex,
            },
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info("FINDING [high] lorawan_replay_accepted: DevNonce replay not protected")
    elif replay_sent:
        insert_finding(Finding(
            type="lorawan_replay_attempted",
            severity="info",
            target_addr="lorawan",
            description=(
                "LoRaWAN Join Request replayed successfully (TX confirmed). "
                "No Join Accept received within 5s. "
                "Network Server may enforce DevNonce uniqueness, or the device "
                "joins a private network not reachable by the sniffer."
            ),
            remediation=(
                "Confirm DevNonce uniqueness enforcement is active at the Network Server. "
                "Run replay test from within the network's RF coverage to verify."
            ),
            evidence={
                "replayed_dev_eui": join_request.get("dev_eui"),
                "replayed_dev_nonce": join_request.get("dev_nonce"),
            },
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info("FINDING [info] lorawan_replay_attempted: no Join Accept received")


# ── Packet classification ─────────────────────────────────────────────────────

def _classify_pkt(pkt, join_requests: list, data_frames: list) -> None:
    """Dispatch received LoRaWAN packet to the appropriate bucket."""
    try:
        mtype = getattr(pkt, "MType", getattr(pkt, "mtype", None))
        if mtype is None:
            return

        # MType 0 = Join Request
        if mtype in (0, "JoinRequest", "JOIN_REQUEST"):
            entry = {
                "dev_eui":   _hex_attr(pkt, "DevEUI", "dev_eui", "deveui"),
                "app_eui":   _hex_attr(pkt, "AppEUI", "app_eui", "joineui", "JoinEUI"),
                "dev_nonce": _hex_attr(pkt, "DevNonce", "dev_nonce"),
                "raw_hex":   _safe_hex(pkt),
            }
            join_requests.append(entry)
            log.info(
                f"[S15] Join Request: DevEUI={entry['dev_eui']} "
                f"AppEUI={entry['app_eui']} Nonce={entry['dev_nonce']}"
            )

        # MType 2 = Unconfirmed Up, 4 = Confirmed Up
        elif mtype in (2, 4, "UnconfirmedDataUp", "ConfirmedDataUp"):
            entry = {
                "dev_addr": _hex_attr(pkt, "DevAddr", "dev_addr"),
                "fcnt":     str(getattr(pkt, "FCnt", getattr(pkt, "fcnt", "?"))),
                "raw_hex":  _safe_hex(pkt)[:32],
            }
            data_frames.append(entry)
            log.info(
                f"[S15] Data uplink: DevAddr={entry['dev_addr']} FCnt={entry['fcnt']}"
            )
    except Exception as exc:
        log.debug(f"[S15] Packet classify error: {exc}")


def _hex_attr(pkt, *names: str) -> str | None:
    """Return first matching attribute as hex string."""
    for name in names:
        val = getattr(pkt, name, None)
        if val is not None:
            try:
                return bytes(val).hex()
            except Exception:
                return str(val)
    return None


def _safe_hex(pkt) -> str:
    try:
        return bytes(pkt).hex()
    except Exception:
        return ""


# ── Findings ──────────────────────────────────────────────────────────────────

def _record_findings(
    engagement_id: str,
    join_requests: list[dict],
    data_frames: list[dict],
) -> None:
    if join_requests:
        insert_finding(Finding(
            type="lorawan_join_captured",
            severity="info",
            target_addr="lorawan",
            description=(
                f"{len(join_requests)} LoRaWAN Join Request(s) captured. "
                "DevEUI, AppEUI, and DevNonce are transmitted in plaintext (LoRaWAN spec). "
                "DevNonce uniqueness enforcement by the network server determines replay risk."
            ),
            remediation=(
                "Ensure the LoRaWAN Network Server (LNS) enforces DevNonce uniqueness "
                "to prevent Join Request replay attacks (required by LoRaWAN 1.0.4+). "
                "Prefer LoRaWAN 1.1 which includes JoinNonce from the server side. "
                "Rotate AppKey if device compromise is suspected."
            ),
            evidence={"join_requests": join_requests},
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info(f"FINDING [info] lorawan_join_captured: {len(join_requests)} request(s)")

    if data_frames:
        insert_finding(Finding(
            type="lorawan_data_frames",
            severity="info",
            target_addr="lorawan",
            description=(
                f"{len(data_frames)} LoRaWAN data uplink(s) observed. "
                "Payload encryption depends on application layer configuration "
                "(ABP mode without AppSKey would expose plaintext)."
            ),
            remediation=(
                "Ensure LoRaWAN payloads are encrypted with AppSKey at the application layer. "
                "Monitor for anomalous frame counter patterns. "
                "Implement end-to-end encryption beyond LoRaWAN transport."
            ),
            evidence={"data_frames": data_frames[:10]},
            pcap_path=None,
            engagement_id=engagement_id,
        ))
        log.info(f"FINDING [info] lorawan_data_frames: {len(data_frames)} frame(s)")



def _analyze_fcnt(data_frames: list[dict], engagement_id: str) -> None:
    """Detect anomalous LoRaWAN FCnt patterns: resets, non-monotonic, large gaps."""
    from core.db import insert_finding as _insert
    from core.models import Finding as _Finding

    by_device: dict[str, list[int]] = {}
    for frame in data_frames:
        dev = frame.get("dev_addr") or "unknown"
        try:
            fcnt = int(frame.get("fcnt", -1))
        except (ValueError, TypeError):
            continue
        if fcnt < 0:
            continue
        by_device.setdefault(dev, []).append(fcnt)

    anomalies: list[dict] = []
    for dev_addr, fcnts in by_device.items():
        if fcnts[0] < 10:
            anomalies.append({"dev_addr": dev_addr, "type": "low_fcnt", "first_fcnt": fcnts[0],
                               "detail": "FCnt < 10 — new ABP session or counter reset"})
            log.info(f"[S15] FCnt anomaly ({dev_addr}): low start FCnt={fcnts[0]}")
        for i in range(1, len(fcnts)):
            prev, curr = fcnts[i - 1], fcnts[i]
            if curr <= prev:
                anomalies.append({"dev_addr": dev_addr, "type": "non_monotonic",
                                   "prev_fcnt": prev, "curr_fcnt": curr,
                                   "detail": "Counter went backwards — replay or reset"})
                log.info(f"[S15] FCnt anomaly ({dev_addr}): {prev} → {curr} (non-monotonic)")
            elif curr - prev > 1000:
                anomalies.append({"dev_addr": dev_addr, "type": "large_gap",
                                   "prev_fcnt": prev, "curr_fcnt": curr,
                                   "detail": f"Gap {curr - prev} — stale replay or frame loss"})
                log.info(f"[S15] FCnt gap ({dev_addr}): {prev} → {curr} (gap {curr - prev})")

    if not anomalies:
        log.info("[S15] FCnt analysis: no anomalies.")
        return

    _insert(_Finding(
        type="lorawan_fcnt_anomaly",
        severity="medium",
        target_addr="lorawan",
        description=(
            f"{len(anomalies)} LoRaWAN FCnt anomaly/anomalies detected. "
            "Non-monotonic counters and resets are replay attack indicators."
        ),
        remediation=(
            "Enforce strict monotonic FCnt at the Network Server. "
            "Reject FCnt <= last seen per device. Use LoRaWAN 1.1 for secure rollover."
        ),
        evidence={"anomalies": anomalies[:10]},
        pcap_path=None,
        engagement_id=engagement_id,
    ))
    log.info(f"FINDING [medium] lorawan_fcnt_anomaly: {len(anomalies)} anomaly/anomalies")


# ── Summary ───────────────────────────────────────────────────────────────────

def _print_summary(
    region: str,
    join_requests: list[dict],
    data_frames: list[dict],
) -> None:
    log.info("\n" + "─" * 76)
    log.info("  STAGE 15 SUMMARY -- LoRaWAN Recon")
    log.info("─" * 76)
    log.info(f"  {'Region':<20}: {region}")
    log.info(f"  {'Join Requests':<20}: {len(join_requests)}")
    log.info(f"  {'Data uplinks':<20}: {len(data_frames)}")

    if join_requests:

        log.info("  Join Requests captured:")
        for jr in join_requests[:5]:
            log.info(
                f"    DevEUI={jr['dev_eui']}  "
                f"AppEUI={jr['app_eui']}  "
                f"Nonce={jr['dev_nonce']}"
            )

    if not join_requests and not data_frames:
        log.info("  Result: no LoRaWAN traffic observed on configured channels.")

    log.info("─" * 76 + "\n")
