from __future__ import annotations

from dataclasses import dataclass, field
from textual.app import ComposeResult
from textual.message import Message
from textual.screen import Screen
from rich.text import Text as RichText
from textual.widgets import Button, Checkbox, Input, Label, Static
from textual.containers import Grid, Horizontal, Vertical, ScrollableContainer

import config


# ── BBS art header (shown at top of launch form) ──────────────────────────────
# Block-letter art from main.py._banner(), plus RUBY WAVES subtitle
_BBS_ART = """\
  \u2584\u2584\u2584\u2584  \u2584\u2584 \u2584\u2584 \u2584\u2584\u2584\u2584  \u2584\u2584 \u2584\u2584 \u2588\u2588     \u2588\u2588  \u2584\u2584\u2584  \u2584\u2584 \u2584\u2584 \u2584\u2584\u2584\u2584\u2584  \u2584\u2584\u2584\u2584
  \u2588\u2588\u2584\u2588\u2584 \u2588\u2588 \u2588\u2588 \u2588\u2588\u2584\u2588\u2588 \u2580\u2588\u2588\u2588\u2580 \u2588\u2588 \u2584\u2588\u2584 \u2588\u2588 \u2588\u2588\u2580\u2588\u2588 \u2588\u2588\u2584\u2588\u2588 \u2588\u2588\u2584\u2584  \u2588\u2588\u2588\u2584\u2584
  \u2588\u2588 \u2588\u2588 \u2580\u2588\u2588\u2588\u2580 \u2588\u2588\u2584\u2588\u2580   \u2588    \u2580\u2588\u2588\u2580\u2588\u2588\u2580  \u2588\u2588\u2580\u2588\u2588  \u2580\u2588\u2580  \u2588\u2588\u2584\u2584\u2584 \u2584\u2584\u2588\u2588\u2580
  """

# All 23 stages: (number, label, is_opt_in)
_ALL_STAGES: list[tuple[int, str, bool]] = [
    (1,  "S01 env mapping",      False),
    (2,  "S02 conn intel",       False),
    (3,  "S03 identity clone",   False),
    (4,  "S04 reactive jam",     True),
    (5,  "S05 gatt enum+shell",  False),
    (6,  "S06 mitm proxy",       True),
    (7,  "S07 gatt fuzzer",      False),
    (8,  "S08 semantic poc",     False),
    (9,  "S09 inject",           True),
    (10, "S10 unifying",         False),
    (11, "S11 zigbee",           False),
    (12, "S12 phy 2.4GHz",       False),
    (13, "S13 smp pairing",      False),
    (14, "S14 esb scan",         False),
    (15, "S15 lorawan",          False),
    (16, "S16 l2cap",            True),
    (17, "S17 sub-ghz",          True),
    (18, "S18 esb prx/ptx",      True),
    (19, "S19 unifying api",     True),
    (20, "S20 ble hijacker",     True),
    (21, "S21 br/edr",           False),
    (22, "S22 rf4ce",            True),
    (23, "S23 raw 802.15.4",     False),
]


@dataclass
class LaunchConfig:
    """All parameters needed to start a run. Passed to run_stages()."""
    name: str = "unnamed"
    location: str = ""
    interface: str = "uart0"
    esb_interface: str = ""
    phy_interface: str = ""
    ubertooth_interface: str = ""
    proxy_interface: str = "hci0"
    scan_duration: int = 120
    stages: set[int] = field(default_factory=set)   # empty = auto-detect
    no_gate: bool = False
    debug: bool = False


class LaunchScreen(Screen):
    """BBS-style engagement configuration form. Emits Launched when operator submits."""

    class Launched(Message):
        """Posted when operator clicks LAUNCH. Carries the collected LaunchConfig."""
        def __init__(self, cfg: LaunchConfig) -> None:
            super().__init__()
            self.cfg = cfg

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        with ScrollableContainer():
            with Vertical(classes="launch-box"):
                yield Static(_BBS_ART, classes="bbs-art")

                yield Label("Engagement Name:")
                yield Input(
                    value=getattr(config, "ENGAGEMENT_NAME", ""),
                    placeholder="e.g. Lobby Floor 1",
                    id="inp-name",
                )
                yield Label("Location:")
                yield Input(placeholder="e.g. Building A", id="inp-location")

                yield Label("BLE Interface:")
                yield Input(value=config.INTERFACE, id="inp-iface")

                yield Label("ESB Interface (blank = auto):")
                yield Input(
                    value=config.ESB_INTERFACE or "",
                    placeholder="rfstorm0",
                    id="inp-esb",
                )
                yield Label("PHY Interface (blank = auto):")
                yield Input(
                    value=config.PHY_SUBGHZ_INTERFACE or "",
                    placeholder="yardstickone0",
                    id="inp-phy",
                )
                yield Label("Ubertooth Interface (blank = auto):")
                yield Input(
                    value=config.UBERTOOTH_INTERFACE or "",
                    placeholder="ubertooth0",
                    id="inp-ubertooth",
                )
                yield Label("Scan Duration (seconds):")
                yield Input(value=str(config.SCAN_DURATION), id="inp-duration")

                yield Static("Stages  (* = opt-in, unchecked by default)", classes="launch-section-label")
                with Grid(classes="stage-grid"):
                    for num, label, opt_in in _ALL_STAGES:
                        marker = "*" if opt_in else " "
                        yield Checkbox(
                            f"{marker}{label}",
                            value=not opt_in,
                            id=f"cb-{num}",
                        )

                yield Checkbox(
                    "Disable active gates (--no-gate)",
                    id="cb-nogate",
                    value=False,
                )
                yield Checkbox("Debug logging", id="cb-debug", value=False)
                _lbl = RichText("[ LAUNCH ENGAGEMENT ]", style="bold #00ffff")
                yield Button(_lbl, id="btn-launch")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-launch":
            return
        self.post_message(self.Launched(self._collect_config()))

    def _collect_config(self) -> LaunchConfig:
        def _inp(id_: str) -> str:
            return self.query_one(f"#{id_}", Input).value.strip()

        def _cb(id_: str) -> bool:
            return self.query_one(f"#{id_}", Checkbox).value

        stages: set[int] = set()
        for num, _, _ in _ALL_STAGES:
            if _cb(f"cb-{num}"):
                stages.add(num)

        try:
            duration = int(_inp("inp-duration"))
        except ValueError:
            duration = config.SCAN_DURATION

        return LaunchConfig(
            name=_inp("inp-name") or "unnamed",
            location=_inp("inp-location"),
            interface=_inp("inp-iface") or config.INTERFACE,
            esb_interface=_inp("inp-esb"),
            phy_interface=_inp("inp-phy"),
            ubertooth_interface=_inp("inp-ubertooth"),
            proxy_interface=config.PROXY_INTERFACE,
            scan_duration=duration,
            stages=stages,
            no_gate=_cb("cb-nogate"),
            debug=_cb("cb-debug"),
        )
