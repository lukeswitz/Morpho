from __future__ import annotations

from enum import Enum
from rich.text import Text
from textual.widget import Widget
from textual.app import RenderResult


class StageState(Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    SKIPPED  = "skipped"
    ERROR    = "error"


# All 23 stage labels — mirrors _STAGE_GROUPS in morpho.py
_STAGE_LABELS: dict[int, str] = {
    1:  "S01 env mapping",
    2:  "S02 conn intel",
    3:  "S03 identity clone",
    4:  "S04 reactive jam*",
    5:  "S05 gatt enum",
    6:  "S06 mitm proxy*",
    7:  "S07 gatt fuzzer",
    8:  "S08 semantic poc",
    9:  "S09 inject*",
    10: "S10 unifying",
    11: "S11 zigbee",
    12: "S12 phy 2.4GHz",
    13: "S13 smp pairing",
    14: "S14 esb scan",
    15: "S15 lorawan",
    16: "S16 l2cap*",
    17: "S17 sub-ghz*",
    18: "S18 esb prx/ptx*",
    19: "S19 unifying api*",
    20: "S20 ble hijacker*",
    21: "S21 br/edr",
    22: "S22 rf4ce*",
    23: "S23 raw 802.15.4",
}

_STATE_MARKERS: dict[StageState, tuple[str, str]] = {
    StageState.PENDING:  ("░", "#555555"),
    StageState.RUNNING:  ("►", "bold #ffff00"),
    StageState.COMPLETE: ("✓", "#00ff00"),
    StageState.SKIPPED:  ("─", "strike #333333"),
    StageState.ERROR:    ("✗", "bold #ff0000"),
}


class StageStatusWidget(Widget):
    """Left panel: vertical list of stage status indicators."""

    def __init__(self, requested_stages: set[int]) -> None:
        super().__init__()
        # Empty set = auto-detect mode: all stages start PENDING (run_stages picks them).
        # Non-empty set: requested stages PENDING, others SKIPPED.
        auto = not requested_stages
        self._states: dict[int, StageState] = {
            n: (StageState.PENDING if (auto or n in requested_stages) else StageState.SKIPPED)
            for n in _STAGE_LABELS
        }

    def on_mount(self) -> None:
        self.border_title = "STAGES"

    def render(self) -> RenderResult:
        text = Text()
        for num in sorted(_STAGE_LABELS):
            label = _STAGE_LABELS[num]
            state = self._states.get(num, StageState.SKIPPED)
            marker, style = _STATE_MARKERS[state]
            text.append(f" {marker} {label}\n", style=style)
        return text

    def set_stage_state(self, stage: int, state: StageState) -> None:
        """Update a stage's state and redraw. Safe to call from event loop."""
        if stage in self._states:
            self._states[stage] = state
            self.refresh()
