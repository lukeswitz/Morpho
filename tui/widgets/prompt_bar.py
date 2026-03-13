from __future__ import annotations

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, Label


class PromptBar(Widget):
    """
    Bottom-docked free-text prompt zone.

    Hidden by default (display: none in CSS). Shown by show_prompt(); hidden by hide().
    Posts Submitted message when operator presses Enter.
    """

    class Submitted(Message):
        """Posted when the operator submits a response."""
        def __init__(self, value: str) -> None:
            super().__init__()
            self.value = value

    def compose(self) -> ComposeResult:
        yield Label("", id="prompt-label")
        yield Input(placeholder="", id="prompt-input")

    def show_prompt(self, label: str, placeholder: str = "") -> None:
        """Show the bar with the given label text and focus the input."""
        self.query_one("#prompt-label", Label).update(label)
        inp = self.query_one("#prompt-input", Input)
        inp.placeholder = placeholder
        inp.value = ""
        self.display = True
        # Use App-level call_after_refresh — the widget-level version may not
        # fire when the widget was previously hidden (display:none), because it
        # hasn't participated in a render cycle yet.
        self.app.call_after_refresh(inp.focus)

    def hide(self) -> None:
        """Hide the prompt bar."""
        self.display = False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Relay the submitted value as a PromptBar.Submitted message."""
        event.stop()
        self.post_message(self.Submitted(event.value))
