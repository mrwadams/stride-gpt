"""Streamlit custom component that embeds the diagrams.net editor.

The component returns a dict  {action: "save"|"close", xml: str}
when the user saves or cancels, and None while the editor is idle.
"""
from __future__ import annotations
import os
import streamlit.components.v1 as components

_FRONTEND = os.path.join(os.path.dirname(__file__), "frontend")
_component_func = components.declare_component("drawio_editor", path=_FRONTEND)


def drawio_editor_component(xml: str = "", key: str | None = None) -> dict | None:
    """Render the embedded draw.io editor.

    Args:
        xml:  Optional draw.io XML to pre-load. Pass "" for a blank canvas.
        key:  Streamlit widget key for state isolation.

    Returns:
        None while the editor is open and the user hasn't acted.
        {"action": "save", "xml": "<mxGraphModel...>"}  on save.
        {"action": "close", "xml": "<last known xml>"}  on cancel.
    """
    return _component_func(xml=xml, key=key, default=None)
