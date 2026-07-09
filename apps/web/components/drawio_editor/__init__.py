"""Streamlit custom component that embeds the diagrams.net editor.

The component returns a dict  {action: "save"|"close", xml: str}
when the user saves or cancels, and None while the editor is idle.
"""
from __future__ import annotations

import os
from pathlib import Path

import streamlit.components.v1 as components

_FRONTEND = str(Path(__file__).parent / "frontend")
_component_func = components.declare_component("drawio_editor", path=_FRONTEND)

_DEFAULT_DRAWIO_HOST = "https://embed.diagrams.net"
# Query params the JSON embed protocol this component speaks requires.
_EMBED_PARAMS = "?embed=1&proto=json&spin=1&ui=min&dark=0&noSaveBtn=0&saveAndExit=0"


def _resolve_drawio_url() -> str:
    """Full draw.io editor URL used by the iframe.

    Defaults to the public diagrams.net embed. Set ``STRIDE_GPT_DRAWIO_URL`` to
    the scheme+host of a self-hosted draw.io (e.g.
    ``https://drawio.internal.example.com``) for air-gapped/enterprise
    deployments; the embed query params are appended automatically.
    """
    host = os.environ.get("STRIDE_GPT_DRAWIO_URL", _DEFAULT_DRAWIO_HOST).strip().rstrip("/")
    return f"{host}/{_EMBED_PARAMS}"


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
    return _component_func(
        xml=xml, drawio_url=_resolve_drawio_url(), key=key, default=None
    )
