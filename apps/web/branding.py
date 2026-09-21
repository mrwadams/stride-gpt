"""Xplor branding for the Streamlit web UI.

Single source of truth for the app's name, brand styling, logo slot and the
upstream attribution. Keeping it here means the rest of ``main.py`` stays
about threat modelling, and a brand refresh touches one file.

Colours and fonts follow the Xplor visual identity; the palette itself lives
in ``.streamlit/config.toml`` because Streamlit reads the theme at startup.
"""

from __future__ import annotations

import base64
from pathlib import Path

import streamlit as st

_REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Names -------------------------------------------------------------- #

APP_NAME = "Xplor PSE Threat Modeling"
APP_SHORT_NAME = "Xplor PSE"

# --- Upstream attribution ----------------------------------------------- #
#
# This app is a fork of STRIDE GPT. The MIT licence requires the copyright
# notice to travel with the code (see LICENSE); this line is the visible
# credit that goes with it.

UPSTREAM_NAME = "STRIDE GPT"
UPSTREAM_AUTHOR = "Matt Adams"
UPSTREAM_REPO_URL = "https://github.com/mrwadams/stride-gpt"
UPSTREAM_AUTHOR_URL = "https://www.linkedin.com/in/matthewrwadams/"

# --- Logo slot ----------------------------------------------------------- #
#
# Drop the official Xplor logo at assets/xplor-logo.(svg|png|webp|jpg) and it
# is picked up automatically. The standard logo is dark ink (#272F35), which
# is unreadable on the dark theme's sidebar, so a reversed/white version can
# be supplied alongside it at assets/xplor-logo-dark.* and is used whenever
# the dark theme is active. Both slots are optional: with no assets at all
# the app falls back to a typographic wordmark, so nothing here can break
# the page.

_LOGO_DIR = _REPO_ROOT / "assets"
_LIGHT_STEMS = ("xplor-logo", "logo")
_DARK_STEMS = ("xplor-logo-dark", "logo-dark")
_SUFFIXES = (".svg", ".png", ".webp", ".jpg", ".jpeg")

_MEDIA_TYPES = {
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


def _find_asset(stems: tuple[str, ...]) -> Path | None:
    """Return the first matching asset in assets/, or None."""
    for stem in stems:
        for suffix in _SUFFIXES:
            candidate = _LOGO_DIR / f"{stem}{suffix}"
            if candidate.is_file():
                return candidate
    return None


def find_logo() -> Path | None:
    """Return the standard (light-background) logo asset, or None."""
    return _find_asset(_LIGHT_STEMS)


def find_dark_logo() -> Path | None:
    """Return the reversed (dark-background) logo asset, or None."""
    return _find_asset(_DARK_STEMS)


def _data_uri(path: Path) -> str:
    """Encode an image file as a base64 ``data:`` URI.

    Every format goes through an ``<img>`` tag, including SVG. An ``<img>``
    never executes script or resolves external references inside the SVG, so
    a malformed or hostile file dropped into assets/ cannot turn into script
    execution in the app's origin.
    """
    media_type = _MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


def render_sidebar_logo(width: int = 200) -> None:
    """Render the brand logo at the top of the sidebar, per theme.

    Light and dark variants are both emitted and switched with a CSS
    ``prefers-color-scheme`` query rather than by detecting the theme in
    Python. Streamlit's own ``st.context.theme.type`` is documented as
    unreliable on first load and immediately after a theme change, which
    would show the wrong logo for a frame; CSS resolves before paint.

    The trade-off: a user who overrides the theme in Settings -> Appearance
    against their OS preference gets the variant matching the OS, not the
    override. The app follows the OS preference by default, so this matches
    the theme in the normal case.
    """
    light_logo = find_logo()

    if light_logo is None:
        _render_wordmark()
        return

    dark_logo = find_dark_logo()
    img_style = f"width:{width}px;max-width:100%;height:auto;"

    if dark_logo is not None:
        dark_markup = (
            f'<img class="xplor-logo-dark" src="{_data_uri(dark_logo)}" '
            f'alt="{APP_NAME}" style="{img_style}">'
        )
    else:
        # No reversed asset supplied. The dark-ink logo measures about 1.1:1
        # against the dark sidebar, so fall back to legible type rather than
        # recolouring the brand mark ourselves.
        dark_markup = (
            '<div class="xplor-logo-dark">'
            '<div style="font-weight:700;font-size:1.5rem;line-height:1.2;'
            'color:#8C85FF;">Xplor</div>'  # Purple - Tint 1, the dark-theme primary
            '<div style="font-weight:600;font-size:0.9rem;line-height:1.2;'
            'opacity:0.85;">PSE Threat Modeling</div>'
            "</div>"
        )

    st.sidebar.html(
        f"""
        <style>
          .xplor-logo-wrap {{
            margin: 0.25rem 0 1rem;
            font-family: 'Poppins', 'Aptos', 'Segoe UI', system-ui, sans-serif;
          }}
          .xplor-logo-dark {{ display: none; }}
          @media (prefers-color-scheme: dark) {{
            .xplor-logo-light {{ display: none; }}
            .xplor-logo-dark {{ display: block; }}
          }}
        </style>
        <div class="xplor-logo-wrap">
          <img class="xplor-logo-light" src="{_data_uri(light_logo)}"
               alt="{APP_NAME}" style="{img_style}">
          {dark_markup}
        </div>
        """
    )


def _render_wordmark() -> None:
    """Typographic header used when no logo asset is supplied at all.

    The colour comes from Streamlit's ``:primary[]`` directive rather than a
    hard-coded hex, so it follows theme.primaryColor per theme: Purple on
    light, Purple - Tint 1 on dark. Plain Purple on the dark sidebar measures
    about 2.2:1 against the background, below the 3:1 WCAG AA needs for large
    text, so the two themes genuinely need different values here.
    """
    st.sidebar.markdown("## :primary[Xplor]")
    st.sidebar.caption("PSE Threat Modeling")


# --- Styling -------------------------------------------------------------- #


def inject_brand_styles() -> None:
    """Load the brand typefaces and apply the few things the theme can't.

    Poppins and Roboto come from Google Fonts. If that request is blocked —
    offline, air-gapped, or egress-filtered — the font stacks in
    .streamlit/config.toml fall back to Aptos and then the platform sans, so
    the app still renders correctly. Nothing here is required for function.
    """
    st.html(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@600;700&family=Roboto:wght@400;500;700&display=swap');

          /* Headlines are sentence case in the brand guidelines; Streamlit
             leaves casing alone, so this only tightens the brand's 120%
             leading and removes the default letter-spacing drift. */
          h1, h2, h3, h4, h5, h6 { line-height: 1.2; letter-spacing: -0.01em; }

          /* Purple -> Teal is a primary brand gradient. Used once, on the
             sidebar edge, as the single piece of brand texture. */
          section[data-testid="stSidebar"] {
            border-right: 3px solid transparent;
            border-image: linear-gradient(180deg, #6923F4 0%, #3ACBCA 100%) 1;
          }
        </style>
        """
    )


def render_upstream_credit() -> None:
    """Credit the upstream project and its author."""
    st.sidebar.markdown(
        f"Built on [{UPSTREAM_NAME}]({UPSTREAM_REPO_URL}) by "
        f"[{UPSTREAM_AUTHOR}]({UPSTREAM_AUTHOR_URL}), used under the MIT licence. "
        f"Adapted and maintained by Xplor."
    )
