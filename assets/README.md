# Brand assets

Drop a logo here and the web UI picks it up automatically on the next page
load. No code change needed.

## Slots

| File | Used when | Status |
|------|-----------|--------|
| `xplor-logo.*` | Light theme | ✅ present (`xplor-logo.webp`) |
| `xplor-logo-dark.*` | Dark theme | ⬜ not supplied yet |

Each slot accepts `.svg`, `.png`, `.webp`, `.jpg` or `.jpeg`, checked in that
order. `logo.*` and `logo-dark.*` work as alternative names.

## Why there are two

The standard Xplor logo is dark ink (`#272F35`). Against the dark theme's
sidebar (`#222930`) that measures roughly **1.1:1** — effectively invisible.
Put the reversed (white) version at `assets/xplor-logo-dark.png` and dark mode
will use it.

Until that file exists, dark mode falls back to a typographic wordmark rather
than showing an unreadable logo. Nothing recolours the brand mark
automatically — that's a brand decision, not one for the code to make.

Variants are switched with a CSS `prefers-color-scheme` query, which resolves
before the page paints. A user who overrides the theme in **Settings →
Appearance** against their OS preference will see the variant matching their
OS. The app follows the OS preference by default, so this lines up in the
normal case.

The lookup lives in [`apps/web/branding.py`](../apps/web/branding.py)
(`find_logo` / `find_dark_logo`).

A note on SVG: the app renders it as a base64 `data:` URI inside an `<img>`
rather than inlining it into the page. That keeps any script or external
reference inside the file inert. Use a plain vector export — no embedded
scripts, no remote `<image href>` links.
