"""Pytest bootstrap — ensure the project root is importable as `vulnscope`.

Placing this at the VulnScope project root means pytest adds this directory to
``sys.path`` before collection, so ``import vulnscope`` works regardless of the
directory pytest is invoked from.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
