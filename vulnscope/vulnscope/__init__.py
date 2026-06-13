"""VulnScope — threat-model-informed vulnerability finding prioritisation.

VulnScope consumes a threat model (the system context: trust boundaries,
high-value assets, STRIDE categories, DREAD scores) alongside a batch of
vulnerability findings, and produces a prioritised, annotated report that
answers: given what we know about this system, which findings actually matter?
"""

from __future__ import annotations

__version__ = "1.0.0"
