"""Configuration — scoring weights, model selection, environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

# Default model. Consistent with STRIDE-GPT / AttackGen — best reasoning-per-cost.
DEFAULT_MODEL = "claude-sonnet-4-6"

# Default composite-score weights (must sum to 1.0). Configurable via CLI flags
# or the VULNSCOPE_*_WEIGHT environment variables.
DEFAULT_ASSET_WEIGHT = 0.35
DEFAULT_ALIGN_WEIGHT = 0.30
DEFAULT_BOUNDARY_WEIGHT = 0.25
DEFAULT_STRIDE_WEIGHT = 0.10


@dataclass(frozen=True)
class Weights:
    """Composite-score dimension weights."""

    asset_criticality: float = DEFAULT_ASSET_WEIGHT
    threat_alignment: float = DEFAULT_ALIGN_WEIGHT
    trust_boundary_exposure: float = DEFAULT_BOUNDARY_WEIGHT
    stride_category_weight: float = DEFAULT_STRIDE_WEIGHT

    def normalised(self) -> Weights:
        """Return weights scaled to sum to 1.0.

        Users overriding a subset of weights rarely make them sum to exactly
        one; normalising keeps the composite on a clean 0-10 scale regardless.
        """
        total = (
            self.asset_criticality
            + self.threat_alignment
            + self.trust_boundary_exposure
            + self.stride_category_weight
        )
        if total <= 0:
            # Degenerate input — fall back to the documented defaults rather
            # than dividing by zero or producing all-zero weights.
            return Weights()
        return Weights(
            asset_criticality=self.asset_criticality / total,
            threat_alignment=self.threat_alignment / total,
            trust_boundary_exposure=self.trust_boundary_exposure / total,
            stride_category_weight=self.stride_category_weight / total,
        )

    def as_dict(self) -> dict[str, float]:
        return {
            "asset_criticality": self.asset_criticality,
            "threat_alignment": self.threat_alignment,
            "trust_boundary_exposure": self.trust_boundary_exposure,
            "stride_category_weight": self.stride_category_weight,
        }


@dataclass(frozen=True)
class Config:
    """Top-level run configuration."""

    model: str = DEFAULT_MODEL
    api_key: str | None = None
    weights: Weights = Weights()
    # Per-call output token cap for the scoring/synthesis prompts. Scoring
    # responses are small JSON blocks; the synthesis is <=250 words.
    max_tokens: int = 1500
    # When True, score with the deterministic heuristic instead of the LLM.
    # Set automatically when no API key is available so the tool stays usable
    # (and demonstrable) without credentials.
    offline: bool = False

    @classmethod
    def from_env(cls, **overrides: object) -> Config:
        """Build a Config from environment variables, applying explicit overrides.

        Recognised variables:
          ANTHROPIC_API_KEY, VULNSCOPE_MODEL, VULNSCOPE_ASSET_WEIGHT,
          VULNSCOPE_ALIGN_WEIGHT, VULNSCOPE_BOUNDARY_WEIGHT,
          VULNSCOPE_STRIDE_WEIGHT.

        Any keyword in ``overrides`` (e.g. from CLI flags) takes precedence
        over the environment. ``None`` overrides are ignored so callers can
        pass through unset flags unconditionally.
        """
        weights = Weights(
            asset_criticality=_env_float("VULNSCOPE_ASSET_WEIGHT", DEFAULT_ASSET_WEIGHT),
            threat_alignment=_env_float("VULNSCOPE_ALIGN_WEIGHT", DEFAULT_ALIGN_WEIGHT),
            trust_boundary_exposure=_env_float(
                "VULNSCOPE_BOUNDARY_WEIGHT", DEFAULT_BOUNDARY_WEIGHT
            ),
            stride_category_weight=_env_float("VULNSCOPE_STRIDE_WEIGHT", DEFAULT_STRIDE_WEIGHT),
        )
        config = cls(
            model=os.environ.get("VULNSCOPE_MODEL", DEFAULT_MODEL),
            api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            weights=weights,
        )

        clean = {k: v for k, v in overrides.items() if v is not None}
        if clean:
            config = replace(config, **clean)  # type: ignore[arg-type]
        return config


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default
