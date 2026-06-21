"""Guardrails policy / detector configuration.

Thresholds default to 80/40 but can be overridden via the BLOCK_SCORE /
TRANSFORM_SCORE environment variables (e.g. in docker-compose) to make it easy
to exercise boundary scores without code changes.
"""
import os

POLICY_VERSION: str = "1"
DETECTORS: list = ["prompt_injection", "pii", "rag_injection"]
BLOCK_SCORE: int = int(os.environ.get("BLOCK_SCORE", "80"))
TRANSFORM_SCORE: int = int(os.environ.get("TRANSFORM_SCORE", "40"))


def get_policy() -> dict:
    """Return the loaded policy/detector configuration."""
    return {
        "version": POLICY_VERSION,
        "detectors": DETECTORS,
        "thresholds": {
            "block_score": BLOCK_SCORE,
            "transform_score": TRANSFORM_SCORE,
        },
    }
