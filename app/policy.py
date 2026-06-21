"""Static guardrails policy / detector configuration."""

POLICY_VERSION: str = "1"
DETECTORS: list = ["prompt_injection", "pii", "rag_injection"]
BLOCK_SCORE: int = 80
TRANSFORM_SCORE: int = 40


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
