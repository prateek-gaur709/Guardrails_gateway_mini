from app.policy import get_policy


def test_get_policy_returns_expected_keys():
    policy = get_policy()
    assert policy["version"] == "1"
    assert policy["detectors"] == ["prompt_injection", "pii", "rag_injection"]
    assert policy["thresholds"] == {"block_score": 80, "transform_score": 40}
