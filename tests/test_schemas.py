import pytest
from pydantic import ValidationError

from app.schemas import AnalyzeRequest, AnalyzeResponse


META = {"app_id": "a", "user_id": "u", "request_id": "r"}


def test_analyze_request_accepts_minimal_payload():
    req = AnalyzeRequest(prompt="hello", metadata=META)
    assert req.prompt == "hello"
    assert req.context_docs == []


def test_analyze_request_rejects_missing_prompt():
    with pytest.raises(ValidationError):
        AnalyzeRequest(context_docs=[], metadata=META)


def test_analyze_request_rejects_missing_metadata():
    with pytest.raises(ValidationError):
        AnalyzeRequest(prompt="hello")


def test_analyze_request_rejects_too_many_context_docs():
    docs = [{"id": f"doc-{i}", "text": "x"} for i in range(4)]
    with pytest.raises(ValidationError):
        AnalyzeRequest(prompt="hi", context_docs=docs, metadata=META)


def test_analyze_response_rejects_out_of_range_score():
    with pytest.raises(ValidationError):
        AnalyzeResponse(
            decision="block", risk_score=150, risk_tags=[],
            sanitized_prompt="[BLOCKED]", sanitized_context_docs=[], reasons=[],
        )


def test_analyze_response_roundtrip():
    resp = AnalyzeResponse(
        decision="allow",
        risk_score=0,
        risk_tags=[],
        sanitized_prompt="hi",
        sanitized_context_docs=[],
        reasons=[],
    )
    assert resp.decision == "allow"
