import pytest
from pydantic import ValidationError

from app.schemas import AnalyzeRequest, AnalyzeResponse


def test_analyze_request_accepts_minimal_payload():
    req = AnalyzeRequest(prompt="hello")
    assert req.prompt == "hello"
    assert req.context_docs == []


def test_analyze_request_rejects_missing_prompt():
    with pytest.raises(ValidationError):
        AnalyzeRequest(context_docs=[])


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
