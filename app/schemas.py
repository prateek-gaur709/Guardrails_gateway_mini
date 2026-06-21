"""Pydantic request/response models for the guardrails API."""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class ContextDoc(BaseModel):
    id: str
    text: str


class Metadata(BaseModel):
    app_id: str
    user_id: str
    request_id: str


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    context_docs: List[ContextDoc] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Reason]
