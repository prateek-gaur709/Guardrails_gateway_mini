"""Pydantic request/response models for the guardrails API."""
from typing import List, Literal

from pydantic import BaseModel, Field

# Bounds keep the request body small (DoS surface) while comfortably fitting
# real prompts and retrieved documents.
MAX_PROMPT_CHARS = 10_000
MAX_DOC_CHARS = 20_000
MAX_CONTEXT_DOCS = 3


class ContextDoc(BaseModel):
    id: str
    text: str = Field(..., max_length=MAX_DOC_CHARS)


class Metadata(BaseModel):
    app_id: str
    user_id: str
    request_id: str


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_CHARS)
    context_docs: List[ContextDoc] = Field(default_factory=list, max_length=MAX_CONTEXT_DOCS)
    metadata: Metadata


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int = Field(..., ge=0, le=100)
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Reason]
