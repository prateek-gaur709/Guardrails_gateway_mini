"""Core guardrails engine: detectors -> tags -> score -> decision."""
from __future__ import annotations

from app.core.detectors import detect_prompt_injection, detect_rag_injection
from app.core.redaction import redact_pii
from app.policy import BLOCK_SCORE, TRANSFORM_SCORE

TAG_WEIGHTS = {
    "prompt_injection": 80,
    "rag_injection": 80,
    "pii": 40,
}


def _decision_for(score: int) -> str:
    if score >= BLOCK_SCORE:
        return "block"
    if score >= TRANSFORM_SCORE:
        return "transform"
    return "allow"


def analyze(prompt: str, context_docs: list[dict]) -> dict:
    """Analyze a prompt + retrieved context and return a policy decision.

    Pure and deterministic: no request metadata, time, randomness, or I/O
    influences the result.
    """
    tags: list[str] = []
    reasons: list[dict] = []

    # Prompt injection (on the prompt).
    for ev in detect_prompt_injection(prompt):
        if "prompt_injection" not in tags:
            tags.append("prompt_injection")
        reasons.append({"tag": "prompt_injection", "evidence": ev})

    # PII (redact prompt).
    sanitized_prompt, prompt_pii = redact_pii(prompt)
    for ev in prompt_pii:
        if "pii" not in tags:
            tags.append("pii")
        reasons.append({"tag": "pii", "evidence": ev})

    # Context docs: RAG injection + PII redaction.
    sanitized_docs: list[dict] = []
    for doc in context_docs:
        text = doc["text"]
        for ev in detect_rag_injection(text):
            if "rag_injection" not in tags:
                tags.append("rag_injection")
            reasons.append({"tag": "rag_injection", "evidence": f'[{doc["id"]}] {ev}'})
        redacted_text, doc_pii = redact_pii(text)
        for ev in doc_pii:
            if "pii" not in tags:
                tags.append("pii")
            reasons.append({"tag": "pii", "evidence": f'[{doc["id"]}] {ev}'})
        sanitized_docs.append({"id": doc["id"], "text": redacted_text})

    risk_score = min(100, sum(TAG_WEIGHTS[t] for t in tags))
    decision = _decision_for(risk_score)

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_tags": tags,
        "sanitized_prompt": sanitized_prompt,
        "sanitized_context_docs": sanitized_docs,
        "reasons": reasons,
    }
