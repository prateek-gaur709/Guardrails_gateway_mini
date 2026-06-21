"""Heuristic detectors for prompt-injection and RAG-injection.

These are deliberately simple, recall-biased keyword/regex heuristics: for a
guardrail, over-flagging a borderline phrase is safer than missing a real
injection. Patterns are pre-compiled once at import (mirroring redaction.py).
"""
import re

# Defined once so the phrase stays consistent across both detectors.
_IGNORE_PREVIOUS = r"ignore (?:all )?previous instructions"

_PROMPT_INJECTION_SOURCES = [
    _IGNORE_PREVIOUS,
    r"ignore (?:the )?above",
    r"disregard (?:all )?(?:previous|prior|the above)",
    r"reveal (?:your )?system prompt",
    r"show (?:me )?(?:your )?system prompt",
    r"act as dan",
    r"do anything now",
    r"you are no longer",
    r"bypass (?:your )?(?:rules|guidelines|restrictions)",
    r"developer mode\s*:?\s*(?:enabled|output|activated|on)\b",
]

_RAG_INJECTION_SOURCES = [
    # \b catches a "system:" role prefix anywhere on a line (mid-sentence,
    # quoted, bulleted RAG-poisoning) while excluding ordinary words like
    # "filesystem:" / "ecosystem:" (no word boundary before "system").
    r"\bsystem\s*:",
    r"override policy",
    r"ignore guidelines",
    _IGNORE_PREVIOUS,
    r"disregard (?:the )?(?:context|instructions)",
    r"assistant\s*:\s*you must",
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(src, re.IGNORECASE) for src in _PROMPT_INJECTION_SOURCES
]
RAG_INJECTION_PATTERNS = [
    re.compile(src, re.IGNORECASE) for src in _RAG_INJECTION_SOURCES
]


def _scan(text, patterns):
    evidence = []
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            evidence.append(f"matched phrase: {match.group(0).strip()}")
    return evidence


def detect_prompt_injection(text):
    """Return evidence of prompt-injection / jailbreak attempts."""
    return _scan(text, PROMPT_INJECTION_PATTERNS)


def detect_rag_injection(text):
    """Return evidence of injected instructions hidden in retrieved docs."""
    return _scan(text, RAG_INJECTION_PATTERNS)
