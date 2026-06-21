"""PII detection and redaction.

Per the assignment the minimum is email + phone; we also redact IPv4 addresses,
credit-card numbers (Luhn-validated), and US SSNs, since each has a distinct,
validatable shape that doesn't collide with ordinary numbers. For a PII guardrail
the safe bias is recall: catching real PII matters more than avoiding the
redaction of an occasional long numeric string.

Order matters: email -> credit card -> SSN -> IPv4 -> phone. Earlier passes
replace their matches with non-numeric tokens, so a later (more permissive) pass
can't re-match the digits inside them. In particular the phone pass runs last,
after the precise formats (card/SSN/IP) have already been claimed and labelled.
"""
import re

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Credit card: 13-19 contiguous digits, or the standard 4x4 grouping with single
# space/dash separators. Keeping the grouping tight (rather than "digits with
# optional separators") avoids merging two space-separated numbers into one
# over-long run. Validated with the Luhn checksum in _luhn_ok.
CREDIT_CARD_RE = re.compile(r"(?<!\w)(?:\d{13,19}|\d{4}(?:[ -]\d{4}){3})(?!\w)")

# US SSN: AAA-GG-SSSS with dash or space separators (the distinctive 3-2-4
# grouping; dates are 4-2-2 and phones are 3-3-4, so no collision).
SSN_RE = re.compile(r"(?<!\w)\d{3}[- ]\d{2}[- ]\d{4}(?!\w)")

# Dotted-quad IPv4; octet range (0-255) is validated in _is_ipv4.
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# A phone candidate: optional leading "+", then a run of digits that may use the
# common separators (space, dash, dot, parentheses). The digit count is checked
# in _phone_sub so short numbers (years, small IDs) are left alone.
PHONE_CANDIDATE_RE = re.compile(r"(?<!\w)\+?\(?\d[\d\s().-]{5,}\d(?!\w)")

# Phone numbers run from ~7 digits (local) to 15 digits (E.164 max, incl. country
# code). Runs outside this range are not treated as phone numbers.
MIN_PHONE_DIGITS = 7
MAX_PHONE_DIGITS = 15

EMAIL_TOKEN = "[REDACTED_EMAIL]"
CC_TOKEN = "[REDACTED_CC]"
SSN_TOKEN = "[REDACTED_SSN]"
IP_TOKEN = "[REDACTED_IP]"
PHONE_TOKEN = "[REDACTED_PHONE]"


def _mask_email(addr: str) -> str:
    """Mask the local part so evidence never carries the raw address."""
    local, _, domain = addr.partition("@")
    masked_local = (local[0] + "***") if local else "***"
    return f"{masked_local}@{domain}"


def _luhn_ok(digits: str) -> bool:
    """Validate a digit string with the Luhn (mod-10) checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_ipv4(token: str) -> bool:
    """True if token is a dotted-quad with every octet in 0-255."""
    parts = token.split(".")
    return len(parts) == 4 and all(
        p.isdigit() and 0 <= int(p) <= 255 for p in parts
    )


def redact_pii(text: str):
    """Redact emails, credit cards, SSNs, IPv4 addresses, and phone numbers.

    Returns (redacted_text, evidence). Evidence strings are masked so the raw
    PII never leaks back through the API response, CLI output, or UI.
    """
    evidence = []

    def _email_sub(match):
        evidence.append(f"matched email: {_mask_email(match.group(0))}")
        return EMAIL_TOKEN

    redacted = EMAIL_RE.sub(_email_sub, text)

    def _cc_sub(match):
        token = match.group(0)
        digits = "".join(c for c in token if c.isdigit())
        if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
            return token  # not a valid card number
        evidence.append(f"matched credit card ending in {digits[-4:]}")
        return CC_TOKEN

    redacted = CREDIT_CARD_RE.sub(_cc_sub, redacted)

    def _ssn_sub(match):
        digits = "".join(c for c in match.group(0) if c.isdigit())
        evidence.append(f"matched ssn ending in {digits[-4:]}")
        return SSN_TOKEN

    redacted = SSN_RE.sub(_ssn_sub, redacted)

    def _ip_sub(match):
        token = match.group(0)
        if not _is_ipv4(token):
            return token  # not a valid IPv4 (e.g. octet > 255)
        evidence.append(f"matched ip address: {token.split('.')[0]}.x.x.x")
        return IP_TOKEN

    redacted = IPV4_RE.sub(_ip_sub, redacted)

    def _redact_phone_group(group):
        digits = [c for c in group if c.isdigit()]
        if MIN_PHONE_DIGITS <= len(digits) <= MAX_PHONE_DIGITS:
            evidence.append(f"matched phone ending in {''.join(digits[-2:])}")
            return PHONE_TOKEN
        return group

    def _phone_sub(match):
        token = match.group(0)
        if sum(c.isdigit() for c in token) <= MAX_PHONE_DIGITS:
            return _redact_phone_group(token)
        # Too many digits for one number: the candidate merged several numbers
        # across whitespace -- evaluate each whitespace-separated group on its own.
        return "".join(
            part if part.isspace() else _redact_phone_group(part)
            for part in re.split(r"(\s+)", token)
        )

    redacted = PHONE_CANDIDATE_RE.sub(_phone_sub, redacted)

    return redacted, evidence
