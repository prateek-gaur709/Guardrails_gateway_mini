from app.core.redaction import redact_pii


def test_pii_detects_email():
    _, evidence = redact_pii("contact me at john.doe@example.com please")
    assert any("email" in e for e in evidence)
    # Evidence must not leak the raw address.
    assert all("john.doe@example.com" not in e for e in evidence)


def test_pii_redacts_email_correctly():
    redacted, _ = redact_pii("contact me at john.doe@example.com please")
    assert "john.doe@example.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted


def test_pii_detects_phone():
    _, evidence = redact_pii("call me on +1 (415) 555-2671 tomorrow")
    assert evidence
    assert any("phone" in e.lower() for e in evidence)


def test_pii_no_false_positive_on_clean_text():
    redacted, evidence = redact_pii("the weather is nice today")
    assert redacted == "the weather is nice today"
    assert evidence == []


def test_pii_redacts_bare_and_formatted_phone_numbers():
    # Recall-biased: a phone-length digit run (7-15 digits) is redacted whether
    # it is bare or formatted -- the assignment's core phone requirement.
    for number in [
        "87796199908",        # bare national number
        "4155552671",         # bare 10-digit
        "+14155552671",       # E.164
        "+91 87796199908",    # with country code
        "(415) 555-2671",     # parenthesized area code
        "415-555-2671",       # dashed
        "415.555.2671",       # dotted
    ]:
        redacted, evidence = redact_pii(f"call {number} please")
        assert "[REDACTED_PHONE]" in redacted, number
        # The whole number is redacted -- no digit survives.
        assert not any(ch.isdigit() for ch in redacted), number
        assert evidence


def test_pii_redacts_ipv4_address():
    redacted, evidence = redact_pii("server at 192.168.0.1 is down")
    assert "[REDACTED_IP]" in redacted
    assert "192.168.0.1" not in redacted
    assert any("ip" in e.lower() for e in evidence)
    # Evidence is masked -- no full address leaks.
    assert all("192.168.0.1" not in e for e in evidence)


def test_pii_ignores_invalid_ipv4_octets():
    # Octet > 255 is not a valid IPv4 (and too few digits to be a phone).
    redacted, evidence = redact_pii("code 999.1.1.1 here")
    assert "[REDACTED_IP]" not in redacted
    assert evidence == []


def test_pii_redacts_valid_credit_card_luhn():
    # 4242 4242 4242 4242 is a well-known Luhn-valid test card.
    for number in ["4242 4242 4242 4242", "4242424242424242", "4111-1111-1111-1111"]:
        redacted, evidence = redact_pii(f"pay with {number} today")
        assert "[REDACTED_CC]" in redacted, number
        assert not any(ch.isdigit() for ch in redacted), number
        assert any("credit card" in e.lower() for e in evidence)


def test_pii_ignores_luhn_invalid_16_digit_number():
    # 16 digits but fails Luhn -> not a card, and >15 digits -> not a phone.
    redacted, evidence = redact_pii("ref 1234567890123456 here")
    assert "[REDACTED_CC]" not in redacted
    assert "[REDACTED_PHONE]" not in redacted
    assert evidence == []


def test_pii_redacts_ssn():
    for number in ["123-45-6789", "123 45 6789"]:
        redacted, evidence = redact_pii(f"ssn {number} on file")
        assert "[REDACTED_SSN]" in redacted, number
        assert "6789" not in redacted, number
        assert any("ssn" in e.lower() for e in evidence)


def test_pii_redacts_adjacent_numbers_separated_by_space():
    # Two numbers separated only by whitespace must both be redacted, not merged
    # into one over-long run that escapes every length check.
    redacted, evidence = redact_pii("4155552671 87796199908")
    assert redacted == "[REDACTED_PHONE] [REDACTED_PHONE]"
    assert len(evidence) == 2


def test_pii_redacts_mixed_pii_in_one_string():
    redacted, _ = redact_pii(
        "a@b.com 192.168.0.1 87796199908 4242424242424242 078-05-1120"
    )
    for token in ["[REDACTED_EMAIL]", "[REDACTED_IP]", "[REDACTED_PHONE]",
                  "[REDACTED_CC]", "[REDACTED_SSN]"]:
        assert token in redacted, token
    assert not any(ch.isdigit() for ch in redacted)


def test_pii_no_partial_redaction():
    # A recognized phone is redacted entirely, never leaving a stray digit group.
    redacted, _ = redact_pii("call 415-555-2671 now")
    assert redacted == "call [REDACTED_PHONE] now"


def test_pii_redacts_phone_at_end_of_sentence():
    # A trailing sentence period must not prevent redaction.
    for text in ["Please call 415-555-2671.", "Reach me at +14155552671."]:
        redacted, _ = redact_pii(text)
        assert "[REDACTED_PHONE]" in redacted, text


def test_pii_does_not_redact_short_numbers():
    # Runs shorter than 7 digits (years, small order IDs, codes) are not phones.
    for text in ["order 123456 shipped", "in 2024 we grew", "room 42 upstairs"]:
        redacted, evidence = redact_pii(text)
        assert "[REDACTED_PHONE]" not in redacted, text
        assert evidence == [], text
