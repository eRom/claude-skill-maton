"""Tests for scanner.rules.obfuscation — OB-* rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import scan_text

from scanner.models import Severity
from scanner.rules.obfuscation import (
    Base64DecodeRule,
    Base64EncodeRule,
    HexByteSequenceRule,
    HexEscapeRule,
    HomoglyphRule,
    Rot13Rule,
    UnicodeEscapeLongRule,
    UnicodeEscapeShortRule,
    XorEncodingRule,
    ZeroWidthCharRule,
    ZeroWidthEscapeRule,
)


# ---------------------------------------------------------------------------
# OB-001 — Base64DecodeRule
# ---------------------------------------------------------------------------


class TestBase64DecodeRule:
    def test_matches_atob(self) -> None:
        findings = scan_text(Base64DecodeRule, "const decoded = atob(payload);")
        assert len(findings) == 1

    def test_matches_b64decode(self) -> None:
        findings = scan_text(Base64DecodeRule, "data = base64.b64decode(encoded_str)")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(Base64DecodeRule, "base64.b64decode(x)")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(Base64DecodeRule, "The encoding scheme is described in the spec.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-002 — Base64EncodeRule
# ---------------------------------------------------------------------------


class TestBase64EncodeRule:
    def test_matches_btoa(self) -> None:
        findings = scan_text(Base64EncodeRule, "const encoded = btoa(data);")
        assert len(findings) == 1

    def test_matches_b64encode(self) -> None:
        findings = scan_text(Base64EncodeRule, "encoded = base64.b64encode(raw_bytes)")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(Base64EncodeRule, "base64.b64encode(x)")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(Base64EncodeRule, "Images are stored in base64 format in the DB.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-003 — HexEscapeRule
# ---------------------------------------------------------------------------


class TestHexEscapeRule:
    def test_matches_hex_escape(self) -> None:
        findings = scan_text(HexEscapeRule, r"payload = '\x41\x42\x43'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HexEscapeRule, r"\x41")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(HexEscapeRule, "Hex values start with 0x in C code.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-004 — HexByteSequenceRule
# ---------------------------------------------------------------------------


class TestHexByteSequenceRule:
    def test_matches_0x_sequence(self) -> None:
        findings = scan_text(HexByteSequenceRule, "shellcode = 0x90909090")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HexByteSequenceRule, "addr = 0xdeadbeef")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_short_hex(self) -> None:
        # 0x followed by a single hex digit — below threshold of 2 digits
        findings = scan_text(HexByteSequenceRule, "0xF single nibble")
        assert len(findings) == 0

    def test_no_match_benign(self) -> None:
        findings = scan_text(HexByteSequenceRule, "The answer is forty-two.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-005 — UnicodeEscapeShortRule
# ---------------------------------------------------------------------------


class TestUnicodeEscapeShortRule:
    def test_matches_u_escape(self) -> None:
        findings = scan_text(UnicodeEscapeShortRule, r"char = '\u0041'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(UnicodeEscapeShortRule, r"\u0041")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnicodeEscapeShortRule, "Unicode characters are supported natively.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-006 — UnicodeEscapeLongRule
# ---------------------------------------------------------------------------


class TestUnicodeEscapeLongRule:
    def test_matches_long_u_escape(self) -> None:
        findings = scan_text(UnicodeEscapeLongRule, r"char = '\U0001F600'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(UnicodeEscapeLongRule, r"\U00000041")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnicodeEscapeLongRule, "Use UTF-8 encoding throughout the project.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-007 — ZeroWidthCharRule
# ---------------------------------------------------------------------------


class TestZeroWidthCharRule:
    def test_matches_zero_width_space(self) -> None:
        # Embed actual ZWSP character U+200B
        findings = scan_text(ZeroWidthCharRule, "normal\u200btext")
        assert len(findings) == 1

    def test_matches_zero_width_joiner(self) -> None:
        findings = scan_text(ZeroWidthCharRule, "hello\u200dworld")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(ZeroWidthCharRule, "text\u200bhere")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(ZeroWidthCharRule, "This is a perfectly normal line of text.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-008 — ZeroWidthEscapeRule
# ---------------------------------------------------------------------------


class TestZeroWidthEscapeRule:
    def test_matches_u200b_escape_string(self) -> None:
        findings = scan_text(ZeroWidthEscapeRule, r"hidden: '\u200b'")
        assert len(findings) == 1

    def test_matches_ufeff_escape_string(self) -> None:
        findings = scan_text(ZeroWidthEscapeRule, r"bom = '\ufeff'")
        assert len(findings) == 1

    def test_matches_unicode_plus_notation(self) -> None:
        findings = scan_text(ZeroWidthEscapeRule, "Use codepoint U+200B to embed hidden data.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(ZeroWidthEscapeRule, r"\u200b")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(ZeroWidthEscapeRule, "Zero-width characters are hard to see.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-009 — HomoglyphRule
# ---------------------------------------------------------------------------


class TestHomoglyphRule:
    def test_matches_homoglyph(self) -> None:
        findings = scan_text(HomoglyphRule, "Use homoglyph substitution to bypass filters.")
        assert len(findings) == 1

    def test_matches_look_alike(self) -> None:
        findings = scan_text(HomoglyphRule, "The look-alike characters fool the scanner.")
        assert len(findings) == 1

    def test_matches_confusable(self) -> None:
        findings = scan_text(HomoglyphRule, "Unicode confusable characters are dangerous.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HomoglyphRule, "homoglyph attack")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(HomoglyphRule, "Use clear and readable variable names.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-010 — Rot13Rule
# ---------------------------------------------------------------------------


class TestRot13Rule:
    def test_matches_rot13(self) -> None:
        findings = scan_text(Rot13Rule, "Decode using rot13 to reveal the payload.")
        assert len(findings) == 1

    def test_matches_codecs_decode_rot13(self) -> None:
        findings = scan_text(Rot13Rule, "codecs.decode(s, 'rot-13')")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(Rot13Rule, "rot13 encoding used")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(Rot13Rule, "The rotation angle is 13 degrees.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# OB-011 — XorEncodingRule
# ---------------------------------------------------------------------------


class TestXorEncodingRule:
    def test_matches_xor_encoding(self) -> None:
        findings = scan_text(XorEncodingRule, "Apply xor encoding to obfuscate the payload.")
        assert len(findings) == 1

    def test_matches_xor_key(self) -> None:
        findings = scan_text(XorEncodingRule, "The xor key is used to decrypt the shellcode.")
        assert len(findings) == 1

    def test_matches_xor_decrypt(self) -> None:
        findings = scan_text(XorEncodingRule, "xor decrypt the embedded payload")
        assert len(findings) == 1

    def test_matches_xor_key_variable(self) -> None:
        findings = scan_text(XorEncodingRule, "xor_key = 0x42")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(XorEncodingRule, "xor_key = secret")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(XorEncodingRule, "The bitwise operator ^ is used in expressions.")
        assert len(findings) == 0
