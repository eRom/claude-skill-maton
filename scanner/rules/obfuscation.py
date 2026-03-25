"""Obfuscation detection rules.

Category 13 — Obfuscation (OB-): base64 encode/decode, hex encoding,
unicode escapes, zero-width characters (steganography), homoglyph
substitution, ROT13, and XOR encoding references.
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 13 — Obfuscation
# ---------------------------------------------------------------------------


class Base64DecodeRule(Rule):
    """Detects base64 decode function calls that may hide payload content."""

    rule_id = "OB-001"
    category = "obfuscation"
    severity = Severity.WARNING
    description = "base64 decode function detected — may conceal hidden payloads"
    patterns = [
        re.compile(r"\batob\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.b64decode\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.decodebytes\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.decodestring\s*\(", re.IGNORECASE),
    ]


class Base64EncodeRule(Rule):
    """Detects base64 encode function calls that may encode instructions or data."""

    rule_id = "OB-002"
    category = "obfuscation"
    severity = Severity.WARNING
    description = "base64 encode function detected — may encode instructions or sensitive data"
    patterns = [
        re.compile(r"\bbtoa\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.b64encode\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.encodebytes\s*\(", re.IGNORECASE),
        re.compile(r"\bbase64\.encodestring\s*\(", re.IGNORECASE),
    ]


class HexEscapeRule(Rule):
    """Detects hex escape sequences (\\x) used to obfuscate strings."""

    rule_id = "OB-003"
    category = "obfuscation"
    severity = Severity.WARNING
    description = r"Hex escape sequence (\x) detected — may obfuscate string content"
    patterns = [
        re.compile(r"\\x[0-9a-fA-F]{2}"),
    ]


class HexByteSequenceRule(Rule):
    """Detects 0x-prefixed byte sequences potentially used for obfuscation."""

    rule_id = "OB-004"
    category = "obfuscation"
    severity = Severity.WARNING
    description = "0x hex byte sequence detected — may obfuscate binary data or shellcode"
    patterns = [
        re.compile(r"0x[0-9a-fA-F]{2,}"),
    ]


class UnicodeEscapeShortRule(Rule):
    r"""Detects \u unicode escape sequences used to obfuscate characters."""

    rule_id = "OB-005"
    category = "obfuscation"
    severity = Severity.WARNING
    description = r"Unicode escape sequence (\u) detected — may obfuscate characters or bypass filters"
    patterns = [
        re.compile(r"\\u[0-9a-fA-F]{4}"),
    ]


class UnicodeEscapeLongRule(Rule):
    r"""Detects \U long unicode escape sequences."""

    rule_id = "OB-006"
    category = "obfuscation"
    severity = Severity.WARNING
    description = r"Long unicode escape sequence (\U) detected — may obfuscate characters"
    patterns = [
        re.compile(r"\\U[0-9a-fA-F]{8}"),
    ]


class ZeroWidthCharRule(Rule):
    """Detects zero-width characters used for steganographic data embedding."""

    rule_id = "OB-007"
    category = "obfuscation"
    severity = Severity.CRITICAL
    description = (
        "Zero-width character detected — steganographic technique used to embed "
        "hidden instructions invisible to human reviewers"
    )
    patterns = [
        # Zero Width Space (ZWSP)
        re.compile(r"\u200b"),
        # Zero Width Non-Joiner (ZWNJ)
        re.compile(r"\u200c"),
        # Zero Width Joiner (ZWJ)
        re.compile(r"\u200d"),
        # Zero Width No-Break Space / BOM (ZWNBSP)
        re.compile(r"\ufeff"),
    ]


class ZeroWidthEscapeRule(Rule):
    r"""Detects literal escape references to zero-width Unicode codepoints."""

    rule_id = "OB-008"
    category = "obfuscation"
    severity = Severity.CRITICAL
    description = (
        r"Reference to zero-width Unicode codepoint (\u200b/\u200c/\u200d/\ufeff) "
        "detected — steganographic embedding technique"
    )
    patterns = [
        re.compile(r"\\u200[bcdBCD]", re.IGNORECASE),
        re.compile(r"\\ufeff", re.IGNORECASE),
        re.compile(r"U\+200[bcdBCD]", re.IGNORECASE),
        re.compile(r"U\+FEFF", re.IGNORECASE),
    ]


class HomoglyphRule(Rule):
    """Detects references to homoglyph substitution techniques."""

    rule_id = "OB-009"
    category = "obfuscation"
    severity = Severity.WARNING
    description = (
        "Homoglyph substitution technique referenced — visually identical characters "
        "used to bypass keyword filters or deceive reviewers"
    )
    patterns = [
        re.compile(r"\bhomoglyph\b", re.IGNORECASE),
        re.compile(r"\blook[-_]?alike\b", re.IGNORECASE),
        re.compile(r"\bconfusable\b", re.IGNORECASE),
        re.compile(r"\bunicode\s+spoof", re.IGNORECASE),
        re.compile(r"\bIDN\s+homograph\b", re.IGNORECASE),
    ]


class Rot13Rule(Rule):
    """Detects ROT13 encoding references used to obfuscate text."""

    rule_id = "OB-010"
    category = "obfuscation"
    severity = Severity.WARNING
    description = "ROT13 encoding detected — simple obfuscation technique to disguise text content"
    patterns = [
        re.compile(r"\brot13\b", re.IGNORECASE),
        re.compile(r"\brot_13\b", re.IGNORECASE),
        re.compile(r"\bcodecs\.decode\s*\([^,]+,\s*['\"]rot.?13['\"]", re.IGNORECASE),
        re.compile(r"\bstr\.maketrans\b.*[A-Za-z]{13}.*[A-Za-z]{13}", re.IGNORECASE),
    ]


class XorEncodingRule(Rule):
    """Detects XOR encoding patterns commonly used to obfuscate shellcode or payloads."""

    rule_id = "OB-011"
    category = "obfuscation"
    severity = Severity.WARNING
    description = "XOR encoding pattern detected — frequently used to obfuscate shellcode or bypass detection"
    patterns = [
        re.compile(r"\bxor\s+encoding\b", re.IGNORECASE),
        re.compile(r"\bxor\s+key\b", re.IGNORECASE),
        re.compile(r"\bxor\s+cipher\b", re.IGNORECASE),
        re.compile(r"\bxor\s+decrypt\b", re.IGNORECASE),
        re.compile(r"\bxor\s+encrypt\b", re.IGNORECASE),
        re.compile(r"\bxor_key\b", re.IGNORECASE),
        re.compile(r"\bxor_bytes\b", re.IGNORECASE),
        re.compile(r"\[\s*b\s*\^\s*k\s*for\s+b\s*,\s*k\s+in\b", re.IGNORECASE),
    ]
