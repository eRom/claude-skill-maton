"""Injection detection rules.

Category 1 — Prompt Injection (PI-*): CRITICAL severity
Category 14 — Social Engineering (SE-*): WARNING severity
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 1 — Prompt Injection (CRITICAL)
# ---------------------------------------------------------------------------


class IgnorePreviousInstructions(Rule):
    rule_id = "PI-001"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: attempt to nullify previous instructions"
    patterns = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    ]


class NewInstructions(Rule):
    rule_id = "PI-002"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: injecting new instructions to override context"
    patterns = [
        re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
        re.compile(r"new\s+instructions?\s+are\b", re.IGNORECASE),
        re.compile(r"from\s+now\s+on[,\s]+your\s+(new\s+)?instructions?", re.IGNORECASE),
    ]


class ForgetEverything(Rule):
    rule_id = "PI-003"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: instruction to forget prior context"
    patterns = [
        re.compile(r"forget\s+everything\b", re.IGNORECASE),
        re.compile(r"forget\s+all\s+(previous\s+)?(instructions?|context|rules?)\b", re.IGNORECASE),
        re.compile(r"clear\s+your\s+(memory|context|instructions?)\b", re.IGNORECASE),
    ]


class YouAreNow(Rule):
    rule_id = "PI-004"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: persona hijacking via 'you are now'"
    patterns = [
        re.compile(r"you\s+are\s+now\s+(?!able|going|allowed)\w", re.IGNORECASE),
        re.compile(r"from\s+this\s+(point|moment|now)\s+(on[,\s]+)?you\s+are\b", re.IGNORECASE),
    ]


class Override(Rule):
    rule_id = "PI-005"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: attempt to override system constraints"
    patterns = [
        re.compile(r"override\s+(\w+\s+){0,2}(instructions?|rules?|constraints?|settings?|guidelines?|policies?)\b", re.IGNORECASE),
        re.compile(r"override\s+(\w+\s+){0,2}(system|safety|content)\s+(prompt|filter|policy|guidelines?)\b", re.IGNORECASE),
    ]


class Jailbreak(Rule):
    rule_id = "PI-006"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: explicit jailbreak attempt"
    patterns = [
        re.compile(r"\bjailbreak\b", re.IGNORECASE),
        re.compile(r"jail\s*break\s+(mode|this|the\s+AI|the\s+model)\b", re.IGNORECASE),
    ]


class DoNotFollow(Rule):
    rule_id = "PI-007"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: explicit instruction to ignore safety guidelines"
    patterns = [
        re.compile(r"do\s+not\s+follow\s+(your\s+)?(instructions?|rules?|guidelines?|policies?)\b", re.IGNORECASE),
        re.compile(r"don'?t\s+follow\s+(your\s+)?(instructions?|rules?|guidelines?|policies?)\b", re.IGNORECASE),
        re.compile(r"ignore\s+(all\s+)?(your\s+)?(rules?|guidelines?|policies?|restrictions?|safety)\b", re.IGNORECASE),
    ]


class ActAs(Rule):
    rule_id = "PI-008"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: persona injection via 'act as'"
    patterns = [
        re.compile(r"\bact\s+as\s+(if\s+you\s+(are|were)\b|an?\s+\w)", re.IGNORECASE),
        re.compile(r"\bbehave\s+as\s+(if\s+you\s+(are|were)\b|an?\s+\w)", re.IGNORECASE),
    ]


class PretendYouAre(Rule):
    rule_id = "PI-009"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: persona injection via 'pretend you are'"
    patterns = [
        re.compile(r"pretend\s+(that\s+)?you\s+(are|were)\b", re.IGNORECASE),
        re.compile(r"roleplay\s+as\s+(an?\s+)?(AI|assistant|bot|system)\b", re.IGNORECASE),
        re.compile(r"simulate\s+(being\s+)?(an?\s+)?(AI|assistant|system)\s+(with(out)?|that\s+(has|ignores?))\b", re.IGNORECASE),
    ]


class SystemPromptExfiltration(Rule):
    rule_id = "PI-010"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: attempt to reveal or manipulate the system prompt"
    patterns = [
        re.compile(r"(reveal|show|print|output|display|repeat|ignore)\s+(your\s+)?system\s+prompt\b", re.IGNORECASE),
        re.compile(r"what\s+(is|are)\s+(your\s+)?system\s+prompt\b", re.IGNORECASE),
        re.compile(r"system\s+prompt\s*:\s*", re.IGNORECASE),
    ]


class BypassSafety(Rule):
    rule_id = "PI-011"
    category = "prompt_injection"
    severity = Severity.CRITICAL
    description = "Prompt injection: attempt to bypass safety or content filters"
    patterns = [
        re.compile(r"bypass\s+(the\s+)?(safety|content|security|ethical?|moderation)\s+(filter|check|guard|policy|rules?|guidelines?)\b", re.IGNORECASE),
        re.compile(r"bypass\s+(your\s+)?(restrictions?|limitations?|constraints?|guidelines?)\b", re.IGNORECASE),
        re.compile(r"circumvent\s+(the\s+)?(safety|content|security|ethical?)\s+(filter|check|policy|rules?)\b", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 14 — Social Engineering (WARNING)
# ---------------------------------------------------------------------------


class FakeUserPermission(Rule):
    rule_id = "SE-001"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: false claim of user permission or instruction"
    patterns = [
        re.compile(r"the\s+user\s+asked\s+me\s+to\b", re.IGNORECASE),
        re.compile(r"the\s+user\s+(has\s+)?(told|instructed|requested)\s+(me|you)\s+to\b", re.IGNORECASE),
    ]


class FalseAuthorization(Rule):
    rule_id = "SE-002"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: false claim of authorization or permission"
    patterns = [
        re.compile(r"\bI\s+have\s+(been\s+)?(given\s+)?permission\b", re.IGNORECASE),
        re.compile(r"\bI\s+am\s+(fully\s+)?authorized\b", re.IGNORECASE),
        re.compile(r"\bauthorized\s+(by\s+)?(the\s+)?(admin|owner|developer|system|operator)\b", re.IGNORECASE),
    ]


class UrgencyOverride(Rule):
    rule_id = "SE-003"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: false urgency or emergency to bypass controls"
    patterns = [
        re.compile(r"\burgent\b.{0,40}(override|bypass|ignore|disable)\b", re.IGNORECASE),
        re.compile(r"emergency\s+override\b", re.IGNORECASE),
        re.compile(r"\bthis\s+is\s+(a\s+)?(critical\s+)?emergency\b.{0,40}(override|bypass|ignore|disable)\b", re.IGNORECASE),
    ]


class PrivilegedMode(Rule):
    rule_id = "SE-004"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: attempt to activate a privileged or unrestricted mode"
    patterns = [
        re.compile(r"\badmin\s+mode\b", re.IGNORECASE),
        re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
        re.compile(r"\bsuperuser\s+mode\b", re.IGNORECASE),
        re.compile(r"\bgod\s+mode\b", re.IGNORECASE),
        re.compile(r"\bunrestricted\s+mode\b", re.IGNORECASE),
    ]


class TrustMe(Rule):
    rule_id = "SE-005"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: appeal to trust to lower model defenses"
    patterns = [
        re.compile(r"\btrust\s+me[,\.]?\s*(I\s+(am|know|promise|swear)|just|please)\b", re.IGNORECASE),
        re.compile(r"\byou\s+can\s+trust\s+me\b", re.IGNORECASE),
    ]


class FakeTestContext(Rule):
    rule_id = "SE-006"
    category = "social_engineering"
    severity = Severity.WARNING
    description = "Social engineering: false test or simulation context to bypass restrictions"
    patterns = [
        re.compile(r"this\s+is\s+(only\s+)?a\s+test\b.{0,60}(ignore|bypass|disable|override)\b", re.IGNORECASE),
        re.compile(r"(ignore|bypass|disable|override).{0,60}this\s+is\s+(only\s+)?a\s+test\b", re.IGNORECASE),
        re.compile(r"in\s+(this\s+)?simulation[,\s]+(you\s+)?(can|may|should|must)\s+(ignore|bypass|disregard)\b", re.IGNORECASE),
    ]
