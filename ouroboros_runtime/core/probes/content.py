"""Content analysis probe for hidden text and malicious elements."""
from __future__ import annotations

import re
from typing import ClassVar

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput


class ContentProbe(BaseProbe):
    """Detects hidden or malicious content in responses.

    Scans for zero-width characters, hidden HTML elements, HTML comments
    with instructions, and Unicode homoglyphs.
    """

    probe_id = "content"

    # Zero-width and invisible Unicode characters
    _ZERO_WIDTH_CHARS: ClassVar[dict[str, str]] = {
        "\u200b": "ZERO WIDTH SPACE",
        "\u200c": "ZERO WIDTH NON-JOINER",
        "\u200d": "ZERO WIDTH JOINER",
        "\u200e": "LEFT-TO-RIGHT MARK",
        "\u200f": "RIGHT-TO-LEFT MARK",
        "\u2060": "WORD JOINER",
        "\u2061": "FUNCTION APPLICATION",
        "\u2062": "INVISIBLE TIMES",
        "\u2063": "INVISIBLE SEPARATOR",
        "\u2064": "INVISIBLE PLUS",
        "\ufeff": "BYTE ORDER MARK",
        "\u00ad": "SOFT HYPHEN",
        "\u034f": "COMBINING GRAPHEME JOINER",
        "\u061c": "ARABIC LETTER MARK",
        "\u115f": "HANGUL CHOSEONG FILLER",
        "\u1160": "HANGUL JUNGSEONG FILLER",
        "\u17b4": "KHMER VOWEL INHERENT AQ",
        "\u17b5": "KHMER VOWEL INHERENT AA",
        "\u180e": "MONGOLIAN VOWEL SEPARATOR",
        "\u3164": "HANGUL FILLER",
        "\uffa0": "HALFWIDTH HANGUL FILLER",
    }

    # Hidden HTML element patterns
    _HIDDEN_ELEMENT_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r'style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*opacity\s*:\s*0[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*font-size\s*:\s*0[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*height\s*:\s*0[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*width\s*:\s*0[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*color\s*:\s*transparent[^"\']*["\']', re.IGNORECASE),
        re.compile(r'style\s*=\s*["\'][^"\']*position\s*:\s*absolute[^"\']*left\s*:\s*-\d+', re.IGNORECASE),
        re.compile(r'hidden\s*=\s*["\']?true["\']?', re.IGNORECASE),
        re.compile(r'aria-hidden\s*=\s*["\']true["\']', re.IGNORECASE),
    ]

    # HTML comment pattern
    _HTML_COMMENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"<!--(.*?)-->",
        re.DOTALL,
    )

    # Common homoglyph mappings (confusable characters)
    _HOMOGLYPHS: ClassVar[dict[str, str]] = {
        "\u0430": "a (Cyrillic)",  # а -> a
        "\u0435": "e (Cyrillic)",  # е -> e
        "\u043e": "o (Cyrillic)",  # о -> o
        "\u0440": "p (Cyrillic)",  # р -> p
        "\u0441": "c (Cyrillic)",  # с -> c
        "\u0445": "x (Cyrillic)",  # х -> x
        "\u0443": "y (Cyrillic)",  # у -> y
        "\u0456": "i (Cyrillic)",  # і -> i
        "\u0391": "A (Greek)",     # Α -> A
        "\u0392": "B (Greek)",     # Β -> B
        "\u0395": "E (Greek)",     # Ε -> E
        "\u0397": "H (Greek)",     # Η -> H
        "\u0399": "I (Greek)",     # Ι -> I
        "\u039a": "K (Greek)",     # Κ -> K
        "\u039c": "M (Greek)",     # Μ -> M
        "\u039d": "N (Greek)",     # Ν -> N
        "\u039f": "O (Greek)",     # Ο -> O
        "\u03a1": "P (Greek)",     # Ρ -> P
        "\u03a4": "T (Greek)",     # Τ -> T
        "\u03a7": "X (Greek)",     # Χ -> X
        "\u03a5": "Y (Greek)",     # Υ -> Y
        "\u0417": "Z (Greek)",     # Ζ -> Z
        "\u2010": "- (hyphen)",    # ‐ -> -
        "\u2011": "- (non-breaking hyphen)",
        "\u2012": "- (figure dash)",
        "\u2013": "- (en dash)",
        "\u2014": "- (em dash)",
        "\u2212": "- (minus sign)",
        "\uff0d": "- (fullwidth hyphen)",
    }

    # Suspicious instruction keywords in comments
    _INSTRUCTION_KEYWORDS: ClassVar[list[str]] = [
        "ignore", "instruction", "system", "prompt", "override",
        "admin", "secret", "hidden", "important", "must",
    ]

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []
        content = input.response_body or ""

        if not content:
            return findings

        target = input.tool_name or input.url or "unknown"

        # Check for zero-width characters
        zwc_findings = self._check_zero_width_chars(content, target)
        findings.extend(zwc_findings)

        # Check for hidden HTML elements
        hidden_findings = self._check_hidden_elements(content, target)
        findings.extend(hidden_findings)

        # Check HTML comments for suspicious content
        comment_findings = self._check_html_comments(content, target)
        findings.extend(comment_findings)

        # Check for homoglyphs in otherwise ASCII text
        homoglyph_findings = self._check_homoglyphs(content, target)
        findings.extend(homoglyph_findings)

        return findings

    def _check_zero_width_chars(self, content: str, target: str) -> list[RuntimeFinding]:
        """Detect zero-width and invisible characters."""
        findings: list[RuntimeFinding] = []
        found_chars: dict[str, int] = {}

        for char, name in self._ZERO_WIDTH_CHARS.items():
            count = content.count(char)
            if count > 0:
                found_chars[name] = count

        if found_chars:
            total = sum(found_chars.values())
            severity = Severity.HIGH if total > 10 else Severity.MEDIUM

            findings.append(RuntimeFinding(
                rule_id=RuleID.MALICIOUS_CONTENT,
                severity=severity,
                title="Zero-width characters detected",
                description=(
                    f"Content contains {total} invisible/zero-width character(s) "
                    f"that may be used to hide instructions or obfuscate text"
                ),
                target=target,
                evidence=", ".join(f"{name}: {count}" for name, count in found_chars.items()),
                metadata={"characters": found_chars, "total_count": total},
            ))

        return findings

    def _check_hidden_elements(self, content: str, target: str) -> list[RuntimeFinding]:
        """Detect hidden HTML elements."""
        findings: list[RuntimeFinding] = []

        for pattern in self._HIDDEN_ELEMENT_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.MALICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    title="Hidden HTML element detected",
                    description=(
                        f"Content contains HTML element(s) with hiding styles "
                        f"that may conceal malicious instructions"
                    ),
                    target=target,
                    evidence=f"Pattern: {pattern.pattern}, Matches: {len(matches)}",
                    metadata={"pattern": pattern.pattern, "match_count": len(matches)},
                ))

        return findings

    def _check_html_comments(self, content: str, target: str) -> list[RuntimeFinding]:
        """Check HTML comments for suspicious instructions."""
        findings: list[RuntimeFinding] = []

        for match in self._HTML_COMMENT_PATTERN.finditer(content):
            comment_text = match.group(1).lower()

            suspicious_keywords = [
                kw for kw in self._INSTRUCTION_KEYWORDS
                if kw in comment_text
            ]

            if suspicious_keywords:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.MALICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    title="Suspicious HTML comment",
                    description=(
                        f"HTML comment contains instruction-like keywords: "
                        f"{', '.join(suspicious_keywords)}"
                    ),
                    target=target,
                    evidence=self._truncate(match.group(0), 200),
                    metadata={"keywords": suspicious_keywords},
                ))

        return findings

    def _check_homoglyphs(self, content: str, target: str) -> list[RuntimeFinding]:
        """Detect Unicode homoglyphs in content."""
        findings: list[RuntimeFinding] = []
        found_homoglyphs: dict[str, int] = {}

        for char, description in self._HOMOGLYPHS.items():
            count = content.count(char)
            if count > 0:
                found_homoglyphs[description] = count

        if found_homoglyphs:
            total = sum(found_homoglyphs.values())
            if total >= 3:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.MALICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    title="Unicode homoglyphs detected",
                    description=(
                        f"Content contains {total} Unicode character(s) that look "
                        f"like ASCII but are from different scripts (Cyrillic, Greek, etc.). "
                        f"This may be used for spoofing or obfuscation."
                    ),
                    target=target,
                    evidence=", ".join(f"{desc}: {count}" for desc, count in found_homoglyphs.items()),
                    metadata={"homoglyphs": found_homoglyphs, "total_count": total},
                ))

        return findings

    def _truncate(self, text: str, max_len: int) -> str:
        """Truncate text to max length."""
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."
