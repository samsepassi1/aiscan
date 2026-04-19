"""AI-SEC-003: Weak Cryptographic Algorithm Detection.

AI-generated code frequently reaches for MD5/SHA1/DES/RC4 because they appear
prominently in Stack Overflow answers and older documentation that LLMs have memorized.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


class WeakCryptoRule(BaseRule):
    rule_id = "AI-SEC-003"
    rule_name = "Weak Cryptographic Algorithm"
    severity = Severity.HIGH
    cwe_ids = ["CWE-327", "CWE-328"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    # (pattern, message, remediation)
    PATTERNS: list[tuple[re.Pattern, str, str]] = [
        (
            re.compile(r"\bhashlib\.md5\s*\("),
            "MD5 is cryptographically broken. Do not use for security-sensitive hashing.",
            "Replace hashlib.md5() with hashlib.sha256() or hashlib.sha3_256().",
        ),
        (
            re.compile(r"\bhashlib\.sha1\s*\("),
            "SHA-1 is deprecated for security use (SHAttered collision attack demonstrated).",
            "Replace hashlib.sha1() with hashlib.sha256() or hashlib.sha3_256().",
        ),
        (
            re.compile(r"\bCrypto\.Cipher\.DES\b"),
            "DES uses a 56-bit key, which is trivially brute-forced with modern hardware.",
            "Use AES-256-GCM via Crypto.Cipher.AES with a 32-byte key.",
        ),
        (
            re.compile(r"\bARC4\b|\bRC4\b"),
            "RC4 is a broken stream cipher with well-documented statistical biases.",
            "Use AES-256-GCM (authenticated encryption) instead.",
        ),
        (
            re.compile(r"\bBlowfish\b"),
            "Blowfish has a 64-bit block size, making it vulnerable to SWEET32 birthday attacks.",
            "Use AES-256-GCM instead.",
        ),
        (
            re.compile(r"\bAES\.MODE_ECB\b|mode\s*=\s*AES\.MODE_ECB"),
            "AES-ECB mode reveals patterns in plaintext (the 'ECB penguin' problem).",
            "Use AES.MODE_GCM or AES.MODE_CBC with a random IV and HMAC authentication.",
        ),
        (
            re.compile(r"\bMD5\s*\("),
            "MD5 function call detected. MD5 is cryptographically broken.",
            "Replace with SHA-256 or SHA-3.",
        ),
    ]

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(parsed.lines, start=1):
            for pattern, message, remediation in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=message,
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.9,
                        remediation=remediation,
                        code_snippet=line.rstrip(),
                    ))
        return findings
