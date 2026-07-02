import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Signature:
    name: str
    pattern: str
    severity: str
    description: str


class SignatureMatcher:
    """Matches packet payloads against threat signatures."""

    SIGNATURES = [
        Signature(
            "SQL Injection",
            r"(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|'\s*OR\s+'1'='1|OR\s+1=1--)",
            "CRITICAL",
            "SQL injection attempt detected in payload"
        ),
        Signature(
            "Cross-Site Scripting",
            r"(?i)(<script[^>]*>|javascript:\s*|onerror\s*=|onload\s*=)",
            "CRITICAL",
            "XSS attack pattern detected"
        ),
        Signature(
            "Unix Reverse Shell",
            r"(?i)(/bin/bash\s+-i|/bin/sh\s+-i|nc\s+-e\s+/bin|bash\s+-i\s*>&)",
            "HIGH",
            "Unix reverse shell command detected"
        ),
        Signature(
            "Windows Command Injection",
            r"(?i)(cmd\.exe|powershell\s+-[eE]n[cC]|powershell\s+-[eE][xX])",
            "HIGH",
            "Windows command injection attempt"
        ),
        Signature(
            "Suspicious User Agent",
            r"(?i)(curl|wget|python-requests|nikto|sqlmap|nmap)",
            "LOW",
            "Potentially suspicious user agent"
        ),
        Signature(
            "Path Traversal",
            r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
            "HIGH",
            "Directory traversal attempt"
        ),
        Signature(
            "Command Injection",
            r"(?i)(;\s*(cat|ls|id|whoami|uname)|&&\s*(cat|ls|id|whoami))",
            "HIGH",
            "Command injection pattern detected"
        ),
        Signature(
            "Data Exfiltration Pattern",
            r"(?i)(password|passwd|shadow|\.pem|\.key|secret|token).*(\b[A-Za-z0-9+/]{40,}=*)",
            "MEDIUM",
            "Possible data exfiltration"
        ),
    ]

    def __init__(self):
        self.signatures = self.SIGNATURES
        self.compiled = [(sig, re.compile(sig.pattern)) for sig in self.signatures]

    def match(self, payload: str) -> List[Tuple[str, str, str]]:
        if not payload:
            return []

        matches = []
        for sig, pattern in self.compiled:
            if pattern.search(payload):
                matches.append((sig.name, sig.severity, sig.description))

        return matches

    def add_signature(self, name: str, pattern: str, severity: str, description: str):
        sig = Signature(name, pattern, severity, description)
        self.signatures.append(sig)
        self.compiled.append((sig, re.compile(pattern)))