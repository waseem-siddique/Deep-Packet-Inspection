# signature_matcher.py
import re

SIGNATURES = [
    {"name": "Suspicious User-Agent", "pattern": r"(?i)(curl|wget|python-requests)", "severity": "LOW"},
    {"name": "Unix reverse shell", "pattern": r"(?i)(/bin/bash|/bin/sh|nc -e)", "severity": "HIGH"},
    {"name": "Windows cmd.exe", "pattern": r"(?i)cmd\.exe", "severity": "HIGH"},
    {"name": "SQL Injection attempt", "pattern": r"(?i)(UNION\s+SELECT|OR\s+1=1|' OR '1'='1)", "severity": "CRITICAL"},
    {"name": "XSS attempt", "pattern": r"(?i)(<script>|javascript:)", "severity": "CRITICAL"},
    {"name": "Suspicious PowerShell", "pattern": r"(?i)(powershell\s+-[eE]", "severity": "HIGH"},
]

class SignatureMatcher:
    def __init__(self):
        self.signatures = SIGNATURES

    def match(self, payload):
        """Check payload against all signatures. Returns list of matched signature names."""
        if not payload:
            return []
        matched = []
        for sig in self.signatures:
            if re.search(sig["pattern"], payload):
                matched.append((sig["name"], sig["severity"]))
        return matched