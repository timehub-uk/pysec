"""
Privacy and PII Analysis - Detect handling of personally identifiable information
"""

import re
from pathlib import Path


PII_PATTERNS = {
    "email": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": "medium",
        "description": "Email address detected"
    },
    "phone": {
        "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b|\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "severity": "medium",
        "description": "Phone number detected"
    },
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "critical",
        "description": "Social Security Number detected"
    },
    "credit_card": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "severity": "critical",
        "description": "Credit card number detected"
    },
    "ip_address": {
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "severity": "low",
        "description": "IP address detected"
    },
    "passport": {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "severity": "critical",
        "description": "Passport number detected"
    },
    "drivers_license": {
        "pattern": r"\b[A-Z]{1,2}\d{5,8}\b",
        "severity": "high",
        "description": "Driver's license number detected"
    },
    "national_id": {
        "pattern": r"\b\d{9,12}\b",
        "severity": "high",
        "description": "National ID number detected"
    },
    "date_of_birth": {
        "pattern": r"(?:dob|birth.?date|date.?of.?birth)[\s:=]+(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}",
        "severity": "medium",
        "description": "Date of birth detected"
    },
    "bank_account": {
        "pattern": r"\b\d{8,17}\b",
        "severity": "high",
        "description": "Bank account number detected"
    }
}


GDPR_KEYWORDS = [
    "gdpr", "data subject", "data controller", "data processor",
    "right to erasure", "right to access", "data portability",
    "consent", "personal data", "special category", "dpo"
]


PCI_KEYWORDS = [
    "pci", "payment card", "cardholder", "card number",
    "cvv", "card verification", "merchant", "pos"
]


HIPAA_KEYWORDS = [
    "hipaa", "phi", "protected health", "medical record",
    "patient", "diagnosis", "treatment", "health plan"
]


def scan_pii(path: Path = Path(".")) -> list[dict]:
    """Scan for PII in code"""
    results = []
    
    extensions = {".py", ".js", ".ts", ".txt", ".json", ".csv", ".log"}
    
    for ext in extensions:
        for filepath in path.rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in ["node_modules", ".git", "venv", "__pycache__"]):
                continue
            
            try:
                content = filepath.read_text(errors="ignore")
                
                for pii_type, info in PII_PATTERNS.items():
                    matches = re.findall(info["pattern"], content, re.IGNORECASE)
                    if matches:
                        count = len(matches)
                        results.append({
                            "type": f"pii-{pii_type}",
                            "severity": info["severity"],
                            "description": f"{info['description']} ({count} occurrences)",
                            "location": str(filepath)
                        })
            except:
                pass
    
    return results


def check_privacy_compliance(path: Path = Path(".")) -> list[dict]:
    """Check for privacy/compliance keywords"""
    results = []
    
    for filepath in path.rglob("*.py"):
        if "__pycache__" in str(filepath):
            continue
        
        try:
            content = filepath.read_text(errors="ignore")
            content_lower = content.lower()
            
            gdpr_count = sum(1 for kw in GDPR_KEYWORDS if kw in content_lower)
            pci_count = sum(1 for kw in PCI_KEYWORDS if kw in content_lower)
            hipaa_count = sum(1 for kw in HIPAA_KEYWORDS if kw in content_lower)
            
            if gdpr_count > 0:
                results.append({
                    "type": "privacy-gdpr",
                    "severity": "info",
                    "description": f"GDPR-related keywords found ({gdpr_count} occurrences)",
                    "location": str(filepath)
                })
            
            if pci_count > 0:
                results.append({
                    "type": "privacy-pci",
                    "severity": "high",
                    "description": f"PCI-DSS related keywords found ({pci_count} occurrences)",
                    "location": str(filepath)
                })
            
            if hipaa_count > 0:
                results.append({
                    "type": "privacy-hipaa",
                    "severity": "high",
                    "description": f"HIPAA related keywords found ({hipaa_count} occurrences)",
                    "location": str(filepath)
                })
        except:
            pass
    
    return results


def scan_privacy(path: Path = Path(".")) -> list[dict]:
    """Full privacy scan"""
    results = []
    
    results.extend(scan_pii(path))
    results.extend(check_privacy_compliance(path))
    
    return results