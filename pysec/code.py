import re
from pathlib import Path


VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "pattern": r"(execute|query|cursor\.execute)\s*\([^)]*%s[^)]*\)|['\"]SELECT.*\{",
        "severity": "high",
        "description": "Potential SQL injection vulnerability"
    },
    "path_traversal": {
        "pattern": r"(open|read|os\.path\.join)\s*\([^)]*request\.|Path\(.*request",
        "severity": "medium",
        "description": "Potential path traversal vulnerability"
    },
    "xss": {
        "pattern": r"(innerHTML|outerHTML|document\.write)\s*\([^)]*request",
        "severity": "medium",
        "description": "Potential XSS vulnerability"
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(|exec\s*\(",
        "severity": "high",
        "description": "Use of eval/exec is a security risk"
    },
    "hardcoded_db": {
        "pattern": r"(mysql|postgresql|mongodb)://[^:]+:[^@]+@",
        "severity": "high",
        "description": "Hardcoded database credentials"
    },
    "insecure_random": {
        "pattern": r"random\.(random|randint)",
        "severity": "low",
        "description": "Insecure use of random module for security"
    },
    "yaml_load": {
        "pattern": r"yaml\.load\s*\([^)]*(?!.*SafeLoader)",
        "severity": "medium",
        "description": "Insecure YAML deserialization"
    },
    "weak_crypto": {
        "pattern": r"(hashlib\.(md5|sha1)\s*\()|import hashlib.*\n.*md5\(|import hashlib.*\n.*sha1\(",
        "severity": "medium",
        "description": "Use of weak cryptographic algorithm"
    }
}


def scan_code_vulnerabilities(path):
    results = []
    
    for filepath in path.rglob("*.py"):
        if "__pycache__" in str(filepath):
            continue
        
        try:
            content = filepath.read_text(errors="ignore")
            
            for vuln_type, info in VULNERABILITY_PATTERNS.items():
                if re.search(info["pattern"], content, re.IGNORECASE):
                    results.append({
                        "type": vuln_type,
                        "severity": info["severity"],
                        "description": info["description"],
                        "location": str(filepath)
                    })
        except Exception:
            pass
    
    return results