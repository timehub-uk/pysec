import re
from pathlib import Path


VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "pattern": r"(execute|query|cursor\.execute)\s*\([^)]*%s[^)]*\)|['\"]SELECT.*\{|\.format\(.*\$|\$\{.*\}",
        "severity": "high",
        "description": "Potential SQL injection vulnerability",
        "fix": "Use parameterized queries or ORM"
    },
    "path_traversal": {
        "pattern": r"(open|read|os\.path\.join|Path)\s*\([^)]*(?:request\.|user_|filename)",
        "severity": "medium",
        "description": "Potential path traversal vulnerability",
        "fix": "Validate and sanitize file paths"
    },
    "xss": {
        "pattern": r"(?<!description\s*=\s)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)",
        "severity": "medium",
        "description": "Potential XSS vulnerability",
        "fix": "Use textContent or sanitization libraries"
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(|\bexec\s*\(",
        "severity": "high",
        "description": "Use of eval/exec is a security risk",
        "fix": "Avoid eval/exec, use safer alternatives"
    },
    "hardcoded_db": {
        "pattern": r"(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@(?!(?:password|secret|token|key|example|test|xxx))",
        "severity": "high",
        "description": "Hardcoded database credentials",
        "fix": "Use environment variables"
    },
    "insecure_random": {
        "pattern": r"(random\.random|random\.randint|random\.choice)",
        "severity": "low",
        "description": "Insecure random for security purposes",
        "fix": "Use secrets module"
    },
    "yaml_load": {
        "pattern": r"yaml\.load\s*\((?!.*SafeLoader)",
        "severity": "medium",
        "description": "Insecure YAML deserialization",
        "fix": "Use yaml.safe_load with SafeLoader"
    },
    "weak_crypto": {
        "pattern": r"(hashlib\.md5|hashlib\.sha1|binascii\.unhexlify)",
        "severity": "medium",
        "description": "Use of weak cryptographic algorithm",
        "fix": "Use SHA-256 or stronger"
    },
    "hardcoded_secret": {
        "pattern": r"(api_key|apikey|secret|token)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "high",
        "description": "Hardcoded secret detected",
        "fix": "Use environment variables"
    },
    "command_injection": {
        "pattern": r"(subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\([^)]*(?:shell\s*=\s*True|shell=True)",
        "severity": "critical",
        "description": "Potential command injection",
        "fix": "Avoid shell=True, use list of args"
    },
    "pickle_insecure": {
        "pattern": r"(pickle\.load|pickle\.loads)\s*\((?!.*SafeSerializer)",
        "severity": "high",
        "description": "Insecure pickle deserialization",
        "fix": "Use restricted unpickler"
    },
    "assert_statements": {
        "pattern": r"\bassert\s+",
        "severity": "low",
        "description": "Assert statements may be disabled in production",
        "fix": "Remove or use proper validation"
    },
    "debug_enabled": {
        "pattern": r"(DEBUG\s*=\s*True|debug\s*=\s*True)",
        "severity": "medium",
        "description": "Debug mode may be enabled",
        "fix": "Disable in production"
    },
    "ssl_verify_disabled": {
        "pattern": r"(verify\s*=\s*False|ssl_verify\s*=\s*False)",
        "severity": "high",
        "description": "SSL verification disabled",
        "fix": "Enable SSL verification"
    },
    "http_without_https": {
        "pattern": r"http://(?!localhost|127\.0\.0\.1)",
        "severity": "medium",
        "description": "Insecure HTTP URL",
        "fix": "Use HTTPS"
    },
    "logger_sensitive_data": {
        "pattern": r"(logger|log)\.(info|debug|warning)\s*\([^)]*(?:password|secret|token|key)[^)]*\)",
        "severity": "high",
        "description": "Sensitive data logged",
        "fix": "Redact sensitive data in logs"
    }
}


def scan_code_vulnerabilities(path):
    results = []
    seen = set()
    
    for filepath in path.rglob("*.py"):
        if "__pycache__" in str(filepath) or "venv" in str(filepath):
            continue
        
        try:
            content = filepath.read_text(errors="ignore")
            lines = content.split("\n")
            
            for vuln_type, info in VULNERABILITY_PATTERNS.items():
                for match in re.finditer(info["pattern"], content, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    key = f"{vuln_type}:{filepath}:{line_num}"
                    
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "type": vuln_type,
                            "severity": info["severity"],
                            "description": info["description"],
                            "fix": info.get("fix", ""),
                            "location": f"{filepath}:{line_num}"
                        })
        except Exception:
            pass
    
    return results