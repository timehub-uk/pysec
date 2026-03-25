import re
from pathlib import Path


SECRET_PATTERNS = {
    "api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "severity": "critical",
        "description": "Potential API key detected"
    },
    "aws_key": {
        "pattern": r"(?i)aws[_-]?(access[_-]?key|secret)[_-]?(id|key)?\s*[=:]\s*['\"][A-Z0-9]{20,}['\"]",
        "severity": "critical",
        "description": "Potential AWS credentials detected"
    },
    "github_token": {
        "pattern": r"(?i)(github[_-]?token|gho_)[a-zA-Z0-9]{36,}",
        "severity": "critical",
        "description": "Potential GitHub token detected"
    },
    "password": {
        "pattern": r"(?i)password\s*[=:]\s*['\"][^'\"]+['\"]",
        "severity": "critical",
        "description": "Hardcoded password detected"
    },
    "private_key": {
        "pattern": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
        "severity": "critical",
        "description": "Private key detected"
    },
    "jwt": {
        "pattern": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "severity": "high",
        "description": "Potential JWT token detected"
    }
}


def scan_secrets(path):
    results = []
    
    extensions = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".sh", ".txt"}
    
    for ext in extensions:
        for filepath in path.rglob(f"*{ext}"):
            if any(skip in str(filepath) for skip in ["node_modules", ".git", "__pycache__", "venv"]):
                continue
            
            try:
                content = filepath.read_text(errors="ignore")
                
                for secret_type, info in SECRET_PATTERNS.items():
                    if re.search(info["pattern"], content):
                        results.append({
                            "type": "secret_leak",
                            "severity": info["severity"],
                            "description": info["description"],
                            "location": str(filepath)
                        })
            except Exception:
                pass
    
    return results